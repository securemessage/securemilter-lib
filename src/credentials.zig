//! Process identity and file-creation mask.
//! Determines who can open the milter socket (group ownership + umask).

const std = @import("std");
const c = std.c;

extern "c" fn setgroups(ngroups: c_int, gidset: ?[*]const c.gid_t) c_int;

// Declared here for the same reason as `setgroups`: both `std.c` and `std.posix`
// expose the uid pair and neither exposes the gid pair.
extern "c" fn getgid() c.gid_t;
extern "c" fn getegid() c.gid_t;

/// FreeBSD's `struct group`, for `getgrnam`.
///
/// Spelled out because `std.c` has `passwd` but not this. Only `gr_gid` is read;
/// the other three fields exist so the layout matches and the offset is right.
const group = extern struct {
    gr_name: ?[*:0]u8,
    gr_passwd: ?[*:0]u8,
    gr_gid: c.gid_t,
    gr_mem: ?[*]?[*:0]u8,
};
extern "c" fn getgrnam(name: [*:0]const u8) ?*group;

/// A `user[:group]` spec resolved to the numeric identity it names.
pub const UserGroup = struct {
    uid: c.uid_t,
    gid: c.gid_t,
};

/// Resolve `user` or `user:group` (opendkim `UserID` format) to numeric ids,
/// changing nothing. `:group` overrides the user's primary group.
///
/// This is the single interpretation of the spec: `dropPrivileges` becomes the
/// identity it returns, and `daemon.ensureRuntimeDirectory` hands the runtime
/// directories to it. Those two must never disagree — a looser second parser
/// lived in `daemon.zig` briefly, and which group it picked is what decides
/// the milter socket's group (BSD inheritance from the directory), i.e.
/// whether Postfix can connect at all.
///
/// Both names are resolved before anything is returned, so an unknown group
/// is a clean refusal rather than a half-applied identity.
pub fn resolveUserGroup(spec: []const u8) !UserGroup {
    const sep = std.mem.indexOfScalar(u8, spec, ':');
    const username = if (sep) |i| spec[0..i] else spec;
    const groupname: ?[]const u8 = if (sep) |i| spec[i + 1 ..] else null;

    var user_buf: [256:0]u8 = undefined;
    if (username.len == 0) return error.InvalidUserSpec;
    if (username.len >= user_buf.len) return error.UsernameTooLong;
    @memcpy(user_buf[0..username.len], username);
    user_buf[username.len] = 0;

    const pw = c.getpwnam(&user_buf) orelse return error.UserNotFound;

    var gid = pw.gid;
    if (groupname) |g| {
        // A separate buffer on purpose: reusing `user_buf` would leave it
        // holding the group name, and the two lookups read too similarly for
        // that to stay noticed.
        var group_buf: [256:0]u8 = undefined;
        if (g.len == 0) return error.InvalidUserSpec;
        if (g.len >= group_buf.len) return error.GroupNameTooLong;
        @memcpy(group_buf[0..g.len], g);
        group_buf[g.len] = 0;

        const gr = getgrnam(&group_buf) orelse return error.GroupNotFound;
        gid = gr.gr_gid;
    }

    return .{ .uid = pw.uid, .gid = gid };
}

/// Set file-creation mask. Wrapped so `bootstrap` can substitute it for
/// ordering tests (mask must be set before socket bind).
pub fn setUmask(mask: c.mode_t) void {
    _ = c.umask(mask);
}

/// Drop privileges to `user` or `user:group` (opendkim `UserID` format).
///
/// Calls setgroups(0) + setgid + setuid. Order matters: setgroups needs root.
///
/// `:group` overrides the user's primary group, controlling who can open the
/// milter's unix socket (socket owned by effective group; `UMask` closes it
/// to others).
///
/// UID 0 is refused: all syscalls succeed silently against root, so `User=root`
/// would report a successful drop while retaining all privileges. `toor` (FreeBSD
/// second uid-0 account) triggers the same guard. To run as root, leave the option
/// unset (`bootstrap.Options.user` is optional).
///
/// Drop is verified after (real + effective uid/gid checked): a partial drop
/// where effective moved but real did not would leave the process able to restore.
pub fn dropPrivileges(spec: []const u8) !void {
    // With `:group`, the daemon runs in a group it is not necessarily a member
    // of — a 0660 socket owned by that group restricts access to Postfix (and
    // nothing else) without depending on no other local accounts. Resolution is
    // complete before the first syscall, so an unknown name is a clean refusal
    // rather than a half-completed drop.
    const target = try resolveUserGroup(spec);

    if (target.uid == 0) return error.RefusingToDropToRoot;

    // Clear supplementary groups — prevents inheriting root's group memberships
    if (setgroups(0, null) != 0) return error.SetgroupsFailed;
    if (c.setgid(target.gid) != 0) return error.SetgidFailed;
    if (c.setuid(target.uid) != 0) return error.SetuidFailed;

    // Real *and* effective, because a mismatch is the shape a partial drop takes:
    // an effective id that moved while the real one did not leaves the process
    // able to return to what it was.
    if (c.getuid() != target.uid or c.geteuid() != target.uid) return error.PrivilegeDropNotEffective;
    if (getgid() != target.gid or getegid() != target.gid) return error.PrivilegeDropNotEffective;
}

// Every case below is rejected before the first syscall, which is what makes
// them safe to run here: a test that actually completed a drop would leave the
// rest of the suite running as somebody else. It is also why the uid-0 case is
// testable at all -- unprivileged, the three syscalls would fail anyway and
// prove nothing, whereas the guard returns the same answer either way.

test "dropping to root is refused rather than quietly doing nothing" {
    // The fault this prevents is silent by construction: as root, every syscall
    // in the drop succeeds against a uid-0 target and the daemon logs an
    // ordinary successful start while holding every privilege it had.
    try std.testing.expectError(error.RefusingToDropToRoot, dropPrivileges("root"));
}

test "an unknown user is refused" {
    try std.testing.expectError(error.UserNotFound, dropPrivileges("no-such-user-4f1c8e2a"));
}

test "an over-long username is refused before getpwnam sees it" {
    const long = "u" ** 300;
    try std.testing.expectError(error.UsernameTooLong, dropPrivileges(long));
}

test "the uid-0 guard is not bypassed by naming a group" {
    // The guard fires on the resolved uid whether or not a group is named, so
    // `root:wheel` cannot walk past the refusal by making the spec look like a
    // deliberate choice.
    try std.testing.expectError(error.RefusingToDropToRoot, dropPrivileges("root:wheel"));
}

test "an unknown group is refused before any syscall runs" {
    // Resolution happens up front for exactly this reason: reaching `setgid` with an
    // unresolvable group would mean `setgroups` had already run, leaving the process
    // stripped of its supplementary groups and still root.
    try std.testing.expectError(error.GroupNotFound, dropPrivileges("nobody:no-such-group-4f1c8e2a"));
}

test "a spec with an empty side is refused" {
    try std.testing.expectError(error.InvalidUserSpec, dropPrivileges(":wheel"));
    try std.testing.expectError(error.InvalidUserSpec, dropPrivileges("nobody:"));
    try std.testing.expectError(error.InvalidUserSpec, dropPrivileges(""));
}

test "an over-long group name is refused before getgrnam sees it" {
    const long = "nobody:" ++ "g" ** 300;
    try std.testing.expectError(error.GroupNameTooLong, dropPrivileges(long));
}

test "a spec resolves to numeric ids, with `:group` overriding the primary group" {
    // The success path is assertable here in a way it never was through
    // `dropPrivileges`: resolution changes no process state, and root is the
    // one account whose ids are fixed. wheel (0) is root's primary group;
    // daemon (1) is a FreeBSD base group no port can move.
    const plain = try resolveUserGroup("root");
    try std.testing.expectEqual(@as(c.uid_t, 0), plain.uid);
    try std.testing.expectEqual(@as(c.gid_t, 0), plain.gid);

    const overridden = try resolveUserGroup("root:daemon");
    try std.testing.expectEqual(@as(c.uid_t, 0), overridden.uid);
    try std.testing.expectEqual(@as(c.gid_t, 1), overridden.gid);
}
