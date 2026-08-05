//! Who the process runs as, and what mask it creates files with.
//!
//! Split from `daemon.zig` when the socket-permission work landed. That module
//! is the individual privileged operations a daemon performs on ITSELF as a
//! process -- fork, claim a PID file, raise a limit, arrange for signals -- and
//! this one is the subset that answers a different question: what identity does
//! the process have, and what does that identity make reachable. The two were
//! one file until `user:group` and `UMask` arrived, at which point the identity
//! half stopped being three syscalls and became the thing the whole local trust
//! boundary rests on.
//!
//! They are also read at different times. Somebody debugging a daemon that will
//! not start reads the other file; somebody asking who can open the signing
//! socket reads this one, and every answer to that question is here.

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

/// Set the process file-creation mask.
///
/// Wrapped rather than called directly so `bootstrap` can substitute it and
/// assert WHERE in the sequence it happens -- which is the whole point of the
/// option, since a mask applied after the socket is bound accomplishes nothing.
pub fn setUmask(mask: c.mode_t) void {
    _ = c.umask(mask);
}

/// Drop privileges to `user` or `user:group`.
///
/// Looks up the user by name via getpwnam, then calls setgroups (clear
/// supplementary groups) + setgid + setuid. Order matters: setgroups
/// requires root, so it must come before setuid.
/// Must be called as root before entering the event loop.
///
/// The optional `:group` overrides the user's primary group, matching opendkim's
/// `UserID user[:group]`. It is not cosmetic: a unix socket is created owned by
/// the process's effective group, so the group named here is precisely the set of
/// accounts that can talk to the milter once `UMask` closes it to others.
///
/// A UID OF 0 IS REFUSED RATHER THAN OBEYED. Every syscall below succeeds when
/// the target is root, so `User = root` produced a daemon that reported a
/// successful privilege drop and kept every privilege it had -- the one outcome
/// an operator reading that log line would rule out. This is not a hypothetical
/// typo either: FreeBSD ships `toor` as a second uid-0 account, so a plausible
/// name resolves to a silent no-op. There is already a way to say "do not drop",
/// which is to leave the option unset (`bootstrap.Options.user` is optional), so
/// nothing is lost by making the confusing spelling an error.
///
/// The drop is then VERIFIED rather than inferred from three return codes. The
/// check is nearly free and covers the cases where a call reports success
/// without having done what was asked -- and, more usefully, it is what would
/// catch a future edit that reorders or drops one of the three calls. Note it
/// cannot substitute for the uid-0 guard above: with a target of 0 the identity
/// after the "drop" is 0, which is exactly what was asked for, so verification
/// passes. The two checks catch different faults.
pub fn dropPrivileges(spec: []const u8) !void {
    // `user[:group]`, the form opendkim's UserID takes. Without the group part the
    // user's primary group is used, as before. WITH it, the daemon runs in a group
    // it is not necessarily a member of -- which is the point: a socket at 0660
    // owned by that group is reachable by Postfix and by nothing else, and that is
    // the only arrangement that closes the local half of the milter trust boundary
    // without depending on there being no other local accounts.
    const sep = std.mem.indexOfScalar(u8, spec, ':');
    const username = if (sep) |i| spec[0..i] else spec;
    const groupname: ?[]const u8 = if (sep) |i| spec[i + 1 ..] else null;

    var name_buf: [256:0]u8 = undefined;
    if (username.len == 0) return error.InvalidUserSpec;
    if (username.len >= name_buf.len) return error.UsernameTooLong;
    @memcpy(name_buf[0..username.len], username);
    name_buf[username.len] = 0;

    const pw = c.getpwnam(&name_buf);
    if (pw == null) return error.UserNotFound;

    const passwd = pw.?;

    if (passwd.uid == 0) return error.RefusingToDropToRoot;

    // Resolved before the first syscall, so an unknown group is a clean refusal
    // rather than a half-completed drop.
    var target_gid = passwd.gid;
    if (groupname) |g| {
        var grp_buf: [256:0]u8 = undefined;
        if (g.len == 0) return error.InvalidUserSpec;
        if (g.len >= grp_buf.len) return error.GroupNameTooLong;
        @memcpy(grp_buf[0..g.len], g);
        grp_buf[g.len] = 0;

        const gr = getgrnam(&grp_buf);
        if (gr == null) return error.GroupNotFound;
        target_gid = gr.?.gr_gid;
    }

    // Clear supplementary groups — prevents inheriting root's group memberships
    if (setgroups(0, null) != 0) return error.SetgroupsFailed;
    if (c.setgid(target_gid) != 0) return error.SetgidFailed;
    if (c.setuid(passwd.uid) != 0) return error.SetuidFailed;

    // Real *and* effective, because a mismatch is the shape a partial drop takes:
    // an effective id that moved while the real one did not leaves the process
    // able to return to what it was.
    if (c.getuid() != passwd.uid or c.geteuid() != passwd.uid) return error.PrivilegeDropNotEffective;
    if (getgid() != target_gid or getegid() != target_gid) return error.PrivilegeDropNotEffective;
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
    // The group is resolved after the uid check, so `root:mail` cannot be used to
    // walk past the refusal by making the spec look like a deliberate choice.
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
