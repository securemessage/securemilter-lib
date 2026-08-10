const std = @import("std");
const mem = std.mem;
const auth_results = @import("auth_results.zig");
const connection_mod = @import("connection.zig");
const codec = @import("milter/codec.zig");
const responses = @import("milter/responses.zig");
const log = @import("log.zig");

/// Remove forged or stale `Authentication-Results` headers for an ADMD.
///
/// The policy can remove this daemon's methods, foreign methods, or every
/// result claiming the local authserv-id.
pub const StripPolicy = struct {
    own_methods: []const []const u8 = &.{},
    local_methods: []const []const u8 = &.{},
    strip_all: bool = false,
    strip_foreign: bool = false,
};

pub const HEADER_NAME = "Authentication-Results";

/// Delete forged/stale A-R headers claiming `authserv_id`.
///
/// Must be called at end-of-message before the daemon evaluates headers and
/// before it adds its own result. Returns the number of headers removed.
///
/// Deletions are issued newest-index-first: `SMFIR_CHGHEADER` addresses the
/// n-th instance of a header name, so removing a lower index would renumber
/// the ones above it.
pub fn stripAuthResults(
    conn: *connection_mod.Connection,
    authserv_id: []const u8,
    policy: StripPolicy,
) u32 {
    if (!policy.strip_all and !policy.strip_foreign and policy.own_methods.len == 0) return 0;

    // Record list positions and the MTA's 1-based A-R occurrence indices.
    const Victim = struct { list_pos: usize, ar_index: u32 };
    var victims: std.ArrayListUnmanaged(Victim) = .{};
    defer victims.deinit(conn.allocator);

    var occurrence: u32 = 0;
    for (conn.headers.items, 0..) |hdr, pos| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, HEADER_NAME)) continue;
        occurrence += 1;
        if (!auth_results.matchesAuthservId(hdr.value, authserv_id)) continue;
        if (!shouldStrip(hdr.value, policy)) continue;
        victims.append(conn.allocator, .{ .list_pos = pos, .ar_index = occurrence }) catch continue;
    }

    if (victims.items.len == 0) return 0;

    const can_delete = conn.negotiated_actions.change_headers;
    if (!can_delete) {
        // Leave headers unchanged: callers must evaluate the message as delivered.
        log.err("cannot remove {d} forged {s} header(s) claiming authserv-id {s}: MTA did not grant SMFIF_CHGHDRS", .{ victims.items.len, HEADER_NAME, authserv_id });
        return 0;
    }

    // Pass 2: delete, highest occurrence index first.
    var removed: u32 = 0;
    var i: usize = victims.items.len;
    while (i > 0) {
        i -= 1;
        const v = victims.items[i];
        const payload = responses.changeHeader(conn.allocator, v.ar_index, HEADER_NAME, "") catch continue;
        defer conn.allocator.free(payload);
        codec.writePacket(conn.fd, payload) catch continue;
        conn.removeHeader(v.list_pos);
        removed += 1;
    }

    if (removed > 0) {
        log.info("removed {d} forged {s} header(s) claiming authserv-id {s}", .{ removed, HEADER_NAME, authserv_id });
    }
    return removed;
}

fn shouldStrip(header_value: []const u8, policy: StripPolicy) bool {
    if (policy.strip_all) return true;
    if (auth_results.assertsAnyMethod(header_value, policy.own_methods)) return true;
    if (policy.strip_foreign) {
        // A local authserv-id may assert only methods this ADMD evaluates.
        var allowed: [32][]const u8 = undefined;
        const n = joinMethods(&allowed, policy.own_methods, policy.local_methods);
        if (auth_results.assertsMethodOutside(header_value, allowed[0..n])) return true;
    }
    return false;
}

fn joinMethods(buf: *[32][]const u8, a: []const []const u8, b: []const []const u8) usize {
    var n: usize = 0;
    for (a) |m| {
        if (n == buf.len) break;
        buf[n] = m;
        n += 1;
    }
    for (b) |m| {
        if (n == buf.len) break;
        buf[n] = m;
        n += 1;
    }
    return n;
}

test "own-method policy strips only headers asserting that method" {
    const spf_only = StripPolicy{ .own_methods = &.{"spf"} };

    try std.testing.expect(shouldStrip("mail.example.org; spf=pass smtp.mailfrom=x@a.test", spf_only));
    // Removing one claimed local method removes its whole header.
    try std.testing.expect(shouldStrip("mail.example.org; spf=pass; dkim=pass header.d=a.test", spf_only));
    // Upstream results for other local evaluators must remain available.
    try std.testing.expect(!shouldStrip("mail.example.org; dkim=pass header.d=a.test", spf_only));
}

test "strip_all ignores methods" {
    const boundary = StripPolicy{ .own_methods = &.{"arc"}, .strip_all = true };
    try std.testing.expect(shouldStrip("mail.example.org; dkim=pass", boundary));
    try std.testing.expect(shouldStrip("mail.example.org; none", boundary));
}

test "strip_foreign keeps locally produced methods" {
    const sealer = StripPolicy{
        .own_methods = &.{"arc"},
        .local_methods = &.{ "spf", "dkim", "dmarc" },
        .strip_foreign = true,
    };

    try std.testing.expect(!shouldStrip("mail.example.org; spf=pass smtp.mailfrom=x@a.test", sealer));
    try std.testing.expect(!shouldStrip("mail.example.org; dmarc=pass header.from=a.test", sealer));
    try std.testing.expect(shouldStrip("mail.example.org; iprev=pass", sealer));
    try std.testing.expect(shouldStrip("mail.example.org; arc=pass", sealer));
}

test "seal-only relay treats every claimed result as foreign" {
    const relay = StripPolicy{ .own_methods = &.{"arc"}, .strip_foreign = true };

    try std.testing.expect(shouldStrip("mail.relay.test; spf=pass smtp.mailfrom=forged.test", relay));
    try std.testing.expect(shouldStrip("mail.relay.test; dkim=pass header.d=forged.test", relay));
    try std.testing.expect(shouldStrip("mail.relay.test; dmarc=pass header.from=forged.test", relay));
}

test "policy with nothing to strip is inert" {
    try std.testing.expect(!shouldStrip("mail.example.org; spf=pass", .{}));
}
