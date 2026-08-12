const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const Allocator = mem.Allocator;
const auth_results = @import("auth_results.zig");
const header_fold = @import("header_fold.zig");
const codec = @import("milter/codec.zig");
const responses = @import("milter/responses.zig");
const log = @import("log.zig");

/// Build and write one `Authentication-Results` field.
///
/// A caller must defer the message if this fails, rather than delivering without
/// the result. The complete value and milter packet are built before writing.
/// `leading_space` comes from negotiated protocol capabilities.
///
/// PREPENDED, NOT APPENDED, and that is a requirement rather than a preference.
/// RFC 8601 §4.1: the field "MUST be treated as though it were a trace header
/// field ... and hence MUST NOT be reordered and MUST be prepended to the
/// message", so that the position records where in the chain of handling MTAs
/// the authentication was done. §4 adds that a handler which can only append is
/// "strictly speaking ... not compliant with this specification". This used
/// SMFIR_ADDHEADER, which appends, and was therefore in exactly that category.
///
/// WHAT THIS IS NOT. Appending never placed the field in the message BODY: the
/// MTA writes an appended field at the end of the header block and emits the
/// blank separator after it, which was confirmed against a delivered message
/// before this change. The defect is trace ordering and RFC compliance, not
/// body corruption -- with four milters appending, the oldest result ends up
/// nearest the body and a consumer cannot tell which hop ran last.
pub fn stamp(
    allocator: Allocator,
    fd: posix.fd_t,
    authserv_id: []const u8,
    results: []const auth_results.MethodResult,
    leading_space: bool,
) !void {
    const value = try auth_results.build(allocator, authserv_id, results);
    defer allocator.free(value);

    // The builder folds with CRLF, the canonical form; the milter protocol
    // carries folds as bare LF (smfi_addheader(3): the MTA adds the CR).
    const wire_value = try header_fold.toWire(allocator, value);
    defer allocator.free(wire_value);

    // Index 0: above every header the MTA has shown us. Any A-R this daemon
    // was going to remove has already been removed by `header_scrub`, which
    // addresses fields by per-name occurrence and so is unaffected by this.
    const payload = try responses.insertHeader(allocator, 0, "Authentication-Results", wire_value, leading_space);
    defer allocator.free(payload);

    try codec.writePacket(fd, payload);
}

/// Return a temporary failure when `stamp` fails and log the missing method.
///
/// Callers retain their distinct success actions, but all must defer rather than
/// deliver without the local authentication result.
pub fn deferCode(err: anyerror, method: []const u8) u8 {
    log.err(
        "deferring: could not record the {s} result ({s}); delivering without it would " ++
            "misrepresent what was checked",
        .{ method, @errorName(err) },
    );
    return @intFromEnum(responses.Code.tempfail);
}

// --- tests -------------------------------------------------------------------

test "stamp writes one complete Authentication-Results field" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    try stamp(std.testing.allocator, fds[1], "mail.test", &.{
        .{
            .method = "spf",
            .result = "pass",
            .properties = &.{
                .{ .ptype = "smtp", .property = "mailfrom", .value = "example.com" },
            },
        },
    }, false);

    var buf: [512]u8 = undefined;
    const n = try posix.read(fds[0], &buf);
    const packet = buf[0..n];

    try std.testing.expect(mem.indexOf(u8, packet, "Authentication-Results") != null);
    try std.testing.expect(mem.indexOf(u8, packet, "spf=pass") != null);
    try std.testing.expect(mem.indexOf(u8, packet, "smtp.mailfrom=example.com") != null);

    // RFC 8601 §4.1 requires prepending, so this must be SMFIR_INSHEADER at
    // index 0 and not SMFIR_ADDHEADER. Asserted on the wire bytes because it is
    // the MTA's view of them that decides where the field lands.
    try std.testing.expectEqual(@as(u8, 'i'), packet[4]);
    try std.testing.expectEqual(@as(u32, 0), mem.readInt(u32, packet[5..9], .big));
}

test "under SMFIP_HDR_LEADSPC the value carries the space, otherwise it does not" {
    // The negotiated flag transfers ownership of this separator to the milter.
    // Assert the packet bytes, which are the part this module owns.
    for ([_]bool{ false, true }) |leading_space| {
        const fds = try posix.pipe2(.{ .NONBLOCK = true });
        defer posix.close(fds[0]);
        defer posix.close(fds[1]);

        try stamp(std.testing.allocator, fds[1], "mail.test", &.{
            .{ .method = "dkim", .result = "pass" },
        }, leading_space);

        var buf: [512]u8 = undefined;
        const n = try posix.read(fds[0], &buf);
        const packet = buf[0..n];

        // Packet layout: length prefix, `i`, index(4), name NUL, then value NUL.
        const name = "Authentication-Results";
        const value_start = 4 + 1 + 4 + name.len + 1;
        try std.testing.expect(packet.len > value_start);
        try std.testing.expectEqual(@as(u8, 0), packet[value_start - 1]);

        if (leading_space) {
            try std.testing.expectEqual(@as(u8, ' '), packet[value_start]);
            try std.testing.expect(mem.startsWith(u8, packet[value_start..], " mail.test;"));
        } else {
            try std.testing.expect(packet[value_start] != ' ');
            try std.testing.expect(mem.startsWith(u8, packet[value_start..], "mail.test;"));
        }
    }
}

test "stamp writes nothing at all when it cannot build the header" {
    // Every allocation failure must leave the socket without a partial field.
    var fail_index: usize = 0;
    var saw_success = false;
    var saw_failure = false;
    while (fail_index < 12) : (fail_index += 1) {
        const fds = try posix.pipe2(.{ .NONBLOCK = true });
        defer posix.close(fds[0]);
        defer posix.close(fds[1]);

        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        const res = stamp(failing.allocator(), fds[1], "mail.test", &.{
            .{ .method = "dkim", .result = "pass" },
        }, false);

        var buf: [512]u8 = undefined;
        const n = posix.read(fds[0], &buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };

        if (res) |_| {
            saw_success = true;
            try std.testing.expect(mem.indexOf(u8, buf[0..n], "dkim=pass") != null);
        } else |_| {
            saw_failure = true;
            try std.testing.expectEqual(@as(usize, 0), n);
        }
    }

    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

test "a folded value reaches the wire with LF folds and no carriage return" {
    // The builder folds a long property list with CRLF (the canonical form);
    // the milter protocol carries folds as bare LF, or the MTA's own LF-to-CRLF
    // pass doubles every fold into a blank line and the field ends early for
    // every downstream parser.
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    try stamp(std.testing.allocator, fds[1], "mail.test", &.{
        .{
            .method = "spf",
            .result = "pass",
            .properties = &.{
                .{ .ptype = "smtp", .property = "mailfrom", .value = "a-rather-long-domain-name.example.com" },
                .{ .ptype = "smtp", .property = "helo", .value = "another-rather-long-hostname.example.org" },
                .{ .ptype = "smtp", .property = "client-ip", .value = "192.0.2.123" },
            },
        },
    }, false);

    var buf: [1024]u8 = undefined;
    const n = try posix.read(fds[0], &buf);
    const packet = buf[0..n];

    try std.testing.expect(mem.indexOfScalar(u8, packet, '\r') == null);
    try std.testing.expect(mem.indexOf(u8, packet, "\n\t") != null);
    try std.testing.expect(mem.indexOf(u8, packet, "smtp.mailfrom=a-rather-long-domain-name.example.com") != null);
    try std.testing.expect(mem.indexOf(u8, packet, "smtp.client-ip=192.0.2.123") != null);
}

test "a stamping failure defers rather than accepting" {
    // A missing local result must defer, not report success.
    const code = deferCode(error.OutOfMemory, "spf");
    try std.testing.expectEqual(@intFromEnum(responses.Code.tempfail), code);
    try std.testing.expect(code != @intFromEnum(responses.Code.accept));
    try std.testing.expect(code != @intFromEnum(responses.Code.@"continue"));
}
