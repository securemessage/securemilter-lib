const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const Allocator = mem.Allocator;
const auth_results = @import("auth_results.zig");
const codec = @import("milter/codec.zig");
const responses = @import("milter/responses.zig");
const log = @import("log.zig");

/// Build and write one `Authentication-Results` field.
///
/// A caller must defer the message if this fails, rather than delivering without
/// the result. The complete value and milter packet are built before writing.
/// `leading_space` comes from negotiated protocol capabilities.
pub fn stamp(
    allocator: Allocator,
    fd: posix.fd_t,
    authserv_id: []const u8,
    results: []const auth_results.MethodResult,
    leading_space: bool,
) !void {
    const value = try auth_results.build(allocator, authserv_id, results);
    defer allocator.free(value);

    const payload = try responses.addHeader(allocator, "Authentication-Results", value, leading_space);
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

        // Packet layout: length prefix, `h`, name NUL, then value NUL.
        const name = "Authentication-Results";
        const value_start = 4 + 1 + name.len + 1;
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

test "a stamping failure defers rather than accepting" {
    // A missing local result must defer, not report success.
    const code = deferCode(error.OutOfMemory, "spf");
    try std.testing.expectEqual(@intFromEnum(responses.Code.tempfail), code);
    try std.testing.expect(code != @intFromEnum(responses.Code.accept));
    try std.testing.expect(code != @intFromEnum(responses.Code.@"continue"));
}
