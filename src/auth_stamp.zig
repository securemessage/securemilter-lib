const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const Allocator = mem.Allocator;
const auth_results = @import("auth_results.zig");
const codec = @import("milter/codec.zig");
const responses = @import("milter/responses.zig");
const log = @import("log.zig");

/// Writing an `Authentication-Results` field, and what to do when that fails.
///
/// The counterpart to `header_scrub`, which removes forged A-R fields: this
/// writes the genuine one. It exists as a shared module because all four daemons
/// had the same defect in their own copy of this code (audit X-9).
///
/// Each daemon built the header value, built the milter packet and wrote it, and
/// swallowed every failure along the way:
///
/// ```
/// const value = auth_results.build(...) catch return continue;   // no header
/// const payload = responses.addHeader(...) catch return continue; // no header
/// codec.writePacket(conn.fd, payload) catch {};                   // no header
/// return accept;                                                  // "success"
/// ```
///
/// A message then reached the next hop with **no result for that method** while
/// the daemon reported success. That is not a cosmetic omission, because the
/// daemons read each other's output: `securedmarc` derives its verdict from the
/// `spf=` and `dkim=` fields the others wrote, so a silently dropped `spf=`
/// stamp makes DMARC evaluate on partial evidence and can invert its verdict. A
/// message that would have passed on an aligned SPF pass can be rejected under
/// `p=reject` because this host could not allocate a header.
///
/// The rule, the same one A-12a established for the ARC chain: **a local fault
/// is never charged to the sender.** If we cannot record what we found, we defer
/// and let the sender retry, rather than delivering a message that misrepresents
/// what we checked.

/// Build and write one `Authentication-Results` field.
///
/// The whole value and its packet are built before anything is written, so an
/// allocation failure cannot leave a partial header on the wire. That ordering
/// matters for the same reason it did in X-8: a milter `addHeader` packet cannot
/// be recalled once written.
pub fn stamp(
    allocator: Allocator,
    fd: posix.fd_t,
    authserv_id: []const u8,
    results: []const auth_results.MethodResult,
) !void {
    const value = try auth_results.build(allocator, authserv_id, results);
    defer allocator.free(value);

    const payload = try responses.addHeader(allocator, "Authentication-Results", value);
    defer allocator.free(payload);

    try codec.writePacket(fd, payload);
}

/// The milter response to send when `stamp` fails: defer, and say why.
///
/// Returned rather than sent, because the success path differs between daemons
/// and roles — some accept, some continue — while the *failure* policy must be
/// identical everywhere. That uniformity is the point of X-9: four daemons had
/// four different silent behaviours for the same fault.
///
/// `method` names the result that was lost (`"spf"`, `"dkim"`, `"dmarc"`,
/// `"arc"`) so an operator reading the log knows which verdict is missing and
/// therefore which downstream decision was affected.
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
    });

    var buf: [512]u8 = undefined;
    const n = try posix.read(fds[0], &buf);
    const packet = buf[0..n];

    try std.testing.expect(mem.indexOf(u8, packet, "Authentication-Results") != null);
    try std.testing.expect(mem.indexOf(u8, packet, "spf=pass") != null);
    try std.testing.expect(mem.indexOf(u8, packet, "smtp.mailfrom=example.com") != null);
}

test "stamp writes nothing at all when it cannot build the header" {
    // Stated as a property over every allocation `stamp` performs, so it cannot
    // rot as the internals of `build` or `addHeader` change: for each failure
    // point the socket must receive either the whole field or nothing.
    //
    // A half-written A-R field would be worse than a missing one -- the next hop
    // would parse whatever arrived as a complete statement about the message.
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
        });

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
    // The defect being guarded against is a daemon that reports success after
    // failing to record its own result.
    const code = deferCode(error.OutOfMemory, "spf");
    try std.testing.expectEqual(@intFromEnum(responses.Code.tempfail), code);
    try std.testing.expect(code != @intFromEnum(responses.Code.accept));
    try std.testing.expect(code != @intFromEnum(responses.Code.@"continue"));
}
