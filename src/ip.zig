//! Strict IP literal parsing (RFC 4291 §2.2), in the one place that needs it.
//!
//! Moved out of `securespf` for L-7, closing the last of S-7. The parser was
//! written there because it decides which senders are authorized; it was
//! *left* there when S-12 converted securespf's authorization sites, because
//! the three remaining consumers — `listener.zig`, `dns/resolver.zig`,
//! `dns/health.zig` — need a `net.Address` to bind or connect, and feeding
//! them meant moving the parser into the library rather than swapping a call
//! site. Copying it would have been the S-12 defect again, so it moved.
//!
//! Why the stdlib parser cannot be used here: `std.net.Ip6Address.parse`
//! is wrong in both directions for our purposes.
//!
//!   - It rejects "::1.1.1.1" and "0:0:0:0:0:0:1.1.1.1" as InvalidIpv4Mapping.
//!     §2.2 form 3 permits a trailing dotted-quad after *any* prefix; only the
//!     "::ffff:" case is an IPv4-mapped address, and the grammar is not
//!     limited to it.
//!   - It accepts ":CAFE::BABE", whose single leading colon is illegal --
//!     only "::" may begin an address -- and returns "::BABE", silently
//!     discarding a group. On the config path that repair is worse than a
//!     rejection: L-7 measured `Socket=inet:8890@:CAFE::` becoming a bind on
//!     [::]:8890 -- a daemon told to listen on one address listening on ALL
//!     of them, on the protocol that has no authentication (A-2/X-13).

const std = @import("std");
const mem = std.mem;
const net = std.net;
const posix = std.posix;

pub const Error = error{InvalidIp};

/// Longest IPv6 literal in text form, "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:d.d.d.d".
const ip6_text_max = 45;

fn hexValue(ch: u8) u16 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'f' => ch - 'a' + 10,
        'A'...'F' => ch - 'A' + 10,
        else => unreachable,
    };
}

/// Parse an IPv6 literal into its 16 octets, per RFC 4291 §2.2.
pub fn parseIp6Bytes(text: []const u8) Error![16]u8 {
    if (text.len == 0 or text.len > ip6_text_max) return error.InvalidIp;

    // Rewrite a trailing dotted-quad into the two hex groups it stands for, so
    // that only one grammar has to be parsed below.
    var buf: [ip6_text_max + 8]u8 = undefined;
    var body = text;
    if (mem.indexOfScalar(u8, text, '.') != null) {
        const cut = mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidIp;
        const quad = parseIp4Bytes(text[cut + 1 ..]) catch return error.InvalidIp;
        body = std.fmt.bufPrint(&buf, "{s}{x}:{x}", .{
            text[0 .. cut + 1],
            (@as(u16, quad[0]) << 8) | quad[1],
            (@as(u16, quad[2]) << 8) | quad[3],
        }) catch return error.InvalidIp;
    }

    var groups = [_]u16{0} ** 8;
    var count: usize = 0;
    // Where "::" appeared, as an index into the groups seen so far.
    var gap: ?usize = null;

    var i: usize = 0;
    var expect_group = true;
    while (i < body.len) {
        if (expect_group) {
            if (body[i] == ':') {
                // Only "::" may stand where a group is expected, which is what
                // rejects a single leading colon.
                if (i + 1 >= body.len or body[i + 1] != ':') return error.InvalidIp;
                if (gap != null) return error.InvalidIp; // at most one "::"
                gap = count;
                i += 2;
                if (i == body.len) {
                    expect_group = false;
                    break;
                }
                continue;
            }
            var digits: usize = 0;
            var value: u32 = 0;
            while (i < body.len and std.ascii.isHex(body[i])) : (i += 1) {
                value = value * 16 + hexValue(body[i]);
                digits += 1;
            }
            if (digits == 0 or digits > 4) return error.InvalidIp;
            if (count >= 8) return error.InvalidIp;
            groups[count] = @intCast(value);
            count += 1;
            expect_group = false;
        } else {
            if (body[i] != ':') return error.InvalidIp;
            expect_group = true;
            // Leave a second colon for the group branch, so "::" is recognised
            // there and ":::" is not mistaken for a separator plus compression.
            if (i + 1 < body.len and body[i + 1] == ':') continue;
            i += 1;
        }
    }
    // Ending on a separator, as in "1:2:" or "1:2:3:4:5:6:7:", is invalid.
    if (expect_group) return error.InvalidIp;

    if (gap) |g| {
        // §2.2: "::" indicates one or more groups of zeros, so a fully populated
        // address leaves it nothing to stand for.
        if (count >= 8) return error.InvalidIp;
        var moved: usize = 0;
        while (moved < count - g) : (moved += 1) {
            groups[7 - moved] = groups[count - 1 - moved];
            groups[count - 1 - moved] = 0;
        }
    } else if (count != 8) {
        return error.InvalidIp;
    }

    var out: [16]u8 = undefined;
    for (groups, 0..) |group, idx| {
        out[idx * 2] = @intCast(group >> 8);
        out[idx * 2 + 1] = @truncate(group);
    }
    return out;
}

/// Convert a dot-notation IPv4 string to 4 bytes.
pub fn parseIp4Bytes(ip_str: []const u8) Error![4]u8 {
    const ip = net.Ip4Address.parse(ip_str, 0) catch return error.InvalidIp;
    return @bitCast(ip.sa.addr);
}

/// Strict `net.Address` constructor for the config path (L-7): a listen or
/// nameserver address that does not parse exactly is rejected, never repaired
/// into a different address than the operator wrote.
pub fn parseIp6Address(text: []const u8, port: u16) Error!net.Address {
    const bytes = try parseIp6Bytes(text);
    return net.Address.initIp6(bytes, port, 0, 0);
}

// --- tests -------------------------------------------------------------------

test "parseIp6Bytes accepts the RFC 4291 forms" {
    // The stdlib parser rejects these as InvalidIpv4Mapping; §2.2 form 3
    // permits a trailing dotted-quad after any prefix.
    _ = try parseIp6Bytes("::1.1.1.1");
    _ = try parseIp6Bytes("0:0:0:0:0:0:1.1.1.1");
    _ = try parseIp6Bytes("::ffff:10.99.0.254");

    const loopback = try parseIp6Bytes("::1");
    try std.testing.expectEqual(@as(u8, 1), loopback[15]);
    try std.testing.expectEqual(@as(u8, 0), loopback[0]);

    const lab = try parseIp6Bytes("fd10:99::254");
    try std.testing.expectEqual(@as(u8, 0xfd), lab[0]);
    try std.testing.expectEqual(@as(u8, 0x10), lab[1]);
    try std.testing.expectEqual(@as(u8, 0x02), lab[14]);
    try std.testing.expectEqual(@as(u8, 0x54), lab[15]);
}

test "parseIp6Bytes rejects what a repairing parser would accept" {
    // L-7's measured case: one illegal leading colon. The stdlib parser
    // repairs this to "::cafe::" and a daemon told to listen on it binds the
    // wildcard instead.
    try std.testing.expectError(error.InvalidIp, parseIp6Bytes(":CAFE::"));
    try std.testing.expectError(error.InvalidIp, parseIp6Bytes(":CAFE::BABE"));
    // Two "::" compressions, a trailing separator, a fifth hex digit.
    try std.testing.expectError(error.InvalidIp, parseIp6Bytes("1::2::3"));
    try std.testing.expectError(error.InvalidIp, parseIp6Bytes("1:2:"));
    try std.testing.expectError(error.InvalidIp, parseIp6Bytes("12345::"));
    try std.testing.expectError(error.InvalidIp, parseIp6Bytes(""));
}

test "parseIp6Address returns a v6 net.Address or refuses" {
    const addr = try parseIp6Address("fd10:99::254", 53);
    try std.testing.expectEqual(@as(u8, posix.AF.INET6), addr.any.family);
    try std.testing.expectEqual(@as(u16, 53), addr.getPort());
    const bytes: [16]u8 = @bitCast(addr.in6.sa.addr);
    try std.testing.expectEqual(@as(u8, 0xfd), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x54), bytes[15]);

    // The config-path failure L-7 filed: rejected, not repaired to a bind on
    // every interface.
    try std.testing.expectError(error.InvalidIp, parseIp6Address(":CAFE::", 8890));
    try std.testing.expectError(error.InvalidIp, parseIp6Address("10.99.0.254", 53));
}
