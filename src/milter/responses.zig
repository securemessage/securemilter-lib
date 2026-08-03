const std = @import("std");
const mem = std.mem;

/// Milter-to-MTA response codes.
///
/// These are sent by the milter back to the MTA in response to commands
/// that expect a reply (see commands.Code.expectsResponse).
pub const Code = enum(u8) {
    accept = 'a',
    @"continue" = 'c',
    discard = 'd',
    reject = 'r',
    tempfail = 't',
    reply_code = 'y',
    progress = 'p',
    quarantine = 'q',
    add_header = 'h',
    insert_header = 'i',
    change_header = 'm',
    add_rcpt = '+',
    add_rcpt_par = '2',
    del_rcpt = '-',
    replace_body = 'b',
    change_from = 'e',
    optneg = 'O',
    skip = 's',
};

/// Build a simple response (no payload).
pub fn simple(code: Code) [1]u8 {
    return .{@intFromEnum(code)};
}

/// Build an SMFIR_ADDHEADER payload.
///
/// Format: name NUL value NUL
///
/// `leading_space` says whether this packet must carry the space that separates
/// the colon from the value. **It is not cosmetic, and it has no default on
/// purpose.**
///
/// `SMFIP_HDR_LEADSPC` is a two-sided bargain. D-23 asked for it to get header
/// values on the *input* side exactly as they appeared on the wire, because
/// `c=simple` hashes the field verbatim and the MTA otherwise eats one space.
/// The half that went unnoticed is that the same flag transfers ownership of
/// that space on the *output* side too: once a milter negotiates it, Postfix
/// stops inserting a space after the colon in headers that milter adds, and
/// expects the milter to supply it.
///
/// Neither daemon that asked for the flag supplied it, so every header they
/// added shipped as `Authentication-Results:mail.example.org;` while the two
/// daemons that never asked emitted `Authentication-Results: ...`. One delivered
/// message carried both forms, from the same host, over the same Postfix.
/// RFC 5322 tolerates the missing space -- FWS after the colon is optional --
/// but every RFC 8601 example writes it, and four daemons in one ADMD disagreeing
/// about their own header is the actual defect.
///
/// Required rather than defaulted for the reason recorded in L-2: a parameter
/// that quietly supplies a value when a call site forgets is the mechanism of
/// the bug, not the fix. Every caller must state which side of the bargain it
/// is on, and the only correct source for that answer is
/// `conn.negotiated_protocol.header_leading_space` -- what the MTA *agreed* to,
/// never what the daemon asked for.
pub fn addHeader(
    allocator: std.mem.Allocator,
    name: []const u8,
    value: []const u8,
    leading_space: bool,
) ![]u8 {
    const space: usize = if (leading_space) 1 else 0;
    const len = 1 + name.len + 1 + space + value.len + 1;
    const buf = try allocator.alloc(u8, len);

    buf[0] = @intFromEnum(Code.add_header);
    @memcpy(buf[1 .. 1 + name.len], name);
    buf[1 + name.len] = 0;
    if (leading_space) buf[2 + name.len] = ' ';
    @memcpy(buf[2 + name.len + space ..][0..value.len], value);
    buf[len - 1] = 0;

    return buf;
}

/// Build an SMFIR_INSHEADER payload.
///
/// Format: index(uint32) name NUL value NUL
pub fn insertHeader(
    allocator: std.mem.Allocator,
    index: u32,
    name: []const u8,
    value: []const u8,
) ![]u8 {
    const len = 1 + 4 + name.len + 1 + value.len + 1;
    const buf = try allocator.alloc(u8, len);

    buf[0] = @intFromEnum(Code.insert_header);
    std.mem.writeInt(u32, buf[1..5], index, .big);
    @memcpy(buf[5 .. 5 + name.len], name);
    buf[5 + name.len] = 0;
    @memcpy(buf[6 + name.len .. 6 + name.len + value.len], value);
    buf[len - 1] = 0;

    return buf;
}

/// Build an SMFIR_CHGHEADER payload.
///
/// Format: index(uint32) name NUL value NUL
/// A zero-length value (single NUL) means delete the header.
pub fn changeHeader(
    allocator: std.mem.Allocator,
    index: u32,
    name: []const u8,
    value: []const u8,
) ![]u8 {
    const len = 1 + 4 + name.len + 1 + value.len + 1;
    const buf = try allocator.alloc(u8, len);

    buf[0] = @intFromEnum(Code.change_header);
    std.mem.writeInt(u32, buf[1..5], index, .big);
    @memcpy(buf[5 .. 5 + name.len], name);
    buf[5 + name.len] = 0;
    @memcpy(buf[6 + name.len .. 6 + name.len + value.len], value);
    buf[len - 1] = 0;

    return buf;
}

/// Build an SMFIR_REPLYCODE payload.
///
/// Format: xyz SP text NUL
pub fn replyCode(
    allocator: std.mem.Allocator,
    smtp_code: []const u8,
    text: []const u8,
) ![]u8 {
    const len = 1 + smtp_code.len + 1 + text.len + 1;
    const buf = try allocator.alloc(u8, len);

    buf[0] = @intFromEnum(Code.reply_code);
    @memcpy(buf[1 .. 1 + smtp_code.len], smtp_code);
    buf[1 + smtp_code.len] = ' ';
    @memcpy(buf[2 + smtp_code.len .. 2 + smtp_code.len + text.len], text);
    buf[len - 1] = 0;

    return buf;
}

test "simple response" {
    const resp = simple(.@"continue");
    try std.testing.expectEqual(@as(u8, 'c'), resp[0]);
}

test "add header" {
    const buf = try addHeader(std.testing.allocator, "X-Test", "value", false);
    defer std.testing.allocator.free(buf);

    try std.testing.expectEqual(@as(u8, 'h'), buf[0]);
    try std.testing.expectEqualStrings("X-Test", buf[1..7]);
    try std.testing.expectEqual(@as(u8, 0), buf[7]);
    try std.testing.expectEqualStrings("value", buf[8..13]);
    try std.testing.expectEqual(@as(u8, 0), buf[13]);
}

test "insert header" {
    const buf = try insertHeader(std.testing.allocator, 0, "X-Prepend", "first");
    defer std.testing.allocator.free(buf);

    try std.testing.expectEqual(@as(u8, 'i'), buf[0]);
    const idx = std.mem.readInt(u32, buf[1..5], .big);
    try std.testing.expectEqual(@as(u32, 0), idx);
}

test "change header delete" {
    const buf = try changeHeader(std.testing.allocator, 1, "Authentication-Results", "");
    defer std.testing.allocator.free(buf);

    try std.testing.expectEqual(@as(u8, 'm'), buf[0]);
    const idx = std.mem.readInt(u32, buf[1..5], .big);
    try std.testing.expectEqual(@as(u32, 1), idx);
}
