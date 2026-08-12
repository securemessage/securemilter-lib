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
/// `leading_space`: whether the packet carries the space after the colon.
/// Not cosmetic, no default (L-2 mechanism: a default hides missing call sites).
/// `SMFIP_HDR_LEADSPC` transfers ownership of the space to the milter on output;
/// callers must use `conn.negotiated_protocol.header_leading_space`, never what
/// they requested (D-23: four daemons disagreed on their own header format).
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
///
/// `index` is a position in the whole header block, 0 being above every
/// existing header -- not the per-name occurrence index that `changeHeader`
/// takes.
///
/// `leading_space` carries the same meaning and the same obligation as in
/// `addHeader`: under `SMFIP_HDR_LEADSPC` the milter owns the space after the
/// colon. It was missing here while `addHeader` had it, which made this
/// function a trap -- switching a caller from appending to inserting would have
/// silently dropped the separator and reintroduced D-23, where four daemons
/// disagreed on their own header format.
pub fn insertHeader(
    allocator: std.mem.Allocator,
    index: u32,
    name: []const u8,
    value: []const u8,
    leading_space: bool,
) ![]u8 {
    const space: usize = if (leading_space) 1 else 0;
    const len = 1 + 4 + name.len + 1 + space + value.len + 1;
    const buf = try allocator.alloc(u8, len);

    buf[0] = @intFromEnum(Code.insert_header);
    std.mem.writeInt(u32, buf[1..5], index, .big);
    @memcpy(buf[5 .. 5 + name.len], name);
    buf[5 + name.len] = 0;
    if (leading_space) buf[6 + name.len] = ' ';
    @memcpy(buf[6 + name.len + space ..][0..value.len], value);
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
    const buf = try insertHeader(std.testing.allocator, 0, "X-Prepend", "first", false);
    defer std.testing.allocator.free(buf);

    try std.testing.expectEqual(@as(u8, 'i'), buf[0]);
    const idx = std.mem.readInt(u32, buf[1..5], .big);
    try std.testing.expectEqual(@as(u32, 0), idx);
    try std.testing.expectEqualStrings("X-Prepend", buf[5..14]);
    try std.testing.expectEqual(@as(u8, 0), buf[14]);
    try std.testing.expectEqualStrings("first", buf[15..20]);
    try std.testing.expectEqual(@as(u8, 0), buf[20]);
}

test "insert header carries the separator only under SMFIP_HDR_LEADSPC" {
    // Same obligation addHeader has. Asserted on the bytes, because the whole
    // point of D-23 was that nobody could see which side owned the space.
    inline for (.{ true, false }) |leading_space| {
        const buf = try insertHeader(std.testing.allocator, 0, "N", "v", leading_space);
        defer std.testing.allocator.free(buf);

        // 'i', index, "N", NUL, then the value with or without its space.
        const value_start = 1 + 4 + 1 + 1;
        if (leading_space) {
            try std.testing.expectEqual(@as(u8, ' '), buf[value_start]);
            try std.testing.expectEqual(@as(u8, 'v'), buf[value_start + 1]);
        } else {
            try std.testing.expectEqual(@as(u8, 'v'), buf[value_start]);
        }
        try std.testing.expectEqual(@as(u8, 0), buf[buf.len - 1]);
    }
}

test "change header delete" {
    const buf = try changeHeader(std.testing.allocator, 1, "Authentication-Results", "");
    defer std.testing.allocator.free(buf);

    try std.testing.expectEqual(@as(u8, 'm'), buf[0]);
    const idx = std.mem.readInt(u32, buf[1..5], .big);
    try std.testing.expectEqual(@as(u32, 1), idx);
}
