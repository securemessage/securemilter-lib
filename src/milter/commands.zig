const std = @import("std");
const mem = std.mem;

/// MTA-to-milter command codes (milter protocol v6).
///
/// The MTA drives the conversation. Each command code is a single byte
/// that appears as the first byte of the data payload following the
/// 4-byte network-order length prefix.
pub const Code = enum(u8) {
    abort = 'A',
    body = 'B',
    connect = 'C',
    macro = 'D',
    body_eob = 'E',
    helo = 'H',
    quit_new_conn = 'K',
    header = 'L',
    mail = 'M',
    eoh = 'N',
    optneg = 'O',
    quit = 'Q',
    rcpt = 'R',
    data = 'T',
    unknown = 'U',

    pub fn expectsResponse(self: Code) bool {
        return switch (self) {
            .abort, .macro, .quit, .quit_new_conn => false,
            else => true,
        };
    }
};

/// Protocol family for SMFIC_CONNECT.
pub const Family = enum(u8) {
    unknown = 'U',
    unix = 'L',
    inet = '4',
    inet6 = '6',
};

/// Parsed SMFIC_CONNECT data.
pub const ConnectInfo = struct {
    hostname: []const u8,
    family: Family,
    port: u16,
    address: []const u8,
};

/// Parsed SMFIC_MACRO data.
pub const MacroSet = struct {
    cmd_code: u8,
    macros: MacroList,

    pub const MacroList = std.ArrayList(MacroEntry);
    pub const MacroEntry = struct {
        name: []const u8,
        value: []const u8,
    };
};

/// Parse SMFIC_CONNECT payload.
///
/// Format: hostname NUL family port-hi port-lo address NUL
pub fn parseConnect(data: []const u8) !ConnectInfo {
    const hostname_end = mem.indexOfScalar(u8, data, 0) orelse return error.MalformedPacket;
    const hostname = data[0..hostname_end];

    const rest = data[hostname_end + 1 ..];
    if (rest.len < 3) return error.MalformedPacket;

    const family: Family = switch (rest[0]) {
        'U' => .unknown,
        'L' => .unix,
        '4' => .inet,
        '6' => .inet6,
        else => .unknown,
    };

    const port = @as(u16, rest[1]) << 8 | @as(u16, rest[2]);

    const addr_start = rest[3..];
    const addr_end = mem.indexOfScalar(u8, addr_start, 0) orelse addr_start.len;
    const address = addr_start[0..addr_end];

    return .{
        .hostname = hostname,
        .family = family,
        .port = port,
        .address = address,
    };
}

/// Parse SMFIC_MACRO payload.
///
/// Format: cmdcode {name NUL value NUL}*
pub fn parseMacros(allocator: std.mem.Allocator, data: []const u8) !MacroSet {
    if (data.len < 1) return error.MalformedPacket;

    var result = MacroSet{
        .cmd_code = data[0],
        .macros = .{},
    };

    var pos: usize = 1;
    while (pos < data.len) {
        const name_end = mem.indexOfScalarPos(u8, data, pos, 0) orelse break;
        const name = data[pos..name_end];
        pos = name_end + 1;

        const value_end = mem.indexOfScalarPos(u8, data, pos, 0) orelse data.len;
        const value = data[pos..value_end];
        pos = value_end + 1;

        try result.macros.append(allocator, .{ .name = name, .value = value });
    }

    return result;
}

/// Parse a NUL-terminated string array (used by MAIL FROM, RCPT TO).
///
/// Format: arg0 NUL [arg1 NUL ...]
pub fn parseNullTermArray(data: []const u8) NullTermIterator {
    return .{ .data = data, .pos = 0 };
}

pub const NullTermIterator = struct {
    data: []const u8,
    pos: usize,

    pub fn next(self: *NullTermIterator) ?[]const u8 {
        if (self.pos >= self.data.len) return null;
        const end = mem.indexOfScalarPos(u8, self.data, self.pos, 0) orelse self.data.len;
        const val = self.data[self.pos..end];
        self.pos = end + 1;
        return val;
    }
};

/// Parse SMFIC_HEADER payload.
///
/// Format: name NUL value NUL
pub fn parseHeader(data: []const u8) !struct { name: []const u8, value: []const u8 } {
    const name_end = mem.indexOfScalar(u8, data, 0) orelse return error.MalformedPacket;
    const name = data[0..name_end];

    const rest = data[name_end + 1 ..];
    const value_end = mem.indexOfScalar(u8, rest, 0) orelse rest.len;
    const value = rest[0..value_end];

    return .{ .name = name, .value = value };
}

test "parse connect inet" {
    const data = "mail.example.com\x00" ++ "4" ++ "\x00\x19" ++ "192.0.2.1\x00";
    const info = try parseConnect(data);
    try std.testing.expectEqualStrings("mail.example.com", info.hostname);
    try std.testing.expectEqual(Family.inet, info.family);
    try std.testing.expectEqual(@as(u16, 25), info.port);
    try std.testing.expectEqualStrings("192.0.2.1", info.address);
}

test "parse macros" {
    const data = "C" ++ "{client_addr}\x00" ++ "192.0.2.1\x00" ++ "{client_name}\x00" ++ "mail.example.com\x00";
    var macros = try parseMacros(std.testing.allocator, data);
    defer macros.macros.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 'C'), macros.cmd_code);
    try std.testing.expectEqual(@as(usize, 2), macros.macros.items.len);
    try std.testing.expectEqualStrings("{client_addr}", macros.macros.items[0].name);
    try std.testing.expectEqualStrings("192.0.2.1", macros.macros.items[0].value);
}

test "parse header" {
    const data = "Subject\x00" ++ "Hello World\x00";
    const hdr = try parseHeader(data);
    try std.testing.expectEqualStrings("Subject", hdr.name);
    try std.testing.expectEqualStrings("Hello World", hdr.value);
}

test "parse null term array" {
    const data = "sender@example.com\x00" ++ "SIZE=1024\x00";
    var iter = parseNullTermArray(data);
    try std.testing.expectEqualStrings("sender@example.com", iter.next().?);
    try std.testing.expectEqualStrings("SIZE=1024", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "command expects response" {
    try std.testing.expect(Code.connect.expectsResponse());
    try std.testing.expect(Code.helo.expectsResponse());
    try std.testing.expect(Code.body_eob.expectsResponse());
    try std.testing.expect(!Code.abort.expectsResponse());
    try std.testing.expect(!Code.macro.expectsResponse());
    try std.testing.expect(!Code.quit.expectsResponse());
}
