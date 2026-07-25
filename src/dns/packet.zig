const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// DNS record types we need for email authentication.
pub const RecordType = enum(u16) {
    A = 1,
    AAAA = 28,
    MX = 15,
    TXT = 16,
    CNAME = 5,
};

/// DNS response codes.
pub const ResponseCode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3,
    not_implemented = 4,
    refused = 5,
    _,
};

/// A parsed DNS answer record.
pub const Answer = struct {
    name: []const u8,
    record_type: u16,
    ttl: u32,
    data: []const u8,
};

/// A parsed DNS response.
pub const Response = struct {
    id: u16,
    rcode: ResponseCode,
    answers: std.ArrayList(Answer),
    truncated: bool,

    pub fn deinit(self: *Response, allocator: Allocator) void {
        for (self.answers.items) |ans| {
            allocator.free(ans.name);
            allocator.free(ans.data);
        }
        self.answers.deinit(allocator);
    }
};

/// Build a DNS query packet for the given domain and record type.
///
/// Returns a buffer containing the complete DNS UDP packet.
/// Caller owns the returned slice.
pub fn buildQuery(allocator: Allocator, domain: []const u8, rtype: RecordType, query_id: u16) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    // Header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
    try buf.appendSlice(allocator, &mem.toBytes(mem.nativeToBig(u16, query_id)));
    try buf.appendSlice(allocator, &.{ 0x01, 0x00 }); // RD=1 (recursion desired)
    try buf.appendSlice(allocator, &.{ 0x00, 0x01 }); // QDCOUNT=1
    try buf.appendSlice(allocator, &.{ 0x00, 0x00 }); // ANCOUNT=0
    try buf.appendSlice(allocator, &.{ 0x00, 0x00 }); // NSCOUNT=0
    try buf.appendSlice(allocator, &.{ 0x00, 0x00 }); // ARCOUNT=0

    // Question: encoded domain name + QTYPE(2) + QCLASS(2)
    try encodeDomainName(&buf, allocator, domain);
    try buf.appendSlice(allocator, &mem.toBytes(mem.nativeToBig(u16, @intFromEnum(rtype))));
    try buf.appendSlice(allocator, &.{ 0x00, 0x01 }); // QCLASS=IN

    return buf.toOwnedSlice(allocator);
}

/// Encode a domain name in DNS wire format (label-length encoding).
fn encodeDomainName(buf: *std.ArrayList(u8), allocator: Allocator, domain: []const u8) !void {
    var iter = mem.splitScalar(u8, domain, '.');
    while (iter.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return error.LabelTooLong;
        try buf.append(allocator, @intCast(label.len));
        try buf.appendSlice(allocator, label);
    }
    try buf.append(allocator, 0); // Root label
}

/// Parse a DNS response packet.
pub fn parseResponse(allocator: Allocator, data: []const u8) !Response {
    if (data.len < 12) return error.PacketTooShort;

    const id = mem.readInt(u16, data[0..2], .big);
    const flags = mem.readInt(u16, data[2..4], .big);
    const rcode: ResponseCode = @enumFromInt(@as(u4, @truncate(flags)));
    const truncated = (flags & 0x0200) != 0;
    const ancount = mem.readInt(u16, data[6..8], .big);

    var response = Response{
        .id = id,
        .rcode = rcode,
        .answers = .{},
        .truncated = truncated,
    };

    // Skip question section
    var pos: usize = 12;
    const qdcount = mem.readInt(u16, data[4..6], .big);
    for (0..qdcount) |_| {
        pos = try skipDomainName(data, pos);
        pos += 4; // QTYPE + QCLASS
        if (pos > data.len) return error.PacketTooShort;
    }

    // Parse answer section
    for (0..ancount) |_| {
        if (pos >= data.len) break;

        const name = try decodeDomainName(allocator, data, pos);
        errdefer allocator.free(name);
        pos = try skipDomainName(data, pos);

        if (pos + 10 > data.len) {
            allocator.free(name);
            break;
        }

        const record_type = mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        pos += 2; // CLASS
        const ttl = mem.readInt(u32, data[pos..][0..4], .big);
        pos += 4;
        const rdlength = mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;

        if (pos + rdlength > data.len) {
            allocator.free(name);
            break;
        }

        const rdata = try extractRdata(allocator, data, pos, rdlength, record_type);

        try response.answers.append(allocator, .{
            .name = name,
            .record_type = record_type,
            .ttl = ttl,
            .data = rdata,
        });

        pos += rdlength;
    }

    return response;
}

/// Extract RDATA based on record type.
/// For TXT records, concatenates all character-strings.
fn extractRdata(allocator: Allocator, data: []const u8, pos: usize, rdlength: u16, record_type: u16) ![]u8 {
    if (record_type == @intFromEnum(RecordType.TXT)) {
        return extractTxtRdata(allocator, data[pos .. pos + rdlength]);
    }
    return allocator.dupe(u8, data[pos .. pos + rdlength]);
}

/// TXT RDATA: one or more character-strings (length-prefixed).
/// Concatenate them into a single string.
fn extractTxtRdata(allocator: Allocator, rdata: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    var pos: usize = 0;
    while (pos < rdata.len) {
        const str_len = rdata[pos];
        pos += 1;
        if (pos + str_len > rdata.len) break;
        try result.appendSlice(allocator, rdata[pos .. pos + str_len]);
        pos += str_len;
    }

    return result.toOwnedSlice(allocator);
}

/// Skip a domain name in wire format (handles compression pointers).
fn skipDomainName(data: []const u8, start: usize) !usize {
    var pos = start;
    while (pos < data.len) {
        const len = data[pos];
        if (len == 0) return pos + 1;
        if (len & 0xC0 == 0xC0) return pos + 2; // Compression pointer
        pos += 1 + len;
    }
    return error.PacketTooShort;
}

/// Decode a domain name from wire format (handles compression pointers).
fn decodeDomainName(allocator: Allocator, data: []const u8, start: usize) ![]u8 {
    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    var pos = start;
    var jumps: u8 = 0;

    while (pos < data.len) {
        const len = data[pos];
        if (len == 0) break;

        if (len & 0xC0 == 0xC0) {
            if (pos + 1 >= data.len) return error.PacketTooShort;
            const offset = (@as(u16, len & 0x3F) << 8) | @as(u16, data[pos + 1]);
            pos = offset;
            jumps += 1;
            if (jumps > 10) return error.TooManyPointers;
            continue;
        }

        pos += 1;
        if (pos + len > data.len) return error.PacketTooShort;
        if (result.items.len > 0) try result.append(allocator, '.');
        try result.appendSlice(allocator, data[pos .. pos + len]);
        pos += len;
    }

    return result.toOwnedSlice(allocator);
}

test "build query" {
    const pkt = try buildQuery(std.testing.allocator, "example.com", .TXT, 0x1234);
    defer std.testing.allocator.free(pkt);

    // Check header
    try std.testing.expectEqual(@as(u16, 0x1234), mem.readInt(u16, pkt[0..2], .big));
    // QDCOUNT = 1
    try std.testing.expectEqual(@as(u16, 1), mem.readInt(u16, pkt[4..6], .big));
    // First label: 7, "example"
    try std.testing.expectEqual(@as(u8, 7), pkt[12]);
    try std.testing.expectEqualStrings("example", pkt[13..20]);
    // Second label: 3, "com"
    try std.testing.expectEqual(@as(u8, 3), pkt[20]);
    try std.testing.expectEqualStrings("com", pkt[21..24]);
    // Root
    try std.testing.expectEqual(@as(u8, 0), pkt[24]);
    // QTYPE = TXT (16)
    try std.testing.expectEqual(@as(u16, 16), mem.readInt(u16, pkt[25..27], .big));
}

test "encode domain name" {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(std.testing.allocator);

    try encodeDomainName(&buf, std.testing.allocator, "_dmarc.example.com");
    // _dmarc(6) . example(7) . com(3) . root(0)
    try std.testing.expectEqual(@as(u8, 6), buf.items[0]);
    try std.testing.expectEqualStrings("_dmarc", buf.items[1..7]);
    try std.testing.expectEqual(@as(u8, 7), buf.items[7]);
}

test "extract txt rdata" {
    // Two character-strings: "v=spf1 " + "include:example.com -all"
    const rdata = "\x07v=spf1 \x18include:example.com -all";
    const result = try extractTxtRdata(std.testing.allocator, rdata);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("v=spf1 include:example.com -all", result);
}

test "decode domain name with pointer" {
    // Packet with "example.com" at offset 12, then a pointer at offset 25
    var data: [30]u8 = undefined;
    @memset(&data, 0);
    // At offset 12: \x07example\x03com\x00
    data[12] = 7;
    @memcpy(data[13..20], "example");
    data[20] = 3;
    @memcpy(data[21..24], "com");
    data[24] = 0;
    // At offset 25: pointer to offset 12
    data[25] = 0xC0;
    data[26] = 12;

    const name = try decodeDomainName(std.testing.allocator, &data, 25);
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("example.com", name);
}
