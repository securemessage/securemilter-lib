const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// DNS record types we need for email authentication.
pub const RecordType = enum(u16) {
    A = 1,
    CNAME = 5,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
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
/// Enforces RFC 1035 limits: max 63 bytes per label, max 253 chars total.
pub fn encodeDomainName(buf: *std.ArrayList(u8), allocator: Allocator, domain: []const u8) !void {
    if (domain.len > 253) return error.NameTooLong;

    // One leading or trailing dot is tolerated. A trailing dot is simply how a
    // fully-qualified name is written, and a leading one is stripped for callers
    // that concatenate a prefix onto a domain.
    //
    // An *interior* empty label is a different thing and must not be repaired.
    // RFC 7208 §4.3 lists a zero-length label among the conditions that make a
    // domain malformed, and collapsing one queries a name nobody wrote: `a:
    // mail.example...com` was being sent to the wire as `mail.example.com`, so a
    // record naming a malformed host matched a perfectly real one.
    var name = domain;
    if (name.len > 0 and name[0] == '.') name = name[1..];
    if (name.len > 0 and name[name.len - 1] == '.') name = name[0 .. name.len - 1];

    // The root, which has no labels at all.
    if (name.len == 0) {
        try buf.append(allocator, 0);
        return;
    }

    var label_count: u8 = 0;
    var iter = mem.splitScalar(u8, name, '.');
    while (iter.next()) |label| {
        if (label.len == 0) return error.EmptyLabel;
        if (label.len > 63) return error.LabelTooLong;
        label_count += 1;
        if (label_count > 127) return error.TooManyLabels;
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
///
/// TXT records have their character-strings concatenated. Records whose RDATA
/// *is* a domain name (CNAME, PTR) or *contains* one (MX, after a 2-octet
/// preference) are decoded to presentation form, so `Answer.data` is a name a
/// caller can query.
///
/// **The decoding has to happen here and cannot be left to the caller.** RFC 1035
/// §4.1.4 allows a name in RDATA to end in a compression pointer, and a pointer
/// is an offset into the whole message. MX and PTR RDATA is where servers use
/// compression most, since the exchange usually shares a suffix with the owner
/// name. Once the RDATA has been copied out of the packet, that offset refers to
/// a buffer the caller does not have, so a compressed name is not merely
/// inconvenient to decode later -- it is unrecoverable.
///
/// The MX preference is dropped rather than reported. No caller needs it: RFC 7208
/// §5.4 checks every host in the MX set regardless of preference. A caller that
/// needs it will have to extend `Answer`.
fn extractRdata(allocator: Allocator, data: []const u8, pos: usize, rdlength: u16, record_type: u16) ![]u8 {
    if (record_type == @intFromEnum(RecordType.TXT)) {
        return extractTxtRdata(allocator, data[pos .. pos + rdlength]);
    }
    if (record_type == @intFromEnum(RecordType.CNAME) or
        record_type == @intFromEnum(RecordType.PTR))
    {
        return decodeDomainName(allocator, data, pos);
    }
    if (record_type == @intFromEnum(RecordType.MX)) {
        // MX RDATA is PREFERENCE (2 octets) then EXCHANGE.
        if (rdlength < 3) return error.PacketTooShort;
        return decodeDomainName(allocator, data, pos + 2);
    }
    return allocator.dupe(u8, data[pos .. pos + rdlength]);
}

/// TXT RDATA: one or more character-strings (length-prefixed).
/// Concatenate them into a single string.
pub fn extractTxtRdata(allocator: Allocator, rdata: []const u8) ![]u8 {
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
/// Validates that label lengths don't exceed packet bounds.
fn skipDomainName(data: []const u8, start: usize) !usize {
    var pos = start;
    var labels: u8 = 0;
    while (pos < data.len) {
        const len = data[pos];
        if (len == 0) return pos + 1;
        if (len & 0xC0 == 0xC0) {
            if (pos + 1 >= data.len) return error.PacketTooShort;
            return pos + 2;
        }
        if (len > 63) return error.LabelTooLong;
        labels += 1;
        if (labels > 127) return error.TooManyLabels;
        const next = pos + 1 + len;
        if (next > data.len) return error.PacketTooShort;
        pos = next;
    }
    return error.PacketTooShort;
}

/// Decode a domain name from wire format (handles compression pointers).
///
/// Security: enforces RFC 1035 limits and detects malicious packets:
///   - Max 253 characters in decoded name
///   - Max 127 labels
///   - Max 10 compression pointer jumps (prevents pointer loops)
///   - Pointer targets must be within packet bounds
///   - Labels > 63 bytes rejected
fn decodeDomainName(allocator: Allocator, data: []const u8, start: usize) ![]u8 {
    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    var pos = start;
    var jumps: u8 = 0;
    var labels: u8 = 0;

    while (pos < data.len) {
        const len = data[pos];
        if (len == 0) break;

        if (len & 0xC0 == 0xC0) {
            if (pos + 1 >= data.len) return error.PacketTooShort;
            const offset: usize = (@as(u16, len & 0x3F) << 8) | @as(u16, data[pos + 1]);
            if (offset >= data.len) return error.InvalidPointer;
            jumps += 1;
            if (jumps > 10) return error.TooManyPointers;
            pos = offset;
            continue;
        }

        if (len > 63) return error.LabelTooLong;
        labels += 1;
        if (labels > 127) return error.TooManyLabels;

        pos += 1;
        if (pos + len > data.len) return error.PacketTooShort;
        if (result.items.len > 0) try result.append(allocator, '.');
        try result.appendSlice(allocator, data[pos .. pos + len]);
        pos += len;

        if (result.items.len > 253) return error.NameTooLong;
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
