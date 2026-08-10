const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const alloc = testing.allocator;

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

/// EDNS0 UDP receive buffer: 1232 bytes avoids IPv6-path fragmentation.
pub const edns_udp_payload_size: u16 = 1232;

/// Build a DNS query packet with an EDNS0 OPT pseudo-record.
///
/// Advertising the EDNS0 buffer avoids the legacy 512-byte UDP limit. The caller
/// owns the returned packet.
pub fn buildQuery(allocator: Allocator, domain: []const u8, rtype: RecordType, query_id: u16) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    // Header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
    try buf.appendSlice(allocator, &mem.toBytes(mem.nativeToBig(u16, query_id)));
    try buf.appendSlice(allocator, &.{ 0x01, 0x00 }); // RD=1 (recursion desired)
    try buf.appendSlice(allocator, &.{ 0x00, 0x01 }); // QDCOUNT=1
    try buf.appendSlice(allocator, &.{ 0x00, 0x00 }); // ANCOUNT=0
    try buf.appendSlice(allocator, &.{ 0x00, 0x00 }); // NSCOUNT=0
    try buf.appendSlice(allocator, &.{ 0x00, 0x01 }); // ARCOUNT=1 (the OPT RR below)

    // Question: encoded domain name + QTYPE(2) + QCLASS(2)
    try encodeDomainName(&buf, allocator, domain);
    try buf.appendSlice(allocator, &mem.toBytes(mem.nativeToBig(u16, @intFromEnum(rtype))));
    try buf.appendSlice(allocator, &.{ 0x00, 0x01 }); // QCLASS=IN

    // EDNS0 OPT pseudo-RR (RFC 6891 §6.1.2). CLASS carries the payload size
    // rather than a class, and TTL carries extended-RCODE(1) + VERSION(1) +
    // flags(2). Version 0 and DO=0: we advertise a buffer, nothing more. No
    // options, so RDLEN is zero.
    try buf.append(allocator, 0x00); // NAME: root
    try buf.appendSlice(allocator, &.{ 0x00, 0x29 }); // TYPE: OPT (41)
    try buf.appendSlice(allocator, &mem.toBytes(mem.nativeToBig(u16, edns_udp_payload_size)));
    try buf.appendSlice(allocator, &.{ 0x00, 0x00, 0x00, 0x00 }); // ext-rcode 0, version 0, flags 0
    try buf.appendSlice(allocator, &.{ 0x00, 0x00 }); // RDLEN: 0

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

// Not decoration. Without the OPT RR a responder is capped at 512 bytes and
// answers anything larger with TC=1 and, in practice, an empty answer section --
// which is why Yahoo scored spf=none and every Microsoft 365 sender scored
// dkim=permerror. These assertions are on the exact wire bytes because the
// failure they guard against is silent: a malformed or missing OPT does not
// error, it just quietly restores the old ceiling.
test "build query advertises an EDNS0 buffer" {
    const pkt = try buildQuery(std.testing.allocator, "example.com", .TXT, 0x1234);
    defer std.testing.allocator.free(pkt);

    // ARCOUNT = 1: the OPT RR is counted, or resolvers ignore it.
    try std.testing.expectEqual(@as(u16, 1), mem.readInt(u16, pkt[10..12], .big));

    // Question ends after QCLASS at offset 29, so the OPT RR is the last 11 bytes.
    const opt = pkt[pkt.len - 11 ..];
    try std.testing.expectEqual(@as(usize, 29 + 11), pkt.len);

    try std.testing.expectEqual(@as(u8, 0), opt[0]); // NAME must be root
    try std.testing.expectEqual(@as(u16, 41), mem.readInt(u16, opt[1..3], .big)); // TYPE = OPT

    // CLASS is the advertised payload size, not a class. Assert the value too:
    // a 512 here would reintroduce the exact bug this guards.
    try std.testing.expectEqual(edns_udp_payload_size, mem.readInt(u16, opt[3..5], .big));
    try std.testing.expect(edns_udp_payload_size > 512);

    // TTL is ext-rcode(1) + VERSION(1) + flags(2). Version must be 0; a nonzero
    // version makes a conforming responder reply BADVERS and answer nothing.
    try std.testing.expectEqual(@as(u32, 0), mem.readInt(u32, opt[5..9], .big));

    // RDLEN = 0: we send no EDNS options.
    try std.testing.expectEqual(@as(u16, 0), mem.readInt(u16, opt[9..11], .big));
}

// The OPT RR is appended after the question, so it must not disturb the offsets
// every other parser and test in here depends on.
test "the EDNS0 OPT RR does not shift the question section" {
    const pkt = try buildQuery(std.testing.allocator, "example.com", .TXT, 0x1234);
    defer std.testing.allocator.free(pkt);

    try std.testing.expectEqual(@as(u8, 7), pkt[12]);
    try std.testing.expectEqualStrings("example", pkt[13..20]);
    try std.testing.expectEqual(@as(u16, 16), mem.readInt(u16, pkt[25..27], .big));
    try std.testing.expectEqual(@as(u16, 1), mem.readInt(u16, pkt[27..29], .big)); // QCLASS=IN
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

// ============================================================
// MALFORMED / TRUNCATED PACKET TESTS
// ============================================================

test "parse empty packet" {
    try testing.expectError(error.PacketTooShort, parseResponse(alloc, ""));
}

test "parse 11-byte packet (one short of header)" {
    const data = [_]u8{0} ** 11;
    try testing.expectError(error.PacketTooShort, parseResponse(alloc, &data));
}

test "parse header-only packet (12 bytes, 0 questions 0 answers)" {
    var data = [_]u8{0} ** 12;
    data[0] = 0xAB;
    data[1] = 0xCD; // ID
    var resp = try parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expectEqual(@as(u16, 0xABCD), resp.id);
    try testing.expectEqual(@as(usize, 0), resp.answers.items.len);
}

test "parse packet with ancount > actual data" {
    var data = [_]u8{0} ** 14;
    mem.writeInt(u16, data[6..8], 999, .big); // ancount = 999 (bogus)
    var resp = try parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expectEqual(@as(usize, 0), resp.answers.items.len);
}

test "parse packet with qdcount but no question data" {
    var data = [_]u8{0} ** 12;
    mem.writeInt(u16, data[4..6], 1, .big); // qdcount = 1
    try testing.expectError(error.PacketTooShort, parseResponse(alloc, &data));
}

test "truncated flag detected" {
    var data = [_]u8{0} ** 12;
    data[2] = 0x02; // TC bit (0x0200 in flags)
    var resp = try parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expect(resp.truncated);
}

test "non-truncated flag" {
    var data = [_]u8{0} ** 12;
    var resp = try parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expect(!resp.truncated);
}

test "parse response codes" {
    for ([_]u4{ 0, 1, 2, 3, 4, 5 }) |code| {
        var data = [_]u8{0} ** 12;
        data[3] = code; // RCODE in low 4 bits of byte 3
        var resp = try parseResponse(alloc, &data);
        defer resp.deinit(alloc);
        try testing.expectEqual(@as(u4, code), @intFromEnum(resp.rcode));
    }
}

// ============================================================
// COMPRESSION POINTER SECURITY TESTS
// ============================================================

test "pointer to self (infinite loop)" {
    // qdcount=0, ancount=1. Answer name at offset 12 is a pointer to itself.
    var data = [_]u8{0} ** 30;
    mem.writeInt(u16, data[6..8], 1, .big); // ancount = 1
    data[12] = 0xC0;
    data[13] = 12; // pointer to self
    try testing.expectError(error.TooManyPointers, parseResponse(alloc, &data));
}

test "pointer loop between two positions" {
    // qdcount=0, ancount=1. Answer name at offset 12 → pointer to 14 → pointer to 12 (loop).
    var data = [_]u8{0} ** 30;
    mem.writeInt(u16, data[6..8], 1, .big); // ancount = 1
    data[12] = 0xC0;
    data[13] = 14; // pointer to offset 14
    data[14] = 0xC0;
    data[15] = 12; // pointer back to offset 12 (loop)
    try testing.expectError(error.TooManyPointers, parseResponse(alloc, &data));
}

test "pointer past end of packet" {
    // qdcount=0, ancount=1. Answer name at offset 12 is a pointer to offset 255 (past end).
    var data = [_]u8{0} ** 30;
    mem.writeInt(u16, data[6..8], 1, .big); // ancount = 1
    data[12] = 0xC0;
    data[13] = 0xFF; // Offset 255 — way past packet end
    try testing.expectError(error.InvalidPointer, parseResponse(alloc, &data));
}

test "valid pointer chain in answer name" {
    // Craft a response with an answer whose name is a pointer to a literal
    // "a\0" placed after the answer's own fixed fields, so the pointer target
    // does not overlap the TYPE/CLASS/TTL/RDLENGTH/RDATA bytes that follow it.
    var data = [_]u8{0} ** 40;
    mem.writeInt(u16, data[0..2], 0x9999, .big); // ID
    mem.writeInt(u16, data[6..8], 1, .big); // ANCOUNT=1
    // qdcount=0, so answer section starts at offset 12

    // Answer name: pointer to offset 28
    data[12] = 0xC0;
    data[13] = 28;
    // TYPE=A(1)
    mem.writeInt(u16, data[14..16], 1, .big);
    // CLASS=IN(1)
    mem.writeInt(u16, data[16..18], 1, .big);
    // TTL=60
    mem.writeInt(u32, data[18..22], 60, .big);
    // RDLENGTH=4
    mem.writeInt(u16, data[22..24], 4, .big);
    // RDATA: 192.0.2.1
    data[24] = 192;
    data[25] = 0;
    data[26] = 2;
    data[27] = 1;

    // At offset 28: literal name "a\0" (the pointer target)
    data[28] = 1;
    data[29] = 'a';
    data[30] = 0;

    var resp = try parseResponse(alloc, data[0..31]);
    defer resp.deinit(alloc);
    try testing.expectEqual(@as(usize, 1), resp.answers.items.len);
    try testing.expectEqualStrings("a", resp.answers.items[0].name);
}

// ============================================================
// LABEL LENGTH / NAME LENGTH SECURITY TESTS
// ============================================================

test "label exactly 63 bytes (max allowed)" {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(alloc);

    // Build a domain: <63-char-label>.com
    var domain_buf: [67]u8 = undefined;
    @memset(domain_buf[0..63], 'a');
    @memcpy(domain_buf[63..67], ".com");
    try encodeDomainName(&buf, alloc, &domain_buf);
    try testing.expectEqual(@as(u8, 63), buf.items[0]);
}

test "label 64 bytes rejected" {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(alloc);

    var domain_buf: [68]u8 = undefined;
    @memset(domain_buf[0..64], 'a');
    @memcpy(domain_buf[64..68], ".com");
    try testing.expectError(
        error.LabelTooLong,
        encodeDomainName(&buf, alloc, &domain_buf),
    );
}

test "domain name 253 chars (max allowed)" {
    // Build a 253-char domain: 63.63.63.61 = 63+1+63+1+63+1+61 = 253
    var domain_buf: [253]u8 = undefined;
    @memset(&domain_buf, 'a');
    domain_buf[63] = '.';
    domain_buf[127] = '.';
    domain_buf[191] = '.';

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(alloc);
    try encodeDomainName(&buf, alloc, &domain_buf);
}

test "domain name 254 chars rejected" {
    var domain_buf: [254]u8 = undefined;
    @memset(&domain_buf, 'a');
    domain_buf[63] = '.';
    domain_buf[127] = '.';
    domain_buf[191] = '.';

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(alloc);
    try testing.expectError(
        error.NameTooLong,
        encodeDomainName(&buf, alloc, &domain_buf),
    );
}

// ============================================================
// TXT RDATA EDGE CASES
// ============================================================

test "txt rdata empty string (length 0)" {
    const rdata = "\x00";
    const result = try extractTxtRdata(alloc, rdata);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "txt rdata single char" {
    const rdata = "\x01X";
    const result = try extractTxtRdata(alloc, rdata);
    defer alloc.free(result);
    try testing.expectEqualStrings("X", result);
}

test "txt rdata string length exceeds rdata boundary" {
    const rdata = "\x05ab"; // Claims 5 bytes but only 2 follow
    const result = try extractTxtRdata(alloc, rdata);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "txt rdata multiple strings concatenated" {
    const rdata = "\x03foo\x03bar\x03baz";
    const result = try extractTxtRdata(alloc, rdata);
    defer alloc.free(result);
    try testing.expectEqualStrings("foobarbaz", result);
}

test "txt rdata 255-byte string (max per RFC 1035)" {
    var rdata: [256]u8 = undefined;
    rdata[0] = 255;
    @memset(rdata[1..], 'Z');
    const result = try extractTxtRdata(alloc, &rdata);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 255), result.len);
}

test "txt rdata empty input" {
    const result = try extractTxtRdata(alloc, "");
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// ============================================================
// QUERY BUILDING EDGE CASES
// ============================================================

test "build query for single-label domain" {
    const pkt = try buildQuery(alloc, "localhost", .A, 1);
    defer alloc.free(pkt);
    try testing.expectEqual(@as(u8, 9), pkt[12]); // "localhost" = 9 chars
}

test "build query for deep subdomain" {
    const pkt = try buildQuery(alloc, "a.b.c.d.e.f.g.h.example.com", .TXT, 1);
    defer alloc.free(pkt);
    try testing.expect(pkt.len > 12); // Should succeed
}

test "build query with underscore prefix (DKIM selector)" {
    const pkt = try buildQuery(alloc, "selector._domainkey.example.com", .TXT, 1);
    defer alloc.free(pkt);
    try testing.expectEqual(@as(u8, 8), pkt[12]); // "selector" = 8 chars
}

test "build query with leading dot stripped" {
    const pkt = try buildQuery(alloc, ".example.com", .TXT, 1);
    defer alloc.free(pkt);
    try testing.expectEqual(@as(u8, 7), pkt[12]); // "example" not empty label
}

test "build query with trailing dot stripped" {
    const pkt = try buildQuery(alloc, "example.com.", .TXT, 1);
    defer alloc.free(pkt);
    // Should produce same encoding as "example.com"
    const pkt2 = try buildQuery(alloc, "example.com", .TXT, 1);
    defer alloc.free(pkt2);
    try testing.expectEqualSlices(u8, pkt[12..], pkt2[12..]);
}

// ============================================================
// FULL RESPONSE PARSING (crafted real-ish packets)
// ============================================================

test "parse crafted TXT response" {
    // Hand-craft a minimal DNS response with one TXT answer
    var pkt: [64]u8 = undefined;
    @memset(&pkt, 0);

    // Header
    mem.writeInt(u16, pkt[0..2], 0x4321, .big); // ID
    pkt[2] = 0x81; // QR=1, RD=1
    pkt[3] = 0x00; // RCODE=0
    mem.writeInt(u16, pkt[4..6], 0, .big); // QDCOUNT=0
    mem.writeInt(u16, pkt[6..8], 1, .big); // ANCOUNT=1

    // Answer: name="x" (literal), TYPE=TXT, CLASS=IN, TTL=300, RDLEN=8, RDATA="v=spf1"
    var pos: usize = 12;
    pkt[pos] = 1;
    pos += 1; // label len
    pkt[pos] = 'x';
    pos += 1;
    pkt[pos] = 0;
    pos += 1; // root
    mem.writeInt(u16, pkt[pos..][0..2], 16, .big);
    pos += 2; // TYPE=TXT
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big);
    pos += 2; // CLASS=IN
    mem.writeInt(u32, pkt[pos..][0..4], 300, .big);
    pos += 4; // TTL
    mem.writeInt(u16, pkt[pos..][0..2], 7, .big);
    pos += 2; // RDLEN
    pkt[pos] = 6;
    pos += 1; // TXT string length
    @memcpy(pkt[pos..][0..6], "v=spf1");

    var resp = try parseResponse(alloc, pkt[0 .. pos + 6]);
    defer resp.deinit(alloc);

    try testing.expectEqual(@as(u16, 0x4321), resp.id);
    try testing.expectEqual(ResponseCode.no_error, resp.rcode);
    try testing.expectEqual(@as(usize, 1), resp.answers.items.len);
    try testing.expectEqualStrings("x", resp.answers.items[0].name);
    try testing.expectEqual(@as(u32, 300), resp.answers.items[0].ttl);
    try testing.expectEqualStrings("v=spf1", resp.answers.items[0].data);
}

test "parse response with NXDOMAIN" {
    var data = [_]u8{0} ** 12;
    data[3] = 3; // RCODE = NAME_ERROR (NXDOMAIN)
    var resp = try parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expectEqual(ResponseCode.name_error, resp.rcode);
}

test "parse response with SERVFAIL" {
    var data = [_]u8{0} ** 12;
    data[3] = 2; // RCODE = SERVER_FAILURE
    var resp = try parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expectEqual(ResponseCode.server_failure, resp.rcode);
}

// ============================================================
// LIVE DNS TEST (actually queries the local resolver)
// ============================================================

test "live TXT query to local resolver" {
    // Only run if we can reach the local DNS
    const resolver = @import("resolver.zig");
    var res = resolver.Resolver.init(alloc, .{ .nameservers = &.{"127.0.0.1"}, .timeout_ms = 2000 });
    defer res.deinit();

    // Query bambania.com which has a local Unbound entry
    var result = res.resolve("bambania.com", .A) catch |err| {
        // If DNS is unreachable, skip gracefully
        std.log.warn("live DNS test skipped (resolver unreachable): {}", .{err});
        return;
    };
    defer result.deinit();

    // We got a response — it should have at least one A record
    try testing.expect(result.answers.len > 0);
}
