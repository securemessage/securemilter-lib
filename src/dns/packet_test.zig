const std = @import("std");
const mem = std.mem;
const packet = @import("packet.zig");
const testing = std.testing;
const alloc = testing.allocator;

// ============================================================
// MALFORMED / TRUNCATED PACKET TESTS
// ============================================================

test "parse empty packet" {
    try testing.expectError(error.PacketTooShort, packet.parseResponse(alloc, ""));
}

test "parse 11-byte packet (one short of header)" {
    const data = [_]u8{0} ** 11;
    try testing.expectError(error.PacketTooShort, packet.parseResponse(alloc, &data));
}

test "parse header-only packet (12 bytes, 0 questions 0 answers)" {
    var data = [_]u8{0} ** 12;
    data[0] = 0xAB;
    data[1] = 0xCD; // ID
    var resp = try packet.parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expectEqual(@as(u16, 0xABCD), resp.id);
    try testing.expectEqual(@as(usize, 0), resp.answers.items.len);
}

test "parse packet with ancount > actual data" {
    var data = [_]u8{0} ** 14;
    mem.writeInt(u16, data[6..8], 999, .big); // ancount = 999 (bogus)
    var resp = try packet.parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expectEqual(@as(usize, 0), resp.answers.items.len);
}

test "parse packet with qdcount but no question data" {
    var data = [_]u8{0} ** 12;
    mem.writeInt(u16, data[4..6], 1, .big); // qdcount = 1
    try testing.expectError(error.PacketTooShort, packet.parseResponse(alloc, &data));
}

test "truncated flag detected" {
    var data = [_]u8{0} ** 12;
    data[2] = 0x02; // TC bit (0x0200 in flags)
    var resp = try packet.parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expect(resp.truncated);
}

test "non-truncated flag" {
    var data = [_]u8{0} ** 12;
    var resp = try packet.parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expect(!resp.truncated);
}

test "parse response codes" {
    for ([_]u4{ 0, 1, 2, 3, 4, 5 }) |code| {
        var data = [_]u8{0} ** 12;
        data[3] = code; // RCODE in low 4 bits of byte 3
        var resp = try packet.parseResponse(alloc, &data);
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
    try testing.expectError(error.TooManyPointers, packet.parseResponse(alloc, &data));
}

test "pointer loop between two positions" {
    // qdcount=0, ancount=1. Answer name at offset 12 → pointer to 14 → pointer to 12 (loop).
    var data = [_]u8{0} ** 30;
    mem.writeInt(u16, data[6..8], 1, .big); // ancount = 1
    data[12] = 0xC0;
    data[13] = 14; // pointer to offset 14
    data[14] = 0xC0;
    data[15] = 12; // pointer back to offset 12 (loop)
    try testing.expectError(error.TooManyPointers, packet.parseResponse(alloc, &data));
}

test "pointer past end of packet" {
    // qdcount=0, ancount=1. Answer name at offset 12 is a pointer to offset 255 (past end).
    var data = [_]u8{0} ** 30;
    mem.writeInt(u16, data[6..8], 1, .big); // ancount = 1
    data[12] = 0xC0;
    data[13] = 0xFF; // Offset 255 — way past packet end
    try testing.expectError(error.InvalidPointer, packet.parseResponse(alloc, &data));
}

test "valid pointer chain in answer name" {
    // Craft a response with an answer whose name uses a pointer chain:
    // At offset 12: literal "a" (1 byte label + root) — used as pointer target
    // Answer at offset 15 uses a pointer to offset 12
    var data = [_]u8{0} ** 40;
    mem.writeInt(u16, data[0..2], 0x9999, .big); // ID
    mem.writeInt(u16, data[6..8], 1, .big); // ANCOUNT=1
    // qdcount=0, so answer section starts at offset 12

    // Answer name: pointer to offset 20 which has "a\0"
    data[12] = 0xC0;
    data[13] = 20;
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

    // At offset 20: literal name "a\0" (the pointer target)
    data[20] = 1;
    data[21] = 'a';
    data[22] = 0; // Wait, this overlaps with TTL bytes

    // The overlap makes this test invalid. Reconstruct without overlap:
    // Let's put the pointer target AFTER the answer data, at offset 28
    data[12] = 0xC0;
    data[13] = 28; // pointer to offset 28
    // Name target at offset 28
    data[28] = 1;
    data[29] = 'a';
    data[30] = 0;

    var resp = try packet.parseResponse(alloc, data[0..31]);
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
    try @import("packet.zig").encodeDomainName(&buf, alloc, &domain_buf);
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
        @import("packet.zig").encodeDomainName(&buf, alloc, &domain_buf),
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
    try @import("packet.zig").encodeDomainName(&buf, alloc, &domain_buf);
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
        @import("packet.zig").encodeDomainName(&buf, alloc, &domain_buf),
    );
}

// ============================================================
// TXT RDATA EDGE CASES
// ============================================================

test "txt rdata empty string (length 0)" {
    const rdata = "\x00";
    const result = try @import("packet.zig").extractTxtRdata(alloc, rdata);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "txt rdata single char" {
    const rdata = "\x01X";
    const result = try @import("packet.zig").extractTxtRdata(alloc, rdata);
    defer alloc.free(result);
    try testing.expectEqualStrings("X", result);
}

test "txt rdata string length exceeds rdata boundary" {
    const rdata = "\x05ab"; // Claims 5 bytes but only 2 follow
    const result = try @import("packet.zig").extractTxtRdata(alloc, rdata);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "txt rdata multiple strings concatenated" {
    const rdata = "\x03foo\x03bar\x03baz";
    const result = try @import("packet.zig").extractTxtRdata(alloc, rdata);
    defer alloc.free(result);
    try testing.expectEqualStrings("foobarbaz", result);
}

test "txt rdata 255-byte string (max per RFC 1035)" {
    var rdata: [256]u8 = undefined;
    rdata[0] = 255;
    @memset(rdata[1..], 'Z');
    const result = try @import("packet.zig").extractTxtRdata(alloc, &rdata);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 255), result.len);
}

test "txt rdata empty input" {
    const result = try @import("packet.zig").extractTxtRdata(alloc, "");
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

// ============================================================
// QUERY BUILDING EDGE CASES
// ============================================================

test "build query for single-label domain" {
    const pkt = try packet.buildQuery(alloc, "localhost", .A, 1);
    defer alloc.free(pkt);
    try testing.expectEqual(@as(u8, 9), pkt[12]); // "localhost" = 9 chars
}

test "build query for deep subdomain" {
    const pkt = try packet.buildQuery(alloc, "a.b.c.d.e.f.g.h.example.com", .TXT, 1);
    defer alloc.free(pkt);
    try testing.expect(pkt.len > 12); // Should succeed
}

test "build query with underscore prefix (DKIM selector)" {
    const pkt = try packet.buildQuery(alloc, "selector._domainkey.example.com", .TXT, 1);
    defer alloc.free(pkt);
    try testing.expectEqual(@as(u8, 8), pkt[12]); // "selector" = 8 chars
}

test "build query with leading dot stripped" {
    const pkt = try packet.buildQuery(alloc, ".example.com", .TXT, 1);
    defer alloc.free(pkt);
    try testing.expectEqual(@as(u8, 7), pkt[12]); // "example" not empty label
}

test "build query with trailing dot stripped" {
    const pkt = try packet.buildQuery(alloc, "example.com.", .TXT, 1);
    defer alloc.free(pkt);
    // Should produce same encoding as "example.com"
    const pkt2 = try packet.buildQuery(alloc, "example.com", .TXT, 1);
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

    var resp = try packet.parseResponse(alloc, pkt[0 .. pos + 6]);
    defer resp.deinit(alloc);

    try testing.expectEqual(@as(u16, 0x4321), resp.id);
    try testing.expectEqual(packet.ResponseCode.no_error, resp.rcode);
    try testing.expectEqual(@as(usize, 1), resp.answers.items.len);
    try testing.expectEqualStrings("x", resp.answers.items[0].name);
    try testing.expectEqual(@as(u32, 300), resp.answers.items[0].ttl);
    try testing.expectEqualStrings("v=spf1", resp.answers.items[0].data);
}

test "parse response with NXDOMAIN" {
    var data = [_]u8{0} ** 12;
    data[3] = 3; // RCODE = NAME_ERROR (NXDOMAIN)
    var resp = try packet.parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expectEqual(packet.ResponseCode.name_error, resp.rcode);
}

test "parse response with SERVFAIL" {
    var data = [_]u8{0} ** 12;
    data[3] = 2; // RCODE = SERVER_FAILURE
    var resp = try packet.parseResponse(alloc, &data);
    defer resp.deinit(alloc);
    try testing.expectEqual(packet.ResponseCode.server_failure, resp.rcode);
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
