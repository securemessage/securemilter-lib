const std = @import("std");
const mem = std.mem;
const posix = std.posix;

/// Maximum milter packet payload size (1 MB).
/// Prevents unbounded allocation from malformed length fields.
pub const MAX_PACKET_SIZE: u32 = 1024 * 1024;

/// A decoded milter packet: command byte + data payload.
pub const Packet = struct {
    cmd: u8,
    data: []const u8,
};

/// Result of a readPacket attempt on a non-blocking socket.
pub const ReadResult = union(enum) {
    packet: Packet,
    incomplete,
    closed,
    err: anyerror,
};

/// Buffered reader for milter packets from a non-blocking socket.
///
/// The milter wire format is:
///   uint32 len  (big-endian, includes cmd byte)
///   char   cmd  (1 byte)
///   char   data[len-1]
///
/// This reader accumulates bytes across multiple read() calls
/// (driven by kqueue readability events) and yields complete
/// packets when fully assembled.
pub const PacketReader = struct {
    allocator: mem.Allocator,
    buf: std.ArrayList(u8),
    expected_len: ?u32 = null,

    pub fn init(allocator: mem.Allocator) PacketReader {
        return .{
            .allocator = allocator,
            .buf = .{},
        };
    }

    pub fn deinit(self: *PacketReader) void {
        self.buf.deinit(self.allocator);
    }

    pub fn reset(self: *PacketReader) void {
        self.buf.clearRetainingCapacity();
        self.expected_len = null;
    }

    /// Feed bytes from the socket into the reader.
    ///
    /// Returns a complete Packet if one has been fully assembled,
    /// .incomplete if more bytes are needed, or .closed/.err.
    pub fn feed(self: *PacketReader, fd: posix.fd_t) ReadResult {
        var read_buf: [8192]u8 = undefined;

        const n = posix.read(fd, &read_buf) catch |e| {
            return switch (e) {
                error.WouldBlock => .incomplete,
                else => .{ .err = e },
            };
        };

        if (n == 0) return .closed;

        self.buf.appendSlice(self.allocator, read_buf[0..n]) catch |e| return .{ .err = e };

        return self.tryDecode();
    }

    /// Attempt to decode a complete packet from buffered data.
    fn tryDecode(self: *PacketReader) ReadResult {
        if (self.expected_len == null) {
            if (self.buf.items.len < 4) return .incomplete;
            self.expected_len = mem.readInt(u32, self.buf.items[0..4], .big);
        }

        const total_len = self.expected_len.?;
        if (total_len < 1 or total_len > MAX_PACKET_SIZE) {
            return .{ .err = error.PacketTooLarge };
        }

        const needed = 4 + total_len;
        if (self.buf.items.len < needed) return .incomplete;

        const cmd = self.buf.items[4];
        const data = self.buf.items[5..needed];

        return .{ .packet = .{ .cmd = cmd, .data = data } };
    }

    /// Advance past the current packet, keeping any trailing bytes
    /// for the next packet.
    pub fn consume(self: *PacketReader) void {
        const total_len = self.expected_len orelse return;
        const needed = 4 + total_len;

        if (self.buf.items.len > needed) {
            const remaining = self.buf.items.len - needed;
            mem.copyForwards(u8, self.buf.items[0..remaining], self.buf.items[needed..]);
            self.buf.shrinkRetainingCapacity(remaining);
        } else {
            self.buf.clearRetainingCapacity();
        }

        self.expected_len = null;
    }
};

/// Write a milter response packet to a file descriptor.
///
/// Encodes the 4-byte big-endian length prefix followed by the payload.
/// The payload's first byte is the response command code.
pub fn writePacket(fd: posix.fd_t, payload: []const u8) !void {
    var hdr: [4]u8 = undefined;
    mem.writeInt(u32, &hdr, @intCast(payload.len), .big);

    var iov = [_]posix.iovec_const{
        .{ .base = &hdr, .len = hdr.len },
        .{ .base = payload.ptr, .len = payload.len },
    };
    _ = try posix.writev(fd, &iov);
}

/// Convenience: write a simple single-byte response.
pub fn writeSimpleResponse(fd: posix.fd_t, code: u8) !void {
    const payload = [_]u8{code};
    try writePacket(fd, &payload);
}

test "packet reader decode" {
    var reader = PacketReader.init(std.testing.allocator);
    defer reader.deinit();

    var pkt_buf: [11]u8 = undefined;
    mem.writeInt(u32, pkt_buf[0..4], 7, .big);
    pkt_buf[4] = 'H';
    @memcpy(pkt_buf[5..11], "foobar");

    reader.buf.appendSlice(std.testing.allocator, &pkt_buf) catch unreachable;
    const result = reader.tryDecode();

    switch (result) {
        .packet => |pkt| {
            try std.testing.expectEqual(@as(u8, 'H'), pkt.cmd);
            try std.testing.expectEqualStrings("foobar", pkt.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "packet reader incomplete then complete" {
    var reader = PacketReader.init(std.testing.allocator);
    defer reader.deinit();

    var pkt_buf: [9]u8 = undefined;
    mem.writeInt(u32, pkt_buf[0..4], 5, .big);
    pkt_buf[4] = 'L';
    @memcpy(pkt_buf[5..9], "test");

    try reader.buf.appendSlice(std.testing.allocator, pkt_buf[0..3]);
    try std.testing.expectEqual(ReadResult.incomplete, reader.tryDecode());

    try reader.buf.appendSlice(std.testing.allocator, pkt_buf[3..]);
    const result = reader.tryDecode();
    switch (result) {
        .packet => |pkt| {
            try std.testing.expectEqual(@as(u8, 'L'), pkt.cmd);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "consume advances to next packet" {
    var reader = PacketReader.init(std.testing.allocator);
    defer reader.deinit();

    var pkt1: [7]u8 = undefined;
    mem.writeInt(u32, pkt1[0..4], 3, .big);
    pkt1[4] = 'A';
    pkt1[5] = 'x';
    pkt1[6] = 'y';

    var pkt2: [6]u8 = undefined;
    mem.writeInt(u32, pkt2[0..4], 2, .big);
    pkt2[4] = 'B';
    pkt2[5] = 'z';

    try reader.buf.appendSlice(std.testing.allocator, &pkt1);
    try reader.buf.appendSlice(std.testing.allocator, &pkt2);

    _ = reader.tryDecode();
    reader.consume();

    const result = reader.tryDecode();
    switch (result) {
        .packet => |pkt| {
            try std.testing.expectEqual(@as(u8, 'B'), pkt.cmd);
        },
        else => return error.TestUnexpectedResult,
    }
}
