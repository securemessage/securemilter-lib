const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const Allocator = mem.Allocator;
const codec = @import("codec.zig");

/// What a flush achieved.
///
/// `.pending` is not an error: the send buffer is full, the unwritten tail is
/// still held here, and the caller must arm EVFILT_WRITE and flush again when
/// the socket becomes writable. Before this module existed that condition was
/// `error.WouldBlock` and cost the connection.
pub const Status = enum { drained, pending };

/// Ceiling on bytes held for one connection.
///
/// A queue that grows without a bound turns "the MTA stopped reading" from a
/// dropped connection into unbounded resident memory, which is worse: the
/// dropped connection defers one message, the memory growth takes the daemon
/// down for every connection at once. 256 KiB is roughly 250 replies of the
/// largest shape this protocol produces here (an ARC set is three inserted
/// headers, around 1 KiB), against a default 32 KiB socket send buffer -- so
/// reaching it means the peer has read nothing for a very long time and is not
/// coming back. That case closes the connection exactly as it did before.
pub const MAX_QUEUED_BYTES: usize = 256 * 1024;

/// Capacity kept across a drain.
///
/// Reply traffic is a steady stream of small packets, so releasing the buffer
/// on every drain would allocate and free once per command. Holding it forever
/// is the other error: one message with a large modification would pin its peak
/// for the life of an MTA connection, times MaxConnections. Keep the small
/// steady-state buffer, release anything above it.
const RETAIN_CAPACITY: usize = 8 * 1024;

/// Bytes queued for one connection, and how many of them have reached the wire.
///
/// The milter reply path is non-blocking and single-threaded per worker, so a
/// write that the kernel cannot take in full has exactly three possible
/// answers: block the thread (stalls every other connection on it), drop the
/// connection (what this replaces), or hold the tail until the socket says it
/// can take more. This is the third.
///
/// ORDERING IS THE INVARIANT. Once anything is queued, everything else for that
/// connection must go through the same queue -- a direct write beside it would
/// put a later packet in front of an earlier one and desync the protocol with
/// nothing in either process saying so. That is why the fd-taking
/// `codec.writePacket` was removed rather than left available: the trap is not
/// that it is wrong to call, it is that it is wrong to call *second*.
pub const OutputBuffer = struct {
    buf: std.ArrayListUnmanaged(u8) = .{},
    /// Bytes at the front of `buf` already accepted by the kernel.
    sent: usize = 0,

    pub fn deinit(self: *OutputBuffer, allocator: Allocator) void {
        self.buf.deinit(allocator);
        self.* = .{};
    }

    /// Bytes still owed to the peer.
    pub fn pending(self: *const OutputBuffer) usize {
        return self.buf.items.len - self.sent;
    }

    /// Frame one milter packet (4-byte big-endian length, then payload) and
    /// append it to the queue. Nothing is written to any socket here.
    pub fn queuePacket(self: *OutputBuffer, allocator: Allocator, payload: []const u8) !void {
        return self.queuePackets(allocator, &.{payload});
    }

    /// Queue several packets as one indivisible unit: all of them are queued,
    /// or none is and the queue is exactly as it was.
    ///
    /// NOT A CONVENIENCE. Queueing them one at a time means the second call can
    /// fail after the first succeeded, which leaves a fragment of a multi-packet
    /// unit on the wire -- and for an ARC set, a fragment is worse than nothing:
    /// the next hop reads AAR and AMS with no ARC-Seal as a malformed chain and
    /// records a permanent cv=fail, destroying a chain that was valid (audit
    /// X-8). The old code got this for free because it built every payload
    /// before writing and the writes themselves did not allocate; a queue
    /// allocates, so the guarantee has to be stated here.
    ///
    /// Reserving the total up front is what makes the appends infallible.
    pub fn queuePackets(self: *OutputBuffer, allocator: Allocator, payloads: []const []const u8) !void {
        var need: usize = 0;
        for (payloads) |payload| {
            if (payload.len > codec.MAX_PACKET_SIZE) return error.PacketTooLarge;
            need += 4 + payload.len;
        }
        if (self.pending() + need > MAX_QUEUED_BYTES) return error.OutputQueueFull;

        // Reclaim the written prefix before growing, so a connection that is
        // draining slowly does not accumulate dead bytes in front of live ones.
        self.compact();

        try self.buf.ensureUnusedCapacity(allocator, need);
        for (payloads) |payload| {
            var hdr: [4]u8 = undefined;
            mem.writeInt(u32, &hdr, @intCast(payload.len), .big);
            self.buf.appendSliceAssumeCapacity(&hdr);
            self.buf.appendSliceAssumeCapacity(payload);
        }
    }

    /// Push as much of the queue as the socket will take.
    ///
    /// Returns `.drained` when nothing is left, `.pending` when the send buffer
    /// filled. Any other error is fatal to the connection, as before -- but a
    /// short write no longer is, because the tail stays here and is retried
    /// from the exact offset the kernel stopped at.
    pub fn flush(self: *OutputBuffer, allocator: Allocator, fd: posix.fd_t) !Status {
        while (self.sent < self.buf.items.len) {
            const n = posix.write(fd, self.buf.items[self.sent..]) catch |err| switch (err) {
                error.WouldBlock => return .pending,
                else => return err,
            };
            // A stream socket returns 0 only when offered nothing, which cannot
            // happen inside this loop. Guarded because the alternative is a loop
            // that never terminates.
            if (n == 0) return error.BrokenPipe;
            self.sent += n;
        }

        self.buf.clearRetainingCapacity();
        self.sent = 0;
        if (self.buf.capacity > RETAIN_CAPACITY) self.buf.shrinkAndFree(allocator, 0);
        return .drained;
    }

    /// Drop the already-written prefix, moving the unwritten tail to the front.
    fn compact(self: *OutputBuffer) void {
        if (self.sent == 0) return;
        const left = self.pending();
        if (left > 0) mem.copyForwards(u8, self.buf.items[0..left], self.buf.items[self.sent..]);
        self.buf.shrinkRetainingCapacity(left);
        self.sent = 0;
    }
};

// --- tests -------------------------------------------------------------------

/// Read everything currently readable from a non-blocking fd.
fn drainFd(fd: posix.fd_t, out: *std.ArrayListUnmanaged(u8)) !void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(fd, &buf) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
        if (n == 0) return;
        try out.appendSlice(std.testing.allocator, buf[0..n]);
    }
}

test "a queued packet reaches the wire with its length prefix" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var out = OutputBuffer{};
    defer out.deinit(std.testing.allocator);

    try out.queuePacket(std.testing.allocator, "Hheader-value");
    // Nothing is written until a flush: the worker decides when, which is what
    // lets several packets share one write.
    try std.testing.expectEqual(@as(usize, 17), out.pending());

    try std.testing.expectEqual(Status.drained, try out.flush(std.testing.allocator, fds[1]));

    var got: std.ArrayListUnmanaged(u8) = .{};
    defer got.deinit(std.testing.allocator);
    try drainFd(fds[0], &got);

    try std.testing.expectEqual(@as(usize, 17), got.items.len);
    try std.testing.expectEqual(@as(u32, 13), mem.readInt(u32, got.items[0..4], .big));
    try std.testing.expectEqualStrings("Hheader-value", got.items[4..]);
    try std.testing.expectEqual(@as(usize, 0), out.pending());
}

test "packets queued before a flush leave in one write, in order" {
    // The end-of-message shape: modification packets, then the final action.
    // Before buffering these were separate write(2) calls and separate segments;
    // the point of queueing them is that the peer sees one.
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var out = OutputBuffer{};
    defer out.deinit(std.testing.allocator);

    try out.queuePacket(std.testing.allocator, "iheader");
    try out.queuePacket(std.testing.allocator, "a");
    try std.testing.expectEqual(Status.drained, try out.flush(std.testing.allocator, fds[1]));

    var got: std.ArrayListUnmanaged(u8) = .{};
    defer got.deinit(std.testing.allocator);
    try drainFd(fds[0], &got);

    // 4 + 7 then 4 + 1, back to back and in the order queued.
    try std.testing.expectEqual(@as(usize, 16), got.items.len);
    try std.testing.expectEqualStrings("iheader", got.items[4..11]);
    try std.testing.expectEqual(@as(u32, 1), mem.readInt(u32, got.items[11..15], .big));
    try std.testing.expectEqual(@as(u8, 'a'), got.items[15]);
}

test "a full pipe leaves the tail queued and the reply completes once it drains" {
    // THE WHOLE POINT OF THIS MODULE, tested against a peer that really has
    // stopped reading. A pipe has a small, fixed capacity, so filling it is
    // deterministic -- unlike a socket, where forcing a short write needs a
    // concurrent reader and is therefore a race.
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var out = OutputBuffer{};
    defer out.deinit(std.testing.allocator);

    const payload = try std.testing.allocator.alloc(u8, 200 * 1024);
    defer std.testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    try out.queuePacket(std.testing.allocator, payload);
    try std.testing.expectEqual(Status.pending, try out.flush(std.testing.allocator, fds[1]));
    try std.testing.expect(out.pending() > 0);

    // The peer starts reading again; every further flush resumes at the byte
    // the kernel stopped at.
    var got: std.ArrayListUnmanaged(u8) = .{};
    defer got.deinit(std.testing.allocator);
    for (0..1000) |_| {
        try drainFd(fds[0], &got);
        if (try out.flush(std.testing.allocator, fds[1]) == .drained) break;
    } else return error.TestUnexpectedResult;
    try drainFd(fds[0], &got);

    // Byte-exact, in order, delivered exactly once: the property a short write
    // used to violate silently.
    try std.testing.expectEqual(@as(usize, 4 + payload.len), got.items.len);
    try std.testing.expectEqual(@as(u32, @intCast(payload.len)), mem.readInt(u32, got.items[0..4], .big));
    try std.testing.expectEqualSlices(u8, payload, got.items[4..]);
    try std.testing.expectEqual(@as(usize, 0), out.pending());
}

test "packets queued behind a stalled one keep their order" {
    // Ordering is the invariant that makes a queue safe: a second packet must
    // never overtake the unwritten tail of the first.
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var out = OutputBuffer{};
    defer out.deinit(std.testing.allocator);

    const big = try std.testing.allocator.alloc(u8, 100 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 'A');

    try out.queuePacket(std.testing.allocator, big);
    try std.testing.expectEqual(Status.pending, try out.flush(std.testing.allocator, fds[1]));

    // Queued while the first packet is still partly unwritten. This is also the
    // case that exercises `compact`, which rebases the tail to the front.
    try out.queuePacket(std.testing.allocator, "z");
    // Compacted, so the written prefix is not carried: without this the buffer
    // holds dead bytes in front of live ones for as long as the peer keeps
    // dribbling, and the ceiling (which counts only what is owed) stops
    // bounding what is actually held.
    try std.testing.expectEqual(out.pending(), out.buf.items.len);
    try std.testing.expectEqual(@as(usize, 0), out.sent);

    var got: std.ArrayListUnmanaged(u8) = .{};
    defer got.deinit(std.testing.allocator);
    for (0..1000) |_| {
        try drainFd(fds[0], &got);
        if (try out.flush(std.testing.allocator, fds[1]) == .drained) break;
    } else return error.TestUnexpectedResult;
    try drainFd(fds[0], &got);

    try std.testing.expectEqual(@as(usize, 4 + big.len + 5), got.items.len);
    // The small packet is last, whole, and behind every byte of the big one.
    try std.testing.expectEqual(@as(u32, 1), mem.readInt(u32, got.items[4 + big.len ..][0..4], .big));
    try std.testing.expectEqual(@as(u8, 'z'), got.items[got.items.len - 1]);
    for (got.items[4 .. 4 + big.len]) |b| try std.testing.expectEqual(@as(u8, 'A'), b);
}

test "the queue refuses to grow without bound, and refuses whole packets only" {
    var out = OutputBuffer{};
    defer out.deinit(std.testing.allocator);

    const chunk = try std.testing.allocator.alloc(u8, 64 * 1024);
    defer std.testing.allocator.free(chunk);
    @memset(chunk, 'x');

    var queued: usize = 0;
    while (out.pending() + 4 + chunk.len <= MAX_QUEUED_BYTES) : (queued += 1) {
        try out.queuePacket(std.testing.allocator, chunk);
    }
    try std.testing.expect(queued > 0);

    const before = out.pending();
    try std.testing.expectError(error.OutputQueueFull, out.queuePacket(std.testing.allocator, chunk));
    // A refused packet must leave nothing behind, or the queue holds a fragment
    // and every packet after it is misframed.
    try std.testing.expectEqual(before, out.pending());
    try std.testing.expect(out.pending() <= MAX_QUEUED_BYTES);
}

test "a multi-packet unit is queued whole or not at all, at every failure point" {
    // The ARC set (audit X-8): AAR and AMS with no ARC-Seal is read by the next
    // hop as a malformed chain and permanently fails a chain that was valid, so
    // a failure part-way through must leave the queue untouched.
    var fail_index: usize = 0;
    var saw_success = false;
    var saw_failure = false;
    while (fail_index < 6) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        var out = OutputBuffer{};
        defer out.deinit(failing.allocator());

        if (out.queuePackets(failing.allocator(), &.{ "iAAR", "iAMS", "iSEAL" })) |_| {
            saw_success = true;
            try std.testing.expectEqual(@as(usize, 4 + 4 + 4 + 4 + 4 + 5), out.pending());
        } else |_| {
            saw_failure = true;
            try std.testing.expectEqual(@as(usize, 0), out.pending());
        }
    }
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

test "a packet larger than the protocol allows is refused, not truncated" {
    var out = OutputBuffer{};
    defer out.deinit(std.testing.allocator);

    const huge = try std.testing.allocator.alloc(u8, codec.MAX_PACKET_SIZE + 1);
    defer std.testing.allocator.free(huge);
    @memset(huge, 'x');

    // @intCast to the u32 length prefix would be a silent truncation for a
    // payload past 4 GiB and a protocol violation well before that.
    try std.testing.expectError(error.PacketTooLarge, out.queuePacket(std.testing.allocator, huge));
    try std.testing.expectEqual(@as(usize, 0), out.pending());
}

test "a peer that hangs up mid-queue surfaces as an error, not as pending" {
    // `.pending` means "try again later". A dead peer must not be reported that
    // way, or the connection is held open waiting for a writability edge that
    // can never arrive.
    var sigs = std.mem.zeroes(std.c.sigset_t);
    _ = std.c.sigaddset(&sigs, 13); // SIGPIPE
    _ = std.c.sigprocmask(std.c.SIG.BLOCK, &sigs, null);

    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[1]);
    posix.close(fds[0]);

    var out = OutputBuffer{};
    defer out.deinit(std.testing.allocator);

    try out.queuePacket(std.testing.allocator, "a");
    try std.testing.expectError(error.BrokenPipe, out.flush(std.testing.allocator, fds[1]));
}

test "capacity is retained for steady traffic and released after a large burst" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var out = OutputBuffer{};
    defer out.deinit(std.testing.allocator);

    try out.queuePacket(std.testing.allocator, "asmall");
    _ = try out.flush(std.testing.allocator, fds[1]);
    try std.testing.expect(out.buf.capacity > 0);

    // A one-off large reply must not pin its peak for the life of the
    // connection, times MaxConnections.
    const big = try std.testing.allocator.alloc(u8, 32 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 'x');
    try out.queuePacket(std.testing.allocator, big);

    var got: std.ArrayListUnmanaged(u8) = .{};
    defer got.deinit(std.testing.allocator);
    for (0..1000) |_| {
        try drainFd(fds[0], &got);
        if (try out.flush(std.testing.allocator, fds[1]) == .drained) break;
    } else return error.TestUnexpectedResult;

    try std.testing.expect(out.buf.capacity <= RETAIN_CAPACITY);
}
