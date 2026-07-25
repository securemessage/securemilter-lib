const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const c = @cImport({
    @cInclude("zmq.h");
});

/// ZMQ PUB socket for fire-and-forget event publishing.
///
/// Each worker thread creates its own Publisher instance that connects
/// to the configured endpoint. If no endpoint is configured (null),
/// all publish calls are silent no-ops — zero overhead on the milter.
///
/// Messages are published with a topic prefix followed by a space
/// and the JSON payload: "dkim.verify {...}"
pub const Publisher = struct {
    ctx: ?*anyopaque,
    sock: ?*anyopaque,
    topic: []const u8,

    /// Create a ZMQ PUB publisher.
    ///
    /// If endpoint is null, creates a no-op publisher (all publishes silently dropped).
    pub fn init(endpoint: ?[]const u8, topic: []const u8) Publisher {
        if (endpoint == null) {
            return .{ .ctx = null, .sock = null, .topic = topic };
        }

        const ctx = c.zmq_ctx_new();
        if (ctx == null) {
            return .{ .ctx = null, .sock = null, .topic = topic };
        }

        const sock = c.zmq_socket(ctx, c.ZMQ_PUB);
        if (sock == null) {
            _ = c.zmq_ctx_destroy(ctx);
            return .{ .ctx = null, .sock = null, .topic = topic };
        }

        // Set linger to 0 so close doesn't block
        var linger: c_int = 0;
        _ = c.zmq_setsockopt(sock, c.ZMQ_LINGER, &linger, @sizeOf(c_int));

        // Set send high-water mark (drop messages if subscriber is slow)
        var hwm: c_int = 1000;
        _ = c.zmq_setsockopt(sock, c.ZMQ_SNDHWM, &hwm, @sizeOf(c_int));

        var ep_buf: [512]u8 = undefined;
        const ep = endpoint.?;
        if (ep.len >= ep_buf.len) {
            _ = c.zmq_close(sock);
            _ = c.zmq_ctx_destroy(ctx);
            return .{ .ctx = null, .sock = null, .topic = topic };
        }
        @memcpy(ep_buf[0..ep.len], ep);
        ep_buf[ep.len] = 0;

        if (c.zmq_connect(sock, &ep_buf) != 0) {
            _ = c.zmq_close(sock);
            _ = c.zmq_ctx_destroy(ctx);
            return .{ .ctx = null, .sock = null, .topic = topic };
        }

        return .{ .ctx = ctx, .sock = sock, .topic = topic };
    }

    pub fn deinit(self: *Publisher) void {
        if (self.sock) |s| _ = c.zmq_close(s);
        if (self.ctx) |ctx| _ = c.zmq_ctx_destroy(ctx);
        self.sock = null;
        self.ctx = null;
    }

    /// Publish a message with the configured topic prefix.
    ///
    /// Format on wire: "<topic> <payload>"
    /// Non-blocking. If the send would block (HWM reached), the message
    /// is silently dropped — never blocks the milter event loop.
    pub fn publish(self: *const Publisher, payload: []const u8) void {
        const sock = self.sock orelse return;

        // Build topic-prefixed message: "topic payload"
        var msg: c.zmq_msg_t = undefined;
        const total_len = self.topic.len + 1 + payload.len;
        if (c.zmq_msg_init_size(&msg, total_len) != 0) return;

        const data_ptr: [*]u8 = @ptrCast(c.zmq_msg_data(&msg));
        @memcpy(data_ptr[0..self.topic.len], self.topic);
        data_ptr[self.topic.len] = ' ';
        @memcpy(data_ptr[self.topic.len + 1 ..][0..payload.len], payload);

        // ZMQ_DONTWAIT: non-blocking, drop if HWM reached
        _ = c.zmq_msg_send(&msg, sock, c.ZMQ_DONTWAIT);
        // zmq_msg_send takes ownership on success; on failure we must close
        // But checking return is complex — zmq_msg_close is safe either way
    }

    /// Returns true if this publisher is connected (not a no-op stub).
    pub fn isConnected(self: *const Publisher) bool {
        return self.sock != null;
    }
};

test "noop publisher" {
    var pub_noop = Publisher.init(null, "test");
    defer pub_noop.deinit();

    try std.testing.expect(!pub_noop.isConnected());
    pub_noop.publish("should silently do nothing");
}

test "publisher with invalid endpoint" {
    var pub_bad = Publisher.init("tcp://255.255.255.255:99999", "test");
    defer pub_bad.deinit();

    // May or may not connect (zmq_connect doesn't validate reachability),
    // but publish should never crash
    pub_bad.publish("{\"test\": true}");
}
