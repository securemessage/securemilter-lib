const std = @import("std");
const mem = std.mem;
const posix = std.posix;
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

        // libzmq's TCP transport is IPv4-only UNLESS ZMQ_IPV6 is set -- a
        // tcp://[v6] endpoint fails outright without it (EOPNOTSUPP, seen as
        // "no events captured on the bus" on the 9.3 v6-only lab set). Sniff
        // the bracketed literal; harmless for v4 endpoints either way.
        if (endpoint) |ep| {
            if (mem.indexOf(u8, ep, "[")) |_| {
                var one: c_int = 1;
                _ = c.zmq_setsockopt(sock, c.ZMQ_IPV6, &one, @sizeOf(c_int));
            }
        }

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

test "a published frame crosses an IPv6 loopback endpoint" {
    // libzmq's TCP transport is v4-only until ZMQ_IPV6 is set; without it the
    // 9.3 v6-only lab set's collector failed its bind with EOPNOTSUPP and the
    // event bus read as a silent hole. A connect-only check has no teeth here
    // (zmq_connect defers resolution and reports success either way), so this
    // is a real round trip: bind a SUB on [::1], publish, receive.
    const addr = try std.net.Address.parseIp6("::1", 0);
    const sockfd = try posix.socket(posix.AF.INET6, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());
    var bound = addr;
    var bound_len: posix.socklen_t = bound.getOsSockLen();
    try posix.getsockname(sockfd, &bound.any, &bound_len);
    posix.close(sockfd);
    const port = bound.getPort();

    const ctx = c.zmq_ctx_new();
    defer _ = c.zmq_ctx_destroy(ctx);
    const sub = c.zmq_socket(ctx, c.ZMQ_SUB);
    // LINGER 0 and an explicit close: zmq_ctx_destroy blocks while a socket
    // is open, which would hang the whole test run at the defer.
    var zero: c_int = 0;
    _ = c.zmq_setsockopt(sub, c.ZMQ_LINGER, &zero, @sizeOf(c_int));
    defer _ = c.zmq_close(sub);
    var one: c_int = 1;
    _ = c.zmq_setsockopt(sub, c.ZMQ_IPV6, &one, @sizeOf(c_int));
    _ = c.zmq_setsockopt(sub, c.ZMQ_SUBSCRIBE, "", 0);
    const rcv_ms: c_int = 3000;
    _ = c.zmq_setsockopt(sub, c.ZMQ_RCVTIMEO, &rcv_ms, @sizeOf(c_int));

    var ep_buf: [64]u8 = undefined;
    const ep = try std.fmt.bufPrint(&ep_buf, "tcp://[::1]:{d}", .{port});
    if (c.zmq_bind(sub, ep.ptr) != 0) return error.TestUnexpectedResult;

    var pub6 = Publisher.init(ep, "test");
    defer pub6.deinit();
    try std.testing.expect(pub6.isConnected());

    // PUB drops messages until the subscription handshake completes, so
    // publish on a short loop rather than once -- the same reason the suite
    // warms every worker before trusting the bus.
    var msg: [64]u8 = undefined;
    var received = false;
    var tries: u8 = 0;
    while (tries < 40 and !received) : (tries += 1) {
        pub6.publish("ping6");
        const n = c.zmq_recv(sub, &msg, msg.len, 0);
        if (n > 0) received = true;
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }
    try std.testing.expect(received);
}
