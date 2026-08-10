const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const Allocator = mem.Allocator;
const codec = @import("milter/codec.zig");
const commands = @import("milter/commands.zig");
const negotiate = @import("milter/negotiate.zig");
const header_mod = @import("header.zig");
const config = @import("config.zig");

/// Milter conversation state — tracks where we are in the SMTP lifecycle.
pub const State = enum {
    new,
    negotiating,
    connected,
    helo,
    mail_from,
    rcpt_to,
    headers,
    end_of_headers,
    body,
    end_of_message,
    dns_pending,
    error_state,
    closed,
};

/// Stored macro values captured during the milter conversation.
///
/// Postfix sends macros at specific protocol stages. We capture
/// the values needed by authentication milters and expose them
/// for the product-specific callback logic.
pub const Macros = struct {
    client_addr: ?[]const u8 = null,
    client_name: ?[]const u8 = null,
    mail_from: ?[]const u8 = null,
    rcpt_to: ?[]const u8 = null,
    queue_id: ?[]const u8 = null,
    helo_name: ?[]const u8 = null,
    daemon_name: ?[]const u8 = null,
    auth_type: ?[]const u8 = null,

    /// Update macros from a parsed SMFIC_MACRO packet.
    pub fn update(self: *Macros, allocator: Allocator, macro_set: *const commands.MacroSet) !void {
        for (macro_set.macros.items) |entry| {
            try self.setByName(allocator, entry.name, entry.value);
        }
    }

    fn setByName(self: *Macros, allocator: Allocator, name: []const u8, value: []const u8) !void {
        const field = self.fieldFor(name) orelse return;
        if (field.*) |old| allocator.free(old);
        field.* = try allocator.dupe(u8, value);
    }

    fn fieldFor(self: *Macros, name: []const u8) ?*?[]const u8 {
        if (eql(name, "{client_addr}") or eql(name, "client_addr")) return &self.client_addr;
        if (eql(name, "{client_name}") or eql(name, "client_name")) return &self.client_name;
        if (eql(name, "{mail_addr}") or eql(name, "mail_addr")) return &self.mail_from;
        if (eql(name, "{rcpt_addr}") or eql(name, "rcpt_addr")) return &self.rcpt_to;
        if (eql(name, "i")) return &self.queue_id;
        if (eql(name, "{daemon_name}") or eql(name, "daemon_name")) return &self.daemon_name;
        if (eql(name, "{auth_type}") or eql(name, "auth_type")) return &self.auth_type;
        return null;
    }

    fn eql(a: []const u8, b: []const u8) bool {
        return mem.eql(u8, a, b);
    }

    pub fn deinit(self: *Macros, allocator: Allocator) void {
        inline for (std.meta.fields(Macros)) |f| {
            if (@field(self, f.name)) |val| {
                allocator.free(val);
            }
        }
        self.* = .{};
    }

    /// Reset per-message macros (keep connection-level ones).
    pub fn resetMessage(self: *Macros, allocator: Allocator) void {
        if (self.mail_from) |v| {
            allocator.free(v);
            self.mail_from = null;
        }
        if (self.rcpt_to) |v| {
            allocator.free(v);
            self.rcpt_to = null;
        }
        if (self.queue_id) |v| {
            allocator.free(v);
            self.queue_id = null;
        }
    }
};

// The header field representation lives in `header.zig`: a connection is a
// lifecycle, and how a field is spelt is a separate concern (see that file).
// Re-exported so every existing `connection.Header` reference still resolves.
pub const Header = header_mod.Header;
pub const HeaderSplit = header_mod.HeaderSplit;
pub const splitLeadingSpace = header_mod.splitLeadingSpace;

/// Caps on attacker-controlled message parts.
///
/// The milter accumulates headers and body for end-of-message hashing. Packet
/// count is unbounded (individual packets capped at 1 MiB by `codec.zig`), so
/// without caps an unbounded body becomes unbounded resident memory (audit X-4).
///
/// Exceeding a cap sets an overflow flag and makes the accumulated data
/// unavailable (not truncated): hashing a truncated copy produces a verdict
/// about content the MTA is not delivering. See `getBody`.
///
/// Read once at connection accept. Changed on restart, not SIGHUP.
pub const Limits = struct {
    /// Maximum accumulated body bytes. 0 disables the cap.
    ///
    /// Should be at least the MTA's `message_size_limit`; below it, legitimate
    /// large mail stops being signed or verified.
    max_body_bytes: usize = 10 * 1024 * 1024,

    /// Maximum header count. 0 disables.
    ///
    /// Set high: DKIM canonicalization rescans per signature (quadratic with many
    /// small headers), so this stops the amplification case. Legitimate mail can
    /// carry 150+ headers (lists, scanners, 50 ARC sets = 150 ARC headers alone).
    max_headers: usize = 500,

    /// Maximum total header bytes (names + values). 0 disables.
    /// Needed separately: a single value can approach 1 MiB, so count alone
    /// still admits hundreds of megabytes.
    max_header_bytes: usize = 1024 * 1024,

    /// Maximum DKIM-Signature headers verified per message. 0 disables.
    /// Each costs DNS + RSA verify; unbounded = remote CPU/DNS amplification
    /// (audit D-4, measured 355x). Matches OpenDKIM's `MaxSignatures`.
    ///
    /// Not applied to ARC: RFC 8617 §5.1.1 permits 50 sets, already enforced
    /// by `securearc`; `max_headers` bounds ARC exposure.
    max_signatures: usize = 20,

    /// Read caps from config, falling back to struct defaults.
    /// Shared across all four daemons; inconsistent caps expose the weakest.
    pub fn fromSection(section: *const config.Config.Section) Limits {
        const defaults = Limits{};
        return .{
            .max_body_bytes = section.getSize("MaxBodyBytes", defaults.max_body_bytes),
            .max_headers = section.getInt("MaxHeaders", usize, defaults.max_headers),
            .max_header_bytes = section.getSize("MaxHeaderBytes", defaults.max_header_bytes),
            .max_signatures = section.getInt("MaxSignatures", usize, defaults.max_signatures),
        };
    }
};

/// A single milter connection's state and buffered data.
///
/// One Connection exists per accepted socket. It holds the protocol
/// reader, conversation state, accumulated macros and headers, and
/// a reference to the listener config it came from.
pub const Connection = struct {
    allocator: Allocator,
    fd: posix.fd_t,
    state: State,
    reader: codec.PacketReader,
    macros: Macros,
    headers: std.ArrayList(Header),
    helo_name: ?[]const u8,
    mail_from_raw: ?[]const u8,
    recipients: std.ArrayList([]const u8),
    /// Accumulated message body, flat buffer (not chunk list).
    /// Flat: single comparison for `appendBody` cap, no concatenation in `getBody`.
    body: std.ArrayList(u8),
    listener_index: usize,
    limits: Limits,
    /// Running total of accumulated header name+value bytes.
    header_bytes: usize,
    /// A body cap or allocation failure was hit; the accumulated body was
    /// discarded and is not recoverable for this message.
    body_overflow: bool,
    /// A header cap was hit; the accumulated header list is incomplete.
    headers_overflow: bool,
    /// Actions the MTA granted during OPTNEG. A milter must not send a
    /// modification packet for an action that was not negotiated.
    negotiated_actions: negotiate.ActionFlags = .{},
    /// Protocol flags the MTA granted during OPTNEG. Must be retained, not just
    /// used to build the response and discarded: `header_leading_space` in
    /// particular changes what a header value contains, and a milter that asks
    /// for it without checking whether it got it would misread every header
    /// against an MTA that declined.
    negotiated_protocol: negotiate.ProtocolFlags = .{},
    /// Peer IP address of the milter TCP connection (the Postfix instance).
    /// Format: bare IP string (e.g., "10.99.0.1") or "local" for Unix sockets.
    peer_addr: [64]u8 = undefined,
    peer_addr_len: u8 = 0,
    /// SMTP client address from SMFIC_CONNECT (milter protocol equivalent of
    /// libmilter's `hostaddr` / `getpeername(2)`). Held separately from the
    /// `{client_addr}` macro: that macro is optional and absent from Postfix's
    /// default `milter_connect_macros`. Read via `clientAddr()`.
    connect_addr: ?[]const u8 = null,
    /// Address family from SMFIC_CONNECT. Distinguishes "no IP (local/unix
    /// submission)" from "IP present but unparseable" (none vs permerror).
    connect_family: commands.Family = .unknown,

    pub fn init(allocator: Allocator, fd: posix.fd_t, listener_index: usize, limits: Limits) Connection {
        return .{
            .allocator = allocator,
            .fd = fd,
            .state = .new,
            .reader = codec.PacketReader.init(allocator),
            .macros = .{},
            .headers = .{},
            .helo_name = null,
            .mail_from_raw = null,
            .recipients = .{},
            .body = .{},
            .listener_index = listener_index,
            .limits = limits,
            .header_bytes = 0,
            .body_overflow = false,
            .headers_overflow = false,
        };
    }

    /// Set the peer address from an accepted connection's address.
    /// For TCP: formats the IP. For Unix/unknown: stores "local".
    pub fn setPeerAddr(self: *Connection, addr: std.net.Address) void {
        var buf: [64]u8 = undefined;
        const ip_str = switch (addr.any.family) {
            posix.AF.INET => blk: {
                const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
                break :blk std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch "unknown";
            },
            posix.AF.INET6 => std.fmt.bufPrint(&buf, "{any}", .{addr.in6}) catch "unknown",
            else => "local",
        };
        const len: u8 = @intCast(@min(ip_str.len, 64));
        @memcpy(self.peer_addr[0..len], ip_str[0..len]);
        self.peer_addr_len = len;
    }

    /// Get the peer address string. Returns "local" if not set.
    pub fn getPeerAddr(self: *const Connection) []const u8 {
        if (self.peer_addr_len == 0) return "local";
        return self.peer_addr[0..self.peer_addr_len];
    }

    /// Format the peer field for logging: "{daemon_name}[{ip}]" or "unknown[{ip}]" or "local".
    pub fn getPeerDisplay(self: *const Connection) struct { name: []const u8, ip: []const u8 } {
        const ip = self.getPeerAddr();
        const name = self.macros.daemon_name orelse "unknown";
        return .{ .name = name, .ip = ip };
    }

    pub fn deinit(self: *Connection) void {
        posix.close(self.fd);
        self.reader.deinit();
        self.macros.deinit(self.allocator);
        self.freeHeaders();
        self.headers.deinit(self.allocator);
        if (self.helo_name) |h| self.allocator.free(h);
        if (self.mail_from_raw) |m| self.allocator.free(m);
        if (self.connect_addr) |a| self.allocator.free(a);
        self.freeRecipients();
        self.recipients.deinit(self.allocator);
        self.body.deinit(self.allocator);
    }

    /// Reset per-message state (called on ABORT or after EOM).
    pub fn resetMessage(self: *Connection) void {
        self.macros.resetMessage(self.allocator);
        self.freeHeaders();
        if (self.mail_from_raw) |m| {
            self.allocator.free(m);
            self.mail_from_raw = null;
        }
        self.freeRecipients();
        // Release rather than retain the body buffer: capacity sized by the
        // largest message on this connection would otherwise be held for the
        // life of a long-lived MTA connection.
        self.body.clearAndFree(self.allocator);
        self.header_bytes = 0;
        self.body_overflow = false;
        self.headers_overflow = false;
        self.state = .connected;
    }

    /// Store a header from SMFIC_HEADER.
    ///
    /// Returns `error.TooManyHeaders` once a cap in `limits` is reached, and
    /// latches `headers_overflow` so the incomplete list cannot be mistaken for
    /// the message's real headers.
    pub fn addHeader(self: *Connection, name: []const u8, value: []const u8) !void {
        return self.addHeaderSpaced(name, value, true);
    }

    /// As `addHeader`, but states whether a space followed the colon on the wire.
    /// The worker uses this when `SMFIP_HDR_LEADSPC` is in force; `addHeader`'s
    /// `true` is the classic MTA behaviour and stays correct when it is not.
    pub fn addHeaderSpaced(self: *Connection, name: []const u8, value: []const u8, had_space: bool) !void {
        if (self.headers_overflow) return error.TooManyHeaders;

        if (self.limits.max_headers != 0 and self.headers.items.len >= self.limits.max_headers) {
            self.headers_overflow = true;
            return error.TooManyHeaders;
        }
        if (self.limits.max_header_bytes != 0 and
            self.header_bytes + name.len + value.len > self.limits.max_header_bytes)
        {
            self.headers_overflow = true;
            return error.TooManyHeaders;
        }

        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);
        const value_dup = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_dup);
        try self.headers.append(self.allocator, .{
            .name = name_dup,
            .value = value_dup,
            .had_space = had_space,
        });
        self.header_bytes += name.len + value.len;
    }

    /// True when a cap or allocation failure left the accumulated copy of this
    /// message incomplete. Callers must not authenticate or sign such a message:
    /// any hash they compute describes content the MTA is not delivering.
    pub fn contentTruncated(self: *const Connection) bool {
        return self.body_overflow or self.headers_overflow;
    }

    /// Count headers with the given name, stopping once `limit` is exceeded.
    ///
    /// Used to reject signature floods before spending a DNS lookup and an RSA
    /// verify on each one. Short-circuits so that counting a flood is itself
    /// cheap.
    pub fn countHeadersCapped(self: *const Connection, name: []const u8, limit: usize) usize {
        var count: usize = 0;
        for (self.headers.items) |hdr| {
            if (!std.ascii.eqlIgnoreCase(hdr.name, name)) continue;
            count += 1;
            if (limit != 0 and count > limit) return count;
        }
        return count;
    }

    /// Drop a header from the accumulated list, preserving the order of the
    /// rest. Used after telling the MTA to delete it, so that product logic
    /// running later in the same end-of-message pass cannot read a header the
    /// delivered message will not contain.
    pub fn removeHeader(self: *Connection, index: usize) void {
        if (index >= self.headers.items.len) return;
        const hdr = self.headers.orderedRemove(index);
        self.allocator.free(hdr.name);
        self.allocator.free(hdr.value);
    }

    /// Store envelope sender from SMFIC_MAIL.
    pub fn setMailFrom(self: *Connection, sender: []const u8) !void {
        if (self.mail_from_raw) |old| self.allocator.free(old);
        self.mail_from_raw = try self.allocator.dupe(u8, sender);
    }

    /// Store a recipient from SMFIC_RCPT.
    pub fn addRecipient(self: *Connection, rcpt: []const u8) !void {
        const dup = try self.allocator.dupe(u8, rcpt);
        try self.recipients.append(self.allocator, dup);
    }

    /// Store HELO name from SMFIC_HELO.
    pub fn setHelo(self: *Connection, name: []const u8) !void {
        if (self.helo_name) |old| self.allocator.free(old);
        self.helo_name = try self.allocator.dupe(u8, name);
    }

    /// Store client address/family from SMFIC_CONNECT.
    /// Connection-level: not cleared by `resetMessage` (client unchanged within session).
    pub fn setConnectInfo(self: *Connection, info: commands.ConnectInfo) !void {
        if (self.connect_addr) |old| self.allocator.free(old);
        self.connect_addr = try self.allocator.dupe(u8, info.address);
        self.connect_family = info.family;
    }

    /// SMTP client address, or null when none exists (unix socket, local submission).
    /// Prefers `{client_addr}` macro; falls back to SMFIC_CONNECT address (absent
    /// from default Postfix `milter_connect_macros`).
    ///
    /// Returns optional: callers must not substitute a placeholder. A literal
    /// "unknown" parses as neither IPv4 nor IPv6, so every SPF mechanism would
    /// decline and evaluation would reach the terminal `-all` (false `fail`).
    pub fn clientAddr(self: *const Connection) ?[]const u8 {
        if (self.macros.client_addr) |m| {
            if (m.len > 0) return m;
        }
        if (self.connect_addr) |a| {
            if (a.len > 0) return a;
        }
        return null;
    }

    fn freeHeaders(self: *Connection) void {
        for (self.headers.items) |hdr| {
            self.allocator.free(hdr.name);
            self.allocator.free(hdr.value);
        }
        self.headers.clearRetainingCapacity();
    }

    fn freeRecipients(self: *Connection) void {
        for (self.recipients.items) |r| {
            self.allocator.free(r);
        }
        self.recipients.clearRetainingCapacity();
    }

    /// Append a body chunk. On cap or allocation failure: discards accumulated
    /// body, latches `body_overflow`, subsequent calls return immediately (no
    /// further memory growth from continued streaming).
    pub fn appendBody(self: *Connection, data: []const u8) !void {
        if (self.body_overflow) return error.BodyTooLarge;

        if (self.limits.max_body_bytes != 0 and
            self.body.items.len + data.len > self.limits.max_body_bytes)
        {
            self.body_overflow = true;
            self.body.clearAndFree(self.allocator);
            return error.BodyTooLarge;
        }

        self.body.appendSlice(self.allocator, data) catch |e| {
            self.body_overflow = true;
            self.body.clearAndFree(self.allocator);
            return e;
        };
    }

    /// The accumulated body, or null if it is not the whole body.
    ///
    /// Optional rather than empty slice: an incomplete body must be distinguishable
    /// from a genuinely empty one, since either could otherwise produce a bogus
    /// verdict. Null forces the caller to decide.
    pub fn getBody(self: *const Connection) ?[]const u8 {
        if (self.body_overflow) return null;
        return self.body.items;
    }
};

test "connection lifecycle" {
    const allocator = std.testing.allocator;

    var pipe: [2]posix.fd_t = undefined;
    const result = std.c.pipe(&pipe);
    if (result != 0) return error.PipeFailed;
    defer posix.close(pipe[0]);

    var conn = Connection.init(allocator, pipe[1], 0, .{});
    defer conn.deinit();

    try std.testing.expectEqual(State.new, conn.state);

    try conn.setHelo("mail.example.com");
    try std.testing.expectEqualStrings("mail.example.com", conn.helo_name.?);

    try conn.setMailFrom("sender@example.com");
    try std.testing.expectEqualStrings("sender@example.com", conn.mail_from_raw.?);

    try conn.addRecipient("rcpt1@example.com");
    try conn.addRecipient("rcpt2@example.com");
    try std.testing.expectEqual(@as(usize, 2), conn.recipients.items.len);

    try conn.addHeader("Subject", "Test");
    try conn.addHeader("From", "sender@example.com");
    try std.testing.expectEqual(@as(usize, 2), conn.headers.items.len);

    conn.resetMessage();
    try std.testing.expectEqual(@as(usize, 0), conn.headers.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.recipients.items.len);
    try std.testing.expect(conn.mail_from_raw == null);
    try std.testing.expectEqualStrings("mail.example.com", conn.helo_name.?);
}

/// Build a Connection over a throwaway pipe. Caller deinits.
fn testConn(allocator: Allocator, pipe: *[2]posix.fd_t, limits: Limits) !Connection {
    if (std.c.pipe(pipe) != 0) return error.PipeFailed;
    return Connection.init(allocator, pipe[1], 0, limits);
}

test "body accumulates contiguously across chunks" {
    const allocator = std.testing.allocator;
    var pipe: [2]posix.fd_t = undefined;
    var conn = try testConn(allocator, &pipe, .{});
    defer conn.deinit();
    defer posix.close(pipe[0]);

    try conn.appendBody("hello ");
    try conn.appendBody("world");
    try std.testing.expectEqualStrings("hello world", conn.getBody().?);
    try std.testing.expect(!conn.contentTruncated());
}

test "empty body is distinguishable from unavailable body" {
    const allocator = std.testing.allocator;
    var pipe: [2]posix.fd_t = undefined;
    var conn = try testConn(allocator, &pipe, .{ .max_body_bytes = 8 });
    defer conn.deinit();
    defer posix.close(pipe[0]);

    // No body at all: an empty slice, not null. A message with no body is
    // legitimate and must still be signable.
    try std.testing.expectEqualStrings("", conn.getBody().?);

    try std.testing.expectError(error.BodyTooLarge, conn.appendBody("123456789"));
    // Over the cap: null, so no caller can mistake it for the empty case above.
    try std.testing.expect(conn.getBody() == null);
}

test "body cap discards the partial copy and stops growing" {
    const allocator = std.testing.allocator;
    var pipe: [2]posix.fd_t = undefined;
    var conn = try testConn(allocator, &pipe, .{ .max_body_bytes = 16 });
    defer conn.deinit();
    defer posix.close(pipe[0]);

    try conn.appendBody("0123456789");
    try std.testing.expectEqual(@as(usize, 10), conn.body.items.len);

    // Past the cap: discard partial body (unusable for hashing), stop growing.
    try std.testing.expectError(error.BodyTooLarge, conn.appendBody("abcdefg"));
    try std.testing.expect(conn.body_overflow);
    try std.testing.expectEqual(@as(usize, 0), conn.body.capacity);

    // Continued streaming after cap: no additional memory allocated.
    for (0..1000) |_| {
        try std.testing.expectError(error.BodyTooLarge, conn.appendBody("padding padding padding"));
    }
    try std.testing.expectEqual(@as(usize, 0), conn.body.capacity);
}

test "header count cap latches overflow" {
    const allocator = std.testing.allocator;
    var pipe: [2]posix.fd_t = undefined;
    var conn = try testConn(allocator, &pipe, .{ .max_headers = 3 });
    defer conn.deinit();
    defer posix.close(pipe[0]);

    try conn.addHeader("A", "1");
    try conn.addHeader("B", "2");
    try conn.addHeader("C", "3");
    try std.testing.expectError(error.TooManyHeaders, conn.addHeader("D", "4"));

    try std.testing.expect(conn.headers_overflow);
    try std.testing.expect(conn.contentTruncated());
    try std.testing.expectEqual(@as(usize, 3), conn.headers.items.len);
}

test "header byte cap trips independently of the count cap" {
    const allocator = std.testing.allocator;
    var pipe: [2]posix.fd_t = undefined;
    // Count cap is generous; only the byte cap can stop this.
    var conn = try testConn(allocator, &pipe, .{ .max_headers = 1000, .max_header_bytes = 64 });
    defer conn.deinit();
    defer posix.close(pipe[0]);

    const big = "x" ** 60;
    try conn.addHeader("X", big);
    try std.testing.expectError(error.TooManyHeaders, conn.addHeader("Y", big));
    try std.testing.expect(conn.headers_overflow);
}

test "zero limits disable the caps" {
    const allocator = std.testing.allocator;
    var pipe: [2]posix.fd_t = undefined;
    var conn = try testConn(allocator, &pipe, .{
        .max_body_bytes = 0,
        .max_headers = 0,
        .max_header_bytes = 0,
    });
    defer conn.deinit();
    defer posix.close(pipe[0]);

    for (0..100) |_| try conn.appendBody("0123456789");
    try std.testing.expectEqual(@as(usize, 1000), conn.getBody().?.len);

    for (0..300) |_| try conn.addHeader("Received", "by host");
    try std.testing.expectEqual(@as(usize, 300), conn.headers.items.len);
    try std.testing.expect(!conn.contentTruncated());
}

test "resetMessage clears overflow so the next message is judged on its own" {
    const allocator = std.testing.allocator;
    var pipe: [2]posix.fd_t = undefined;
    var conn = try testConn(allocator, &pipe, .{ .max_body_bytes = 4, .max_headers = 1 });
    defer conn.deinit();
    defer posix.close(pipe[0]);

    try std.testing.expectError(error.BodyTooLarge, conn.appendBody("too long"));
    try conn.addHeader("A", "1");
    try std.testing.expectError(error.TooManyHeaders, conn.addHeader("B", "2"));
    try std.testing.expect(conn.contentTruncated());

    // An MTA reuses one milter connection for many messages; a single oversized
    // message must not condemn the rest.
    conn.resetMessage();
    try std.testing.expect(!conn.contentTruncated());
    try std.testing.expectEqual(@as(usize, 0), conn.header_bytes);
    try conn.appendBody("ok");
    try std.testing.expectEqualStrings("ok", conn.getBody().?);
}

test "countHeadersCapped short-circuits past the limit" {
    const allocator = std.testing.allocator;
    var pipe: [2]posix.fd_t = undefined;
    var conn = try testConn(allocator, &pipe, .{ .max_headers = 0 });
    defer conn.deinit();
    defer posix.close(pipe[0]);

    for (0..50) |_| try conn.addHeader("DKIM-Signature", "v=1;");
    try conn.addHeader("From", "a@b.c");

    // Case-insensitive per RFC 5322, and stops as soon as the limit is beaten
    // rather than counting the whole flood.
    try std.testing.expectEqual(@as(usize, 21), conn.countHeadersCapped("dkim-signature", 20));
    try std.testing.expectEqual(@as(usize, 50), conn.countHeadersCapped("DKIM-Signature", 0));
    try std.testing.expectEqual(@as(usize, 1), conn.countHeadersCapped("from", 20));
}

test "Limits.fromSection reads overrides and keeps defaults otherwise" {
    const source =
        \\MaxBodyBytes = 25M
        \\MaxSignatures = 5
    ;
    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    const limits = Limits.fromSection(cfg.global().?);
    try std.testing.expectEqual(@as(usize, 25 * 1024 * 1024), limits.max_body_bytes);
    try std.testing.expectEqual(@as(usize, 5), limits.max_signatures);

    // Untouched options keep the struct defaults rather than becoming zero,
    // which would silently disable the cap.
    const defaults = Limits{};
    try std.testing.expectEqual(defaults.max_headers, limits.max_headers);
    try std.testing.expectEqual(defaults.max_header_bytes, limits.max_header_bytes);
}

test "Limits.fromSection honours an explicit zero as unlimited" {
    const source =
        \\MaxBodyBytes = 0
        \\MaxHeaders = 0
    ;
    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    const limits = Limits.fromSection(cfg.global().?);
    try std.testing.expectEqual(@as(usize, 0), limits.max_body_bytes);
    try std.testing.expectEqual(@as(usize, 0), limits.max_headers);
}

test "macros update and reset" {
    const allocator = std.testing.allocator;
    var macros: Macros = .{};
    defer macros.deinit(allocator);

    var macro_list: commands.MacroSet.MacroList = .{};
    defer macro_list.deinit(allocator);
    try macro_list.append(allocator, .{ .name = "{client_addr}", .value = "192.0.2.1" });
    try macro_list.append(allocator, .{ .name = "i", .value = "ABC123" });

    const set = commands.MacroSet{ .cmd_code = 'C', .macros = macro_list };
    try macros.update(allocator, &set);

    try std.testing.expectEqualStrings("192.0.2.1", macros.client_addr.?);
    try std.testing.expectEqualStrings("ABC123", macros.queue_id.?);

    macros.resetMessage(allocator);
    try std.testing.expect(macros.queue_id == null);
    try std.testing.expectEqualStrings("192.0.2.1", macros.client_addr.?);
}
