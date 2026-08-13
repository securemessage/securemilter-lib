const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const net = std.net;
const Allocator = mem.Allocator;
const packet = @import("packet.zig");
const log_mod = @import("../log.zig");
const ip = @import("../ip.zig");

/// DNS resolution result.
pub const Result = struct {
    answers: []packet.Answer,
    allocator: Allocator,

    pub fn deinit(self: *Result) void {
        for (self.answers) |ans| {
            self.allocator.free(ans.name);
            self.allocator.free(ans.data);
        }
        self.allocator.free(self.answers);
    }

    /// Get all TXT record data as slices.
    pub fn txtRecords(self: *const Result) TxtIterator {
        return .{ .answers = self.answers, .pos = 0 };
    }
};

pub const TxtIterator = struct {
    answers: []const packet.Answer,
    pos: usize,

    pub fn next(self: *TxtIterator) ?[]const u8 {
        while (self.pos < self.answers.len) {
            const ans = self.answers[self.pos];
            self.pos += 1;
            if (ans.record_type == @intFromEnum(packet.RecordType.TXT)) {
                return ans.data;
            }
        }
        return null;
    }
};

/// Cache and negative-answer types are re-exported from `cache.zig`.
const cache_mod = @import("cache.zig");
pub const NegativeKind = cache_mod.NegativeKind;
pub const Cache = cache_mod.Cache;
pub const isTransientError = cache_mod.isTransientError;

const health_mod = @import("health.zig");
pub const HealthMonitor = health_mod.HealthMonitor;

/// DNS resolver configuration.
pub const ResolverConfig = struct {
    nameservers: []const []const u8 = &.{"127.0.0.1"},
    port: u16 = 53,
    timeout_ms: u32 = 5000,
    retries: u8 = 2,
    cache_size: u32 = 1000,
    negative_ttl: u32 = 60,
};

/// Synchronous DNS resolver with per-worker cache, round-robin, and optional
/// health-monitor-based server selection.
pub const Resolver = struct {
    allocator: Allocator,
    config: ResolverConfig,
    cache: Cache,
    next_id: u16,
    addrs: []net.Address,
    rr_index: usize,
    health_monitor: ?*const HealthMonitor,

    pub fn init(allocator: Allocator, config: ResolverConfig) Resolver {
        return initWithMonitor(allocator, config, null);
    }

    pub fn initWithMonitor(allocator: Allocator, config: ResolverConfig, monitor: ?*const HealthMonitor) Resolver {
        const addrs = allocator.alloc(net.Address, config.nameservers.len) catch
            @panic("DNS resolver: failed to allocate server addresses");

        for (config.nameservers, 0..) |ns, i| {
            addrs[i] = parseNameserver(ns, config.port) catch
                @panic("DNS resolver: invalid nameserver address");
        }

        // Copy nameserver strings because a worker resolver can outlive the RCU
        // configuration snapshot that supplied them.
        const owned_ns = allocator.alloc([]const u8, config.nameservers.len) catch
            @panic("DNS resolver: failed to allocate nameserver list");
        for (config.nameservers, 0..) |ns, i| {
            owned_ns[i] = allocator.dupe(u8, ns) catch
                @panic("DNS resolver: failed to copy nameserver");
        }

        var owned_config = config;
        owned_config.nameservers = owned_ns;

        return .{
            .allocator = allocator,
            .config = owned_config,
            .cache = Cache.init(allocator, config.cache_size, config.negative_ttl),
            .next_id = @truncate(@as(u64, @bitCast(std.time.milliTimestamp()))),
            .addrs = addrs,
            .rr_index = 0,
            .health_monitor = monitor,
        };
    }

    pub fn deinit(self: *Resolver) void {
        self.cache.deinit();
        self.allocator.free(self.addrs);
        for (self.config.nameservers) |ns| self.allocator.free(ns);
        self.allocator.free(self.config.nameservers);
    }

    /// Resolve a domain name for the given record type.
    ///
    /// Checks cache first, then sends a UDP query.
    /// Returns owned Result that caller must deinit.
    pub fn resolve(self: *Resolver, domain: []const u8, rtype: packet.RecordType) !Result {
        // Check cache
        const cache_key = try self.cache.makeCacheKey(domain, rtype);
        defer self.allocator.free(cache_key);

        if (self.cache.get(cache_key)) |entry| {
            if (entry.negative) |kind| {
                log_mod.debug("dns: cache negative hit {s} kind={s}", .{ domain, @tagName(kind) });
                return kind.toError();
            }
            log_mod.debug("dns: cache hit {s}", .{domain});
            const duped = try self.cache.dupeAnswers(entry.answers);
            return .{ .answers = duped, .allocator = self.allocator };
        }

        log_mod.debug("dns: cache miss {s}", .{domain});

        // Build and send query
        const query_id = self.nextId();
        const query_pkt = try packet.buildQuery(self.allocator, domain, rtype, query_id);
        defer self.allocator.free(query_pkt);

        const query_start = std.time.nanoTimestamp();
        const response_data = self.sendAndReceive(query_pkt) catch |err| {
            const query_elapsed = @divFloor(std.time.nanoTimestamp() - query_start, 1_000_000);
            // A monitor skip produced no wire traffic: nothing was learned
            // about the domain, so there is nothing to cache. Negative-caching
            // it once turned a seconds-long probe flap into a per-domain
            // temperror for the whole negative TTL.
            if (err == error.DnsNoHealthyServers) {
                log_mod.warn("dns: {s} not queried, all nameservers marked down (monitor)", .{domain});
                return err;
            }
            // Warn, not debug: every path through here defers real mail, and a
            // failure class that only a debug build can see is invisible in
            // exactly the environment that needs it.
            log_mod.warn("dns: query {s} failed err={} elapsed={d}ms", .{ domain, err, query_elapsed });
            // Remember a timeout so a dead nameserver is not re-hammered for
            // every message, but remember it *as* a timeout: replaying it as a
            // generic failure would let one dropped packet look like an
            // authoritative answer for the whole negative TTL.
            if (err == error.DnsTimeout) {
                self.cache.putNegative(domain, rtype, .timeout) catch {};
            }
            return err;
        };
        defer self.allocator.free(response_data);

        var response = try packet.parseResponse(self.allocator, response_data);
        defer response.deinit(self.allocator);

        if (response.id != query_id) return error.IdMismatch;

        // A TC=1 answer is incomplete, and RFC 7766 §5 makes retrying it over TCP
        // mandatory rather than optional. EDNS0 raises the ceiling but does not
        // remove it, and a resolver may still answer TC=1 with an *empty* answer
        // section -- which a caller cannot tell apart from NXDOMAIN. Ignoring
        // `truncated` here would score real senders with oversized records
        // (e.g. Microsoft 365's DKIM keys) as if the record did not exist.
        //
        // A failed retry deliberately falls through to whatever the UDP answer
        // held, rather than erroring. A partial answer is still better evidence
        // than none, and the alternative is a temperror on every oversized RRset
        // anywhere 53/tcp happens to be filtered.
        if (response.truncated) {
            log_mod.debug("dns: {s} truncated over udp, retrying over tcp", .{domain});
            if (self.sendAndReceiveTcp(query_pkt)) |tcp_data| {
                defer self.allocator.free(tcp_data);
                if (packet.parseResponse(self.allocator, tcp_data)) |parsed| {
                    var tcp_response = parsed;
                    if (tcp_response.id == query_id) {
                        response.deinit(self.allocator);
                        response = tcp_response;
                    } else {
                        // Not an answer to our question; keep the UDP one.
                        tcp_response.deinit(self.allocator);
                    }
                } else |perr| {
                    log_mod.debug("dns: tcp reply for {s} unparseable err={}", .{ domain, perr });
                }
            } else |err| {
                log_mod.debug("dns: tcp retry for {s} failed err={}", .{ domain, err });
            }
        }

        if (response.rcode != .no_error) {
            // RCODE 3 is the only one that says anything permanent about the
            // name. Everything else is the server declining to answer, and is
            // classified transient so a caller cannot mistake it for a verdict.
            const kind: NegativeKind = if (response.rcode == .name_error)
                .name_error
            else
                .server_failure;
            if (kind == .server_failure) {
                // sendAndReceive already walked every configured server, so
                // this answer is the *consensus*, not one server's mood.
                log_mod.warn("dns: {s} refused, rcode={s} from all nameservers", .{ domain, @tagName(response.rcode) });
            }
            self.cache.putNegative(domain, rtype, kind) catch {};
            return kind.toError();
        }

        // Cache the positive result
        self.cache.put(domain, rtype, response.answers.items) catch {};

        // Return owned copy
        const duped = try self.cache.dupeAnswers(response.answers.items);
        return .{ .answers = duped, .allocator = self.allocator };
    }

    /// Convenience: resolve TXT records and return first match.
    pub fn resolveTxt(self: *Resolver, domain: []const u8) !?[]const u8 {
        var result = try self.resolve(domain, .TXT);
        defer result.deinit();

        var iter = result.txtRecords();
        if (iter.next()) |txt| {
            return try self.allocator.dupe(u8, txt);
        }
        return null;
    }

    fn sendAndReceive(self: *Resolver, query: []const u8) ![]u8 {
        const num_servers = self.addrs.len;

        // Fast path: if health monitor reports ALL servers down, fail immediately.
        // Distinct from a wire timeout: no query was sent, so nothing was
        // learned about the domain, and the caller must not cache this as the
        // domain's answer.
        if (self.health_monitor) |monitor| {
            if (monitor.healthyCount() == 0) return error.DnsNoHealthyServers;
        }

        // Try each server starting from round-robin index, skipping
        // servers the health monitor has marked unhealthy.
        //
        // SERVFAIL and REFUSED do not end the walk: one server's refusal says
        // nothing about what the next would answer (a validating resolver's
        // transient DNSSEC failure is the observed case). The first refusal is
        // kept as the answer of last resort, so a single-server setup behaves
        // exactly as before.
        var refusal: ?[]u8 = null;
        defer if (refusal) |f| self.allocator.free(f);

        var tried: usize = 0;
        while (tried < num_servers) : (tried += 1) {
            const idx = (self.rr_index + tried) % num_servers;

            // Skip servers marked unhealthy by the proactive monitor (zero delay)
            if (self.health_monitor) |monitor| {
                if (!monitor.isHealthy(idx)) continue;
            }

            if (try self.udpServerQuery(self.addrs[idx], query)) |answer| {
                const rcode = answer[3] & 0x0F;
                if (rcode == 2 or rcode == 5) { // SERVFAIL, REFUSED
                    log_mod.debug("dns: {s} returned rcode={d}, trying next server", .{ self.config.nameservers[idx], rcode });
                    if (refusal) |old| self.allocator.free(old);
                    refusal = answer;
                    continue;
                }
                // Success — advance round-robin
                self.rr_index = (idx + 1) % num_servers;
                return answer;
            }
        }

        if (refusal) |f| {
            const kept = f;
            refusal = null; // ownership moves to the caller
            return kept;
        }
        return error.DnsTimeout;
    }

    /// One server's worth of UDP attempts, or null when it did not answer.
    ///
    /// The socket's family must be the SERVER's, and the configured list may
    /// mix families, so the socket is per server rather than per query: a fixed
    /// AF.INET socket would fail at sendto with EADDRNOTAVAIL against a v6
    /// nameserver, in 0ms, surfacing as "DNS lookup failed transiently" against
    /// a resolver that answers correctly. The TCP path below already does this
    /// right (`addr.any.family`); this is the UDP side of the same rule.
    fn udpServerQuery(self: *Resolver, addr: net.Address, query: []const u8) !?[]u8 {
        const sock = try posix.socket(
            @intCast(addr.any.family),
            posix.SOCK.DGRAM | posix.SOCK.CLOEXEC,
            0,
        );
        defer posix.close(sock);

        const timeout_sec = self.config.timeout_ms / 1000;
        const timeout_usec = (self.config.timeout_ms % 1000) * 1000;
        const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = @intCast(timeout_usec) };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&tv));

        var attempts: u8 = 0;
        while (attempts <= self.config.retries) : (attempts += 1) {
            _ = posix.sendto(sock, query, 0, &addr.any, addr.getOsSockLen()) catch continue;

            var buf: [4096]u8 = undefined;
            const n = posix.recvfrom(sock, &buf, 0, null, null) catch continue;

            if (n < 12) continue;

            return try self.allocator.dupe(u8, buf[0..n]);
        }
        return null;
    }

    /// Re-issue a query over TCP, for an answer that did not fit in a datagram.
    ///
    /// Walks the same servers in the same round-robin order as the UDP path and
    /// skips any the health monitor has already written off, so a nameserver that
    /// is down does not get retried here after being skipped there.
    fn sendAndReceiveTcp(self: *Resolver, query: []const u8) ![]u8 {
        const num_servers = self.addrs.len;

        var tried: usize = 0;
        while (tried < num_servers) : (tried += 1) {
            const idx = (self.rr_index + tried) % num_servers;

            if (self.health_monitor) |monitor| {
                if (!monitor.isHealthy(idx)) continue;
            }

            return self.tcpQuery(self.addrs[idx], query) catch continue;
        }

        return error.DnsTimeout;
    }

    /// One TCP query, bounded at every step, with nothing polling.
    ///
    /// TCP_KEEPINIT bounds connection establishment. A plain blocking connect() is
    /// governed by the kernel's SYN retry schedule instead -- 75 seconds by
    /// default on FreeBSD -- and a milter worker stalled that long on one
    /// unreachable nameserver is an outage, not a slow lookup. SO_RCVTIMEO and
    /// SO_SNDTIMEO then bound the data phase, exactly as the UDP path does.
    fn tcpQuery(self: *Resolver, addr: net.Address, query: []const u8) ![]u8 {
        // The two-byte length prefix cannot describe anything longer.
        if (query.len > 65535) return error.QueryTooLong;

        const sock = try posix.socket(
            @intCast(addr.any.family),
            posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
            0,
        );
        defer posix.close(sock);

        // Rounded up, and never zero: TCP_KEEPINIT is in seconds, and zero means
        // "use the system default", which is the unbounded behaviour being
        // avoided here. Best-effort -- an older kernel that rejects the option
        // should still get a working lookup, just not a bounded connect.
        const connect_secs: u32 = @max(1, (self.config.timeout_ms + 999) / 1000);
        // 128 is TCP_KEEPINIT from <netinet/tcp.h>; Zig does not expose it.
        posix.setsockopt(sock, posix.IPPROTO.TCP, 128, mem.asBytes(&connect_secs)) catch {};

        const timeout_sec = self.config.timeout_ms / 1000;
        const timeout_usec = (self.config.timeout_ms % 1000) * 1000;
        const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = @intCast(timeout_usec) };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&tv));
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&tv));

        try posix.connect(sock, &addr.any, addr.getOsSockLen());

        // RFC 1035 §4.2.2: over TCP the message is preceded by its own two-byte
        // length, because a stream has no datagram boundaries to delimit it.
        var len_buf: [2]u8 = undefined;
        mem.writeInt(u16, &len_buf, @intCast(query.len), .big);
        try writeAll(sock, &len_buf);
        try writeAll(sock, query);

        try readExact(sock, &len_buf);
        const msg_len = mem.readInt(u16, &len_buf, .big);
        if (msg_len < 12) return error.PacketTooShort;

        const msg = try self.allocator.alloc(u8, msg_len);
        errdefer self.allocator.free(msg);
        try readExact(sock, msg);
        return msg;
    }

    fn nextId(self: *Resolver) u16 {
        const id = self.next_id;
        self.next_id +%= 1;
        return id;
    }
};

/// A stream socket may accept fewer bytes than offered, so a single send() is not
/// a write.
fn writeAll(sock: posix.socket_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = try posix.send(sock, bytes[off..], 0);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
}

/// Fill `out` completely.
///
/// A short read on a stream socket is not an error -- it means the rest has not
/// arrived yet. A zero-length read *is* end of file, and treating that as "try
/// again" would spin forever against a peer that has hung up.
fn readExact(sock: posix.socket_t, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try posix.recv(sock, out[off..], 0);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
}

fn parseNameserver(host: []const u8, port: u16) !net.Address {
    if (net.Ip4Address.parse(host, port)) |ip4| {
        return .{ .in = ip4 };
    } else |_| {}
    // L-7: strict, never repaired -- a mistyped nameserver must fail at parse,
    // not resolve against an address the operator did not write.
    if (ip.parseIp6Address(host, port)) |addr| {
        return addr;
    } else |_| {}
    return error.InvalidNameserver;
}

test "UDP query to an IPv6 nameserver" {
    // A resolver that opened a fixed AF.INET socket per query would fail at
    // sendto with EADDRNOTAVAIL against a v6-only nameserver. The responder
    // below binds ::1 ONLY, so a v4 socket cannot reach it in principle -- the
    // test cannot pass vacuously.
    const srv = try posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(srv);
    const bind_addr = try net.Address.parseIp6("::1", 0);
    try posix.bind(srv, &bind_addr.any, bind_addr.getOsSockLen());
    var bound = bind_addr;
    var bound_len: posix.socklen_t = bound.getOsSockLen();
    try posix.getsockname(srv, &bound.any, &bound_len);
    const port = bound.getPort();

    // Answer one query with a well-formed empty NOERROR response: the query
    // id and question echoed, QR|RD|RA set, no answer records. resolve() then
    // succeeds with zero answers, which is distinguishable from the
    // regression's signature (DnsTimeout without a packet ever leaving).
    // RCVTIMEO bounds the thread so a regressed client strands nothing.
    const Responder = struct {
        fn run(sock: posix.socket_t) void {
            const tv = posix.timeval{ .sec = 5, .usec = 0 };
            posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&tv)) catch return;
            var qbuf: [512]u8 = undefined;
            var src: posix.sockaddr.storage = undefined;
            var src_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const n = posix.recvfrom(sock, &qbuf, 0, @ptrCast(&src), &src_len) catch return;
            if (n < 12) return;
            var rbuf: [600]u8 = undefined;
            rbuf[0] = qbuf[0];
            rbuf[1] = qbuf[1];
            rbuf[2] = 0x85; // QR | RD
            rbuf[3] = 0x80; // RA, RCODE=NOERROR
            rbuf[4] = 0;
            rbuf[5] = 1; // QDCOUNT
            rbuf[6] = 0;
            rbuf[7] = 0; // ANCOUNT
            rbuf[8] = 0;
            rbuf[9] = 0; // NSCOUNT
            rbuf[10] = 0;
            rbuf[11] = 0; // ARCOUNT
            const question = qbuf[12..n];
            @memcpy(rbuf[12..][0..question.len], question);
            _ = posix.sendto(sock, rbuf[0 .. 12 + question.len], 0, @ptrCast(&src), src_len) catch return;
        }
    };
    const th = try std.Thread.spawn(.{}, Responder.run, .{srv});
    th.detach();

    var r = Resolver.init(std.testing.allocator, .{
        .nameservers = &.{"::1"},
        .port = port,
        .timeout_ms = 2000,
        .retries = 0,
    });
    defer r.deinit();

    var result = r.resolve("example.test", .A) catch |err| {
        if (err == error.DnsTimeout) return error.TestUnexpectedResult;
        return err;
    };
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.answers.len);
}

test "resolver init and deinit" {
    var r = Resolver.init(std.testing.allocator, .{});
    defer r.deinit();
    try std.testing.expect(r.next_id != 0);
    try std.testing.expectEqual(@as(usize, 1), r.addrs.len);
}

// A minimal scripted UDP responder: answers each query with the rcode for
// its ordinal (last entry repeats), counting what arrived so a test can tell
// "the walk moved on" from "the wire was never touched".
const TestResponder = struct {
    sock: posix.socket_t,
    rcodes: []const u8,
    queries: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn run(self: *TestResponder) void {
        const tv = posix.timeval{ .sec = 5, .usec = 0 };
        posix.setsockopt(self.sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&tv)) catch return;
        var qbuf: [512]u8 = undefined;
        while (true) {
            var src: posix.sockaddr.storage = undefined;
            var src_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const n = posix.recvfrom(self.sock, &qbuf, 0, @ptrCast(&src), &src_len) catch return;
            if (n < 12) continue;
            const i = self.queries.fetchAdd(1, .seq_cst);
            var rbuf: [600]u8 = undefined;
            rbuf[0] = qbuf[0];
            rbuf[1] = qbuf[1];
            rbuf[2] = 0x85; // QR | RD
            rbuf[3] = self.rcodes[@min(i, self.rcodes.len - 1)];
            rbuf[4] = 0;
            rbuf[5] = 1; // QDCOUNT
            @memset(rbuf[6..12], 0);
            const question = qbuf[12..n];
            @memcpy(rbuf[12..][0..question.len], question);
            _ = posix.sendto(self.sock, rbuf[0 .. 12 + question.len], 0, @ptrCast(&src), src_len) catch return;
        }
    }
};

fn bindV4Responder() !struct { sock: posix.socket_t, port: u16 } {
    const srv = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(srv);
    const bind_addr = try net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(srv, &bind_addr.any, bind_addr.getOsSockLen());
    var bound = bind_addr;
    var bound_len: posix.socklen_t = bound.getOsSockLen();
    try posix.getsockname(srv, &bound.any, &bound_len);
    return .{ .sock = srv, .port = bound.getPort() };
}

fn spawnResponder(sock: posix.socket_t, rcodes: []const u8) !*TestResponder {
    const responder = try std.testing.allocator.create(TestResponder);
    responder.* = .{ .sock = sock, .rcodes = rcodes };
    const th = try std.Thread.spawn(.{}, TestResponder.run, .{responder});
    th.detach();
    return responder;
}

test "SERVFAIL from the first server falls over to the next" {
    // A validating resolver's transient DNSSEC failure answers SERVFAIL fast;
    // accepting it as final tempfailed real mail while a second configured
    // server stood by. (Same address twice: the config format shares one port
    // across servers, so the two entries are two walks over one responder.)
    const srv = try bindV4Responder();
    defer posix.close(srv.sock);
    const responder = try spawnResponder(srv.sock, &.{ 2, 0 });
    defer std.testing.allocator.destroy(responder);

    var r = Resolver.init(std.testing.allocator, .{
        .nameservers = &.{ "127.0.0.1", "127.0.0.1" },
        .port = srv.port,
        .timeout_ms = 2000,
        .retries = 0,
    });
    defer r.deinit();

    var result = try r.resolve("failover.test", .TXT);
    defer result.deinit();
    try std.testing.expectEqual(@as(u32, 2), responder.queries.load(.seq_cst));
}

test "a lone server's SERVFAIL is still honoured, and cached as transient" {
    const srv = try bindV4Responder();
    defer posix.close(srv.sock);
    const responder = try spawnResponder(srv.sock, &.{2});
    defer std.testing.allocator.destroy(responder);

    var r = Resolver.init(std.testing.allocator, .{
        .nameservers = &.{"127.0.0.1"},
        .port = srv.port,
        .timeout_ms = 2000,
        .retries = 0,
    });
    defer r.deinit();

    try std.testing.expectError(error.DnsServerFailure, r.resolve("refused.test", .TXT));
    // Cached: the repeat ask must not reach the wire.
    try std.testing.expectError(error.DnsServerFailure, r.resolve("refused.test", .TXT));
    try std.testing.expectEqual(@as(u32, 1), responder.queries.load(.seq_cst));
}

test "a monitor skip is not cached against the domain" {
    // The skip path never sends a query, so nothing was learned about the
    // domain; caching it once turned a probe flap into a per-domain outage
    // for the whole negative TTL. The second ask must reach the wire.
    const srv = try bindV4Responder();
    defer posix.close(srv.sock);
    const responder = try spawnResponder(srv.sock, &.{0});
    defer std.testing.allocator.destroy(responder);

    const monitor = try HealthMonitor.init(std.testing.allocator, &.{"127.0.0.1"}, srv.port, 5, 200);
    defer monitor.deinit();

    var r = Resolver.initWithMonitor(std.testing.allocator, .{
        .nameservers = &.{"127.0.0.1"},
        .port = srv.port,
        .timeout_ms = 2000,
        .retries = 0,
    }, monitor);
    defer r.deinit();

    monitor.server_healthy[0].store(0, .release);
    try std.testing.expectError(error.DnsNoHealthyServers, r.resolve("skipped.test", .TXT));

    monitor.server_healthy[0].store(1, .release);
    var result = try r.resolve("skipped.test", .TXT);
    defer result.deinit();
    try std.testing.expectEqual(@as(u32, 1), responder.queries.load(.seq_cst));
}

test "resolver multi-server init" {
    const servers: []const []const u8 = &.{ "8.8.8.8", "1.1.1.1", "9.9.9.9" };
    var r = Resolver.init(std.testing.allocator, .{ .nameservers = servers });
    defer r.deinit();
    try std.testing.expectEqual(@as(usize, 3), r.addrs.len);
    try std.testing.expectEqual(@as(usize, 0), r.rr_index);
}

test "resolver outlives the nameserver strings it was configured from" {
    // The lifetime this asserts is securearc's: its nameserver list belongs to
    // an RCU configuration snapshot, and since X-3 the resolver is per worker
    // thread rather than per message, so it is still alive when a retired
    // snapshot is reclaimed. The worker announces quiescence -- which is what
    // permits that reclamation -- BEFORE calling the hook that drops the
    // resolver, so this window is real and not hypothetical.
    //
    // Freeing the caller's strings and then using the resolver is exactly what
    // the daemon does; under the testing allocator a borrowed slice here is a
    // use-after-free rather than a silent pass.
    const alloc = std.testing.allocator;

    var servers = try alloc.alloc([]const u8, 2);
    servers[0] = try alloc.dupe(u8, "192.0.2.1");
    servers[1] = try alloc.dupe(u8, "192.0.2.2");

    var r = Resolver.init(alloc, .{ .nameservers = servers });
    defer r.deinit();

    // The configuration snapshot goes away, as `Reloadable.deinit` does to it.
    for (servers) |s| alloc.free(s);
    alloc.free(servers);

    // The resolver must still hold its own readable copy, not the freed one.
    try std.testing.expectEqual(@as(usize, 2), r.config.nameservers.len);
    try std.testing.expectEqualStrings("192.0.2.1", r.config.nameservers[0]);
    try std.testing.expectEqualStrings("192.0.2.2", r.config.nameservers[1]);
    try std.testing.expectEqual(@as(usize, 2), r.addrs.len);
}
