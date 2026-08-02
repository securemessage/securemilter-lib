const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const net = std.net;
const Allocator = mem.Allocator;
const packet = @import("packet.zig");
const log_mod = @import("../log.zig");

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

/// Why a name produced no usable answer.
///
/// SPF cannot reconstruct this distinction after the fact and needs it:
/// RFC 7208 §4.6.4 counts an authoritative "no such name" as a *void lookup*
/// and lets evaluation continue, whereas a SERVFAIL or a timeout is transient
/// and must become `temperror`. Collapsing the two into one error made a
/// momentary nameserver hiccup look like proof that a mechanism did not match,
/// which is how a legitimate sender ends up rejected by a `-all`.
pub const NegativeKind = enum {
    /// RCODE 3. The name itself does not exist.
    name_error,
    /// RCODE 2, or any other server-side refusal.
    server_failure,
    /// No usable reply arrived within the timeout.
    timeout,

    pub fn toError(self: NegativeKind) anyerror {
        return switch (self) {
            .name_error => error.DnsNameError,
            .server_failure => error.DnsServerFailure,
            .timeout => error.DnsTimeout,
        };
    }

    /// True when the name is known not to exist, as opposed to the answer being
    /// merely unavailable right now.
    pub fn isAuthoritative(self: NegativeKind) bool {
        return self == .name_error;
    }
};

/// Classify a resolver error for callers that must distinguish "there is no such
/// name" from "ask again later".
///
/// The default is transient, which is the safe direction: reporting `temperror`
/// for a permanent condition costs a retry, while reporting a verdict for a
/// transient one can reject mail that would otherwise have been delivered.
///
/// The exceptions are the conditions where retrying is provably useless because
/// the name never reached the wire. A name with an empty or over-long label cannot
/// be encoded as a question at all, so no nameserver will ever answer it, and RFC
/// 7208 §4.3 groups a malformed domain with NXDOMAIN for exactly that reason -- to
/// a caller the two are the same fact. Classifying these as transient turned a
/// malformed record into `temperror` and asked the sender to try again forever.
pub fn isTransientError(err: anyerror) bool {
    return switch (err) {
        error.DnsNameError => false,
        error.EmptyLabel,
        error.LabelTooLong,
        error.NameTooLong,
        error.TooManyLabels,
        => false,
        else => true,
    };
}

/// TTL-aware DNS cache entry.
const CacheEntry = struct {
    answers: []packet.Answer,
    expires_at: i64,
    /// Null for a positive entry; otherwise why the lookup produced nothing.
    negative: ?NegativeKind,
};

/// Per-worker DNS cache with TTL expiry, max size, negative caching, and FIFO eviction.
pub const Cache = struct {
    entries: std.StringHashMap(CacheEntry),
    insertion_order: std.ArrayListUnmanaged([]u8),
    allocator: Allocator,
    max_entries: u32,
    negative_ttl: u32,

    pub fn init(allocator: Allocator, max_entries: u32, negative_ttl: u32) Cache {
        return .{
            .entries = std.StringHashMap(CacheEntry).init(allocator),
            .insertion_order = .{},
            .allocator = allocator,
            .max_entries = if (max_entries == 0) 1000 else max_entries,
            .negative_ttl = if (negative_ttl == 0) 60 else negative_ttl,
        };
    }

    pub fn deinit(self: *Cache) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.freeEntry(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
        for (self.insertion_order.items) |key| {
            _ = key; // Keys already freed above via entries iterator
        }
        self.insertion_order.deinit(self.allocator);
    }

    pub fn get(self: *Cache, key: []const u8) ?*const CacheEntry {
        const entry = self.entries.getPtr(key) orelse return null;
        const now = std.time.timestamp();
        if (now >= entry.expires_at) {
            return null; // Expired
        }
        return entry;
    }

    /// Cache a successful DNS response.
    pub fn put(self: *Cache, domain: []const u8, rtype: packet.RecordType, answers: []const packet.Answer) !void {
        if (answers.len == 0) return;

        var min_ttl: u32 = answers[0].ttl;
        for (answers[1..]) |ans| {
            if (ans.ttl < min_ttl) min_ttl = ans.ttl;
        }
        if (min_ttl < 30) min_ttl = 30;
        if (min_ttl > 86400) min_ttl = 86400;

        const key = try self.makeCacheKey(domain, rtype);
        errdefer self.allocator.free(key);

        const duped = try self.dupeAnswers(answers);

        try self.evictIfFull();
        try self.insertEntry(key, .{
            .answers = duped,
            .expires_at = std.time.timestamp() + @as(i64, min_ttl),
            .negative = null,
        });
    }

    /// Cache a negative result, remembering *why* it was negative.
    ///
    /// The kind has to be stored, not just the fact: a cached timeout that came
    /// back as an authoritative-looking failure would let one dropped packet
    /// suppress a domain for the whole negative TTL.
    pub fn putNegative(
        self: *Cache,
        domain: []const u8,
        rtype: packet.RecordType,
        kind: NegativeKind,
    ) !void {
        const key = try self.makeCacheKey(domain, rtype);
        errdefer self.allocator.free(key);

        try self.evictIfFull();
        try self.insertEntry(key, .{
            .answers = &.{},
            .expires_at = std.time.timestamp() + @as(i64, self.negative_ttl),
            .negative = kind,
        });
    }

    /// Build the key for a name/type pair, **case-folded** (audit L-3).
    ///
    /// Names are case-insensitive (RFC 1035 §2.3.3), so keyed verbatim `Example.COM`
    /// and `example.com` were two entries. The half that is not merely wasteful: a
    /// NEGATIVE entry could be stepped around by re-asking in another case, so a name
    /// that just NXDOMAINed was queried again instead of being suppressed for its TTL.
    /// Folding here covers every path, since all of them build their key through this.
    ///
    /// ASCII-only per RFC 4343 -- folding a non-ASCII byte would merge names the
    /// protocol keeps distinct.
    pub fn makeCacheKey(self: *Cache, domain: []const u8, rtype: packet.RecordType) ![]u8 {
        const type_int = @intFromEnum(rtype);
        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ domain, type_int });
        // Bounded to the name: the ":<type>" suffix this appended is digits already.
        for (key[0..domain.len]) |*ch| ch.* = std.ascii.toLower(ch.*);
        return key;
    }

    pub fn dupeAnswers(self: *Cache, answers: []const packet.Answer) ![]packet.Answer {
        const duped = try self.allocator.alloc(packet.Answer, answers.len);
        for (answers, 0..) |ans, i| {
            duped[i] = .{
                .name = try self.allocator.dupe(u8, ans.name),
                .record_type = ans.record_type,
                .ttl = ans.ttl,
                .data = try self.allocator.dupe(u8, ans.data),
            };
        }
        return duped;
    }

    fn insertEntry(self: *Cache, key: []u8, entry: CacheEntry) !void {
        const result = try self.entries.getOrPut(key);
        if (result.found_existing) {
            if (result.value_ptr.negative == null) self.freeEntry(result.value_ptr.*);
            self.allocator.free(key);
        } else {
            try self.insertion_order.append(self.allocator, key);
        }
        result.value_ptr.* = entry;
    }

    fn evictIfFull(self: *Cache) !void {
        if (self.entries.count() < self.max_entries) return;

        // First pass: evict expired entries
        const now = std.time.timestamp();
        var i: usize = 0;
        while (i < self.insertion_order.items.len) {
            const key = self.insertion_order.items[i];
            if (self.entries.get(key)) |entry| {
                if (now >= entry.expires_at) {
                    self.removeByIndex(i, key);
                    if (self.entries.count() < self.max_entries) return;
                    continue; // Don't increment i, array shifted
                }
            }
            i += 1;
        }

        // Still full: evict oldest (FIFO)
        if (self.insertion_order.items.len > 0) {
            const oldest_key = self.insertion_order.items[0];
            self.removeByIndex(0, oldest_key);
        }
    }

    fn removeByIndex(self: *Cache, idx: usize, key: []u8) void {
        if (self.entries.fetchRemove(key)) |kv| {
            if (kv.value.negative == null) self.freeEntry(kv.value);
            self.allocator.free(kv.key);
        }
        _ = self.insertion_order.orderedRemove(idx);
    }

    fn freeEntry(self: *Cache, entry: CacheEntry) void {
        for (entry.answers) |ans| {
            self.allocator.free(ans.name);
            self.allocator.free(ans.data);
        }
        self.allocator.free(entry.answers);
    }
};

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

/// Synchronous DNS resolver with per-worker caching and multi-server
/// round-robin with proactive health monitoring.
///
/// Uses a shared HealthMonitor (background probe thread) to skip
/// unhealthy servers with zero delay. If no HealthMonitor is set,
/// falls back to trying all servers with timeout-based failover.
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

        // Own the nameserver strings instead of borrowing the caller's.
        //
        // A resolver now outlives what configured it: audit X-3 made it one per
        // worker thread, kept across messages, while securearc's nameserver list
        // belongs to an RCU configuration snapshot whose `deinit` frees exactly
        // these strings. The ordering makes that concrete rather than
        // theoretical -- a worker announces quiescence at the top of its loop,
        // which is what licences the main thread to free a retired snapshot, and
        // only THEN calls the reload hook that drops this resolver. In between,
        // a live resolver holds a slice into freed memory.
        //
        // Nothing dereferences it today: after init only `timeout_ms` and
        // `retries` are read, and queries go to the parsed `addrs` above. But
        // that is an invariant no one wrote down and the compiler cannot check,
        // and it turns into a use-after-free the first time someone re-reads the
        // list -- to re-resolve a nameserver hostname, say, or to log which
        // server answered. Copying a handful of short strings once per worker
        // costs nothing measurable and makes the struct self-contained.
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
            log_mod.debug("dns: query {s} failed err={} elapsed={d}ms", .{ domain, err, query_elapsed });
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
        // section -- which a caller cannot tell apart from NXDOMAIN. Before this
        // existed, `truncated` was parsed, asserted in the tests, and then read
        // by nobody, so Yahoo scored spf=none and every Microsoft 365 sender
        // scored dkim=permerror.
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
        if (self.health_monitor) |monitor| {
            if (monitor.healthyCount() == 0) return error.DnsTimeout;
        }

        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
        defer posix.close(sock);

        const timeout_sec = self.config.timeout_ms / 1000;
        const timeout_usec = (self.config.timeout_ms % 1000) * 1000;
        const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = @intCast(timeout_usec) };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&tv));

        // Try each server starting from round-robin index, skipping
        // servers the health monitor has marked unhealthy.
        var tried: usize = 0;
        while (tried < num_servers) : (tried += 1) {
            const idx = (self.rr_index + tried) % num_servers;

            // Skip servers marked unhealthy by the proactive monitor (zero delay)
            if (self.health_monitor) |monitor| {
                if (!monitor.isHealthy(idx)) continue;
            }

            const addr = self.addrs[idx];

            var attempts: u8 = 0;
            while (attempts <= self.config.retries) : (attempts += 1) {
                _ = posix.sendto(sock, query, 0, &addr.any, addr.getOsSockLen()) catch continue;

                var buf: [4096]u8 = undefined;
                const n = posix.recvfrom(sock, &buf, 0, null, null) catch |err| {
                    if (err == error.WouldBlock) continue;
                    continue;
                };

                if (n < 12) continue;

                // Success — advance round-robin
                self.rr_index = (idx + 1) % num_servers;
                return try self.allocator.dupe(u8, buf[0..n]);
            }
        }

        return error.DnsTimeout;
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
    if (net.Ip6Address.parse(host, port)) |ip6| {
        return .{ .in6 = ip6 };
    } else |_| {}
    return error.InvalidNameserver;
}

test "cache put and get" {
    var cache = Cache.init(std.testing.allocator, 1000, 60);
    defer cache.deinit();

    const answers = &[_]packet.Answer{.{
        .name = "example.com",
        .record_type = @intFromEnum(packet.RecordType.TXT),
        .ttl = 300,
        .data = "v=spf1 -all",
    }};

    try cache.put("example.com", .TXT, answers);

    const key = try cache.makeCacheKey("example.com", .TXT);
    defer std.testing.allocator.free(key);
    const cached = cache.get(key);
    try std.testing.expect(cached != null);
    try std.testing.expectEqual(@as(usize, 1), cached.?.answers.len);
    try std.testing.expectEqualStrings("v=spf1 -all", cached.?.answers[0].data);
    try std.testing.expect(cached.?.negative == null);
}

test "cache miss returns null" {
    var cache = Cache.init(std.testing.allocator, 1000, 60);
    defer cache.deinit();

    const key = try cache.makeCacheKey("nonexistent.com", .TXT);
    defer std.testing.allocator.free(key);
    try std.testing.expect(cache.get(key) == null);
}

test "cache negative entry" {
    var cache = Cache.init(std.testing.allocator, 1000, 60);
    defer cache.deinit();

    try cache.putNegative("nxdomain.com", .TXT, .name_error);

    const key = try cache.makeCacheKey("nxdomain.com", .TXT);
    defer std.testing.allocator.free(key);
    const cached = cache.get(key);
    try std.testing.expect(cached != null);
    try std.testing.expectEqual(NegativeKind.name_error, cached.?.negative.?);
}

// L-3. Two assertions, because only the second one is more than housekeeping:
// a negative entry that can be stepped around by changing capitalisation is not
// suppressing anything.
test "a name cached in one case is found in another" {
    var cache = Cache.init(std.testing.allocator, 1000, 60);
    defer cache.deinit();

    const answers = &[_]packet.Answer{.{
        .name = "example.com",
        .record_type = @intFromEnum(packet.RecordType.TXT),
        .ttl = 300,
        .data = "v=spf1 -all",
    }};
    try cache.put("Example.COM", .TXT, answers);

    // Stored under one spelling, asked for under two others.
    for ([_][]const u8{ "example.com", "EXAMPLE.com", "Example.COM" }) |spelling| {
        const key = try cache.makeCacheKey(spelling, .TXT);
        defer std.testing.allocator.free(key);
        const hit = cache.get(key);
        try std.testing.expect(hit != null);
        try std.testing.expectEqualStrings("v=spf1 -all", hit.?.answers[0].data);
    }

    // And it is ONE entry, not three: the point is a shared cache slot, not
    // merely that each spelling happens to resolve.
    try std.testing.expectEqual(@as(u32, 1), cache.entries.count());
}

test "a negative entry cannot be bypassed by re-asking in another case" {
    var cache = Cache.init(std.testing.allocator, 1000, 60);
    defer cache.deinit();

    try cache.putNegative("nxdomain.example", .TXT, .name_error);

    const key = try cache.makeCacheKey("NXDomain.Example", .TXT);
    defer std.testing.allocator.free(key);
    const hit = cache.get(key);
    try std.testing.expect(hit != null);
    try std.testing.expectEqual(NegativeKind.name_error, hit.?.negative.?);
}

// RFC 4343 confines DNS case-insensitivity to US-ASCII. Folding a non-ASCII byte
// would merge names the protocol keeps distinct, so the fold must stop at 0x7f.
// Pinned because `toLower` is the kind of call someone later swaps for a
// Unicode-aware one without realising it changes what counts as the same name.
test "makeCacheKey does not case-fold non-ASCII bytes" {
    var cache = Cache.init(std.testing.allocator, 1000, 60);
    defer cache.deinit();

    const a = try cache.makeCacheKey("\xc3\x9fexample.com", .TXT);
    defer std.testing.allocator.free(a);
    const b = try cache.makeCacheKey("\xc3\xbfexample.com", .TXT);
    defer std.testing.allocator.free(b);

    try std.testing.expect(!mem.eql(u8, a, b));
    try std.testing.expectEqualStrings("\xc3\x9fexample.com:16", a);
}

test "a cached timeout does not masquerade as a name error" {
    // One dropped packet must not suppress a domain for the whole negative TTL
    // by looking like an authoritative "no such name". SPF reads that difference
    // to decide between temperror and a verdict.
    var cache = Cache.init(std.testing.allocator, 1000, 60);
    defer cache.deinit();

    try cache.putNegative("slow.example", .A, .timeout);
    const key = try cache.makeCacheKey("slow.example", .A);
    defer std.testing.allocator.free(key);

    const kind = cache.get(key).?.negative.?;
    try std.testing.expectEqual(NegativeKind.timeout, kind);
    try std.testing.expectEqual(error.DnsTimeout, kind.toError());
    try std.testing.expect(!kind.isAuthoritative());
    try std.testing.expect(isTransientError(kind.toError()));

    // And the authoritative case is the only one that is not transient.
    try std.testing.expect(NegativeKind.name_error.isAuthoritative());
    try std.testing.expect(!isTransientError(error.DnsNameError));
    try std.testing.expect(isTransientError(error.DnsServerFailure));
}

test "cache eviction when full" {
    var cache = Cache.init(std.testing.allocator, 3, 60);
    defer cache.deinit();

    const answer = &[_]packet.Answer{.{
        .name = "a.com",
        .record_type = @intFromEnum(packet.RecordType.TXT),
        .ttl = 3600,
        .data = "data",
    }};

    try cache.put("a.com", .TXT, answer);
    try cache.put("b.com", .TXT, answer);
    try cache.put("c.com", .TXT, answer);
    try cache.put("d.com", .TXT, answer); // Should evict a.com

    const key_a = try cache.makeCacheKey("a.com", .TXT);
    defer std.testing.allocator.free(key_a);
    try std.testing.expect(cache.get(key_a) == null); // Evicted

    const key_d = try cache.makeCacheKey("d.com", .TXT);
    defer std.testing.allocator.free(key_d);
    try std.testing.expect(cache.get(key_d) != null); // Present
}

test "resolver init and deinit" {
    var r = Resolver.init(std.testing.allocator, .{});
    defer r.deinit();
    try std.testing.expect(r.next_id != 0);
    try std.testing.expectEqual(@as(usize, 1), r.addrs.len);
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
