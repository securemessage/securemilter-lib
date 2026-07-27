const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const net = std.net;
const Allocator = mem.Allocator;
const packet = @import("packet.zig");

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

/// TTL-aware DNS cache entry.
const CacheEntry = struct {
    answers: []packet.Answer,
    expires_at: i64,
    is_negative: bool,
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
            .is_negative = false,
        });
    }

    /// Cache a negative result (NXDOMAIN, SERVFAIL, or empty response).
    pub fn putNegative(self: *Cache, domain: []const u8, rtype: packet.RecordType) !void {
        const key = try self.makeCacheKey(domain, rtype);
        errdefer self.allocator.free(key);

        try self.evictIfFull();
        try self.insertEntry(key, .{
            .answers = &.{},
            .expires_at = std.time.timestamp() + @as(i64, self.negative_ttl),
            .is_negative = true,
        });
    }

    pub fn makeCacheKey(self: *Cache, domain: []const u8, rtype: packet.RecordType) ![]u8 {
        const type_int = @intFromEnum(rtype);
        return std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ domain, type_int });
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
            if (!result.value_ptr.is_negative) self.freeEntry(result.value_ptr.*);
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
            if (!kv.value.is_negative) self.freeEntry(kv.value);
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

        return .{
            .allocator = allocator,
            .config = config,
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
            if (entry.is_negative) return error.DnsError;
            const duped = try self.cache.dupeAnswers(entry.answers);
            return .{ .answers = duped, .allocator = self.allocator };
        }

        // Build and send query
        const query_id = self.nextId();
        const query_pkt = try packet.buildQuery(self.allocator, domain, rtype, query_id);
        defer self.allocator.free(query_pkt);

        const response_data = self.sendAndReceive(query_pkt) catch |err| {
            // Cache negative result on timeout (transient failure)
            if (err == error.DnsTimeout) self.cache.putNegative(domain, rtype) catch {};
            return err;
        };
        defer self.allocator.free(response_data);

        var response = try packet.parseResponse(self.allocator, response_data);
        defer response.deinit(self.allocator);

        if (response.id != query_id) return error.IdMismatch;
        if (response.rcode != .no_error) {
            // Cache NXDOMAIN/SERVFAIL as negative
            self.cache.putNegative(domain, rtype) catch {};
            return error.DnsError;
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

    fn nextId(self: *Resolver) u16 {
        const id = self.next_id;
        self.next_id +%= 1;
        return id;
    }
};

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
    try std.testing.expect(!cached.?.is_negative);
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

    try cache.putNegative("nxdomain.com", .TXT);

    const key = try cache.makeCacheKey("nxdomain.com", .TXT);
    defer std.testing.allocator.free(key);
    const cached = cache.get(key);
    try std.testing.expect(cached != null);
    try std.testing.expect(cached.?.is_negative);
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
