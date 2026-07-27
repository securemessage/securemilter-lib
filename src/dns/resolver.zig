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
};

/// Per-worker DNS cache with TTL expiry.
pub const Cache = struct {
    entries: std.StringHashMap(CacheEntry),
    allocator: Allocator,

    pub fn init(allocator: Allocator) Cache {
        return .{
            .entries = std.StringHashMap(CacheEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Cache) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.freeEntry(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
    }

    pub fn get(self: *Cache, key: []const u8) ?[]const packet.Answer {
        const entry = self.entries.get(key) orelse return null;
        const now = std.time.timestamp();
        if (now >= entry.expires_at) {
            return null; // Expired
        }
        return entry.answers;
    }

    pub fn put(self: *Cache, domain: []const u8, rtype: packet.RecordType, answers: []const packet.Answer) !void {
        if (answers.len == 0) return;

        var min_ttl: u32 = answers[0].ttl;
        for (answers[1..]) |ans| {
            if (ans.ttl < min_ttl) min_ttl = ans.ttl;
        }
        if (min_ttl < 30) min_ttl = 30; // Floor at 30 seconds
        if (min_ttl > 86400) min_ttl = 86400; // Cap at 1 day

        const key = try self.makeCacheKey(domain, rtype);
        errdefer self.allocator.free(key);

        const duped = try self.dupeAnswers(answers);

        const result = try self.entries.getOrPut(key);
        if (result.found_existing) {
            self.freeEntry(result.value_ptr.*);
            self.allocator.free(key);
        }

        result.value_ptr.* = .{
            .answers = duped,
            .expires_at = std.time.timestamp() + @as(i64, min_ttl),
        };
    }

    fn makeCacheKey(self: *Cache, domain: []const u8, rtype: packet.RecordType) ![]u8 {
        const type_int = @intFromEnum(rtype);
        return std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ domain, type_int });
    }

    fn dupeAnswers(self: *Cache, answers: []const packet.Answer) ![]packet.Answer {
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

    fn freeEntry(self: *Cache, entry: CacheEntry) void {
        for (entry.answers) |ans| {
            self.allocator.free(ans.name);
            self.allocator.free(ans.data);
        }
        self.allocator.free(entry.answers);
    }
};

/// DNS resolver configuration.
pub const ResolverConfig = struct {
    nameservers: []const []const u8 = &.{"127.0.0.1"},
    port: u16 = 53,
    timeout_ms: u32 = 5000,
    retries: u8 = 2,
    health_cooldown_s: u32 = 30,
    max_failures: u8 = 3,
};

/// Per-server health state for failover tracking.
const ServerHealth = struct {
    consecutive_failures: u8 = 0,
    last_failure_time: i64 = 0,
};

/// Synchronous DNS resolver with per-worker caching, multi-server
/// round-robin, failover, and health monitoring.
///
/// Sends UDP queries and waits for responses with a timeout.
/// Tries servers in round-robin order, skipping unhealthy ones
/// unless all are down (then retries after a cooldown period).
pub const Resolver = struct {
    allocator: Allocator,
    config: ResolverConfig,
    cache: Cache,
    next_id: u16,
    addrs: []net.Address,
    health: []ServerHealth,
    rr_index: usize,

    pub fn init(allocator: Allocator, config: ResolverConfig) Resolver {
        const addrs = allocator.alloc(net.Address, config.nameservers.len) catch
            @panic("DNS resolver: failed to allocate server addresses");
        const health = allocator.alloc(ServerHealth, config.nameservers.len) catch
            @panic("DNS resolver: failed to allocate health state");

        for (config.nameservers, 0..) |ns, i| {
            addrs[i] = parseNameserver(ns, config.port) catch
                @panic("DNS resolver: invalid nameserver address");
            health[i] = .{};
        }

        return .{
            .allocator = allocator,
            .config = config,
            .cache = Cache.init(allocator),
            .next_id = @truncate(@as(u64, @bitCast(std.time.milliTimestamp()))),
            .addrs = addrs,
            .health = health,
            .rr_index = 0,
        };
    }

    pub fn deinit(self: *Resolver) void {
        self.cache.deinit();
        self.allocator.free(self.addrs);
        self.allocator.free(self.health);
    }

    /// Resolve a domain name for the given record type.
    ///
    /// Checks cache first, then sends a UDP query.
    /// Returns owned Result that caller must deinit.
    pub fn resolve(self: *Resolver, domain: []const u8, rtype: packet.RecordType) !Result {
        // Check cache
        const cache_key = try self.cache.makeCacheKey(domain, rtype);
        defer self.allocator.free(cache_key);

        if (self.cache.get(cache_key)) |cached| {
            const duped = try self.cache.dupeAnswers(cached);
            return .{ .answers = duped, .allocator = self.allocator };
        }

        // Build and send query
        const query_id = self.nextId();
        const query_pkt = try packet.buildQuery(self.allocator, domain, rtype, query_id);
        defer self.allocator.free(query_pkt);

        const response_data = try self.sendAndReceive(query_pkt);
        defer self.allocator.free(response_data);

        var response = try packet.parseResponse(self.allocator, response_data);
        defer response.deinit(self.allocator);

        if (response.id != query_id) return error.IdMismatch;
        if (response.rcode != .no_error) return error.DnsError;

        // Cache the result
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
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
        defer posix.close(sock);

        const timeout_sec = self.config.timeout_ms / 1000;
        const timeout_usec = (self.config.timeout_ms % 1000) * 1000;
        const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = @intCast(timeout_usec) };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&tv));

        const num_servers = self.addrs.len;
        const now = std.time.timestamp();

        // Try each server starting from round-robin index.
        // First pass: skip unhealthy servers. Second pass: try unhealthy ones past cooldown.
        var tried: usize = 0;
        while (tried < num_servers * 2) : (tried += 1) {
            const idx = (self.rr_index + tried) % num_servers;
            const h = &self.health[idx];

            // Skip unhealthy servers on first pass (tried < num_servers)
            if (tried < num_servers and h.consecutive_failures >= self.config.max_failures) {
                const elapsed = now - h.last_failure_time;
                if (elapsed < @as(i64, self.config.health_cooldown_s)) continue;
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

                // Success — mark server healthy, advance round-robin
                h.consecutive_failures = 0;
                self.rr_index = (idx + 1) % num_servers;
                return try self.allocator.dupe(u8, buf[0..n]);
            }

            // All retries exhausted for this server — mark failure
            h.consecutive_failures +|= 1;
            h.last_failure_time = now;
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
    var cache = Cache.init(std.testing.allocator);
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
    try std.testing.expectEqual(@as(usize, 1), cached.?.len);
    try std.testing.expectEqualStrings("v=spf1 -all", cached.?[0].data);
}

test "cache miss returns null" {
    var cache = Cache.init(std.testing.allocator);
    defer cache.deinit();

    const key = try cache.makeCacheKey("nonexistent.com", .TXT);
    defer std.testing.allocator.free(key);
    try std.testing.expect(cache.get(key) == null);
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
