//! Per-worker DNS answer cache.
//!
//! Split out of `resolver.zig` because it shares nothing with the query engine
//! but an allocator: it never touches a socket, a nameserver, or `Result`, and
//! reaches only for `packet.Answer` and the negative taxonomy below. Eight of
//! that file's eleven tests were already testing this and nothing else.
//!
//! The negative-answer taxonomy -- `NegativeKind` and `isTransientError` --
//! comes with it rather than staying behind. `CacheEntry` is shaped around
//! `NegativeKind`, so that much had to move or the dependency would run both
//! ways; `isTransientError` follows because the two are one classification and
//! `Resolver` never calls it. Every caller reaches it through `dns.zig`, and
//! the test that pins the distinction -- a dropped packet must not look like an
//! authoritative "no such name" -- exercises both halves at once. Splitting
//! them would put half a rule in each file.
//!
//! `resolver.zig` re-exports all three, so `dns.zig` and the four daemons are
//! unchanged.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const packet = @import("packet.zig");

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
