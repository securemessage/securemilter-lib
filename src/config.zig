const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// A parsed INI configuration with [section] support.
///
/// Sections are identified by `[name]` headers. Keys before any section
/// header belong to the implicit "global" section. Keys within a
/// `[listener:name]` section are accessible via the listener's name.
pub const Config = struct {
    allocator: Allocator,
    sections: SectionMap,
    section_order: std.ArrayList([]const u8),

    const SectionMap = std.StringHashMap(Section);

    pub const Section = struct {
        name: []const u8,
        entries: EntryMap,
        entry_order: std.ArrayList([]const u8),

        const EntryMap = std.StringHashMap([]const u8);

        pub fn get(self: *const Section, key: []const u8) ?[]const u8 {
            return self.entries.get(key);
        }

        pub fn getOrDefault(self: *const Section, key: []const u8, default: []const u8) []const u8 {
            return self.entries.get(key) orelse default;
        }

        pub fn getBool(self: *const Section, key: []const u8, default: bool) bool {
            const val = self.entries.get(key) orelse return default;
            return parseBool(val) orelse default;
        }

        pub fn getInt(self: *const Section, key: []const u8, comptime T: type, default: T) T {
            const val = self.entries.get(key) orelse return default;
            return std.fmt.parseInt(T, val, 10) catch default;
        }

        /// Read a byte count, accepting an optional K/M/G suffix.
        ///
        /// Message size limits are naturally written as "10M", not 10485760;
        /// Postfix-adjacent configuration is where operators set these, so the
        /// spelling should match. Suffixes are binary multiples and
        /// case-insensitive, a trailing "B" is allowed ("10MB"), and anything
        /// unparseable or overflowing falls back to `default` rather than
        /// silently becoming a smaller number.
        pub fn getSize(self: *const Section, key: []const u8, default: usize) usize {
            const raw = self.entries.get(key) orelse return default;
            return parseSize(raw) orelse default;
        }

        /// Read permission mask in octal. Null = option absent.
        /// Octal unconditionally (deliberate narrowing from `strtol` base 0): a mask
        /// has no meaningful decimal spelling (`117` vs `0117` diverges). Malformed
        /// values are errors (not defaults): a wrong mask grants more permission than
        /// the file states (audit X-14).
        pub fn getMode(self: *const Section, key: []const u8) !?std.posix.mode_t {
            const raw = self.entries.get(key) orelse return null;
            const trimmed = std.mem.trim(u8, raw, " \t");
            if (trimmed.len == 0) return error.InvalidMode;
            return std.fmt.parseInt(std.posix.mode_t, trimmed, 8) catch return error.InvalidMode;
        }

        /// Read comma-separated list: trimmed, non-empty parts. Zero-length if absent/empty.
        /// One implementation shared by every daemon, so a `toOwnedSlice` ownership
        /// mistake on SIGHUP cannot be made independently by each one.
        ///
        /// Returned strings borrow from `Config`; `allocator.free(result)` cleans the
        /// outer slice. Callers outliving their `Config` must duplicate contents (done
        /// by every `Reloadable.init`).
        pub fn getCsvList(
            self: *const Section,
            allocator: Allocator,
            key: []const u8,
            default: []const u8,
        ) ![]const []const u8 {
            var list: std.ArrayListUnmanaged([]const u8) = .{};
            errdefer list.deinit(allocator);

            var it = mem.splitSequence(u8, self.getOrDefault(key, default), ",");
            while (it.next()) |part| {
                const trimmed = mem.trim(u8, part, " \t");
                if (trimmed.len > 0) try list.append(allocator, trimmed);
            }
            return list.toOwnedSlice(allocator);
        }

        fn deinit(self: *Section, allocator: Allocator) void {
            var it = self.entries.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            self.entries.deinit();

            for (self.entry_order.items) |key| {
                allocator.free(key);
            }
            self.entry_order.deinit(allocator);

            allocator.free(self.name);
        }
    };

    pub fn init(allocator: Allocator) Config {
        return .{
            .allocator = allocator,
            .sections = SectionMap.init(allocator),
            .section_order = .{},
        };
    }

    pub fn deinit(self: *Config) void {
        var it = self.sections.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.sections.deinit();

        for (self.section_order.items) |name| {
            self.allocator.free(name);
        }
        self.section_order.deinit(self.allocator);
    }

    /// Return the global (unnamed) section, or null if no global keys exist.
    pub fn global(self: *const Config) ?*const Section {
        return self.sections.getPtr("global");
    }

    /// Return a named section, e.g. "listener:verify-inbound".
    pub fn getSection(self: *const Config, name: []const u8) ?*const Section {
        return self.sections.getPtr(name);
    }

    /// Iterate over all section names in file order.
    pub fn sectionNames(self: *const Config) []const []const u8 {
        return self.section_order.items;
    }

    /// Return all sections whose name starts with a given prefix.
    /// Caller owns the returned slice (but not the section pointers).
    pub fn sectionsWithPrefix(self: *const Config, prefix: []const u8) !std.ArrayList(*const Section) {
        var result: std.ArrayList(*const Section) = .{};
        for (self.section_order.items) |name| {
            if (mem.startsWith(u8, name, prefix)) {
                if (self.sections.getPtr(name)) |sec| {
                    try result.append(self.allocator, sec);
                }
            }
        }
        return result;
    }
};

/// Global keys the library itself consumes, for validateKeys tables. The
/// daemons concatenate their own keys onto this at comptime.
pub const base_global_keys = [_][]const u8{
    // connection.Limits
    "MaxHeaders",
    "MaxHeaderBytes",
    "MaxBodyBytes",
    "MaxSignatures",
    // log.LogConfig
    "Syslog",
    "SyslogFacility",
    "LogLevel",
};

/// One offending key found by `validateKeys`.
pub const KeyOffense = struct {
    section: []const u8,
    key: []const u8,
    kind: Kind,

    pub const Kind = enum {
        /// No table knows this key -- almost certainly a typo.
        unknown,
        /// A known global key sitting in a listener section, where it has no
        /// effect. The file's own layout hides the mistake from review.
        misplaced,
    };
};

/// One class of configuration section: which sections it covers, and the only
/// keys legal inside them.
///
/// `listener:*` was the sole non-global class for as long as every daemon in
/// the suite had exactly one kind of repeated section. SecureSCAN does not: its
/// module set is open-ended by design, so its configuration grows a family of
/// sections per module, and a validator that recognises two fixed shapes cannot
/// express that. Rather than teach this file about modules, the caller now
/// describes its own section classes.
pub const SectionKind = struct {
    /// The section name to match. With `prefix` set this is matched against the
    /// START of the name and should carry its own separator ("listener:",
    /// "modules."); otherwise it must equal the whole name.
    name: []const u8,
    prefix: bool = false,
    keys: []const []const u8,
};

/// Validate every key in every section against the daemon's known-key tables.
///
/// Silent acceptance is how a security control gets switched off invisibly:
/// the daemon starts, the operator's intent is not in effect, and nothing says
/// so. Twice in one day of live deployment work a key appended at end-of-file
/// landed in the last listener section and did nothing. The operator must be
/// told, so the caller is expected to refuse startup and name the offense.
///
/// Returns the first offense, or null when the file is clean.
pub fn validateKeys(
    cfg: *const Config,
    global_keys: []const []const u8,
    listener_keys: []const []const u8,
) ?KeyOffense {
    return validateSections(cfg, global_keys, &.{
        .{ .name = "listener:", .prefix = true, .keys = listener_keys },
    });
}

/// `validateKeys` generalised to any set of section classes.
///
/// A section matching no kind is checked against `global_keys`, which is what
/// this function did for everything except `listener:*` before the kinds table
/// existed. That is deliberately unchanged: tightening it to "an unrecognised
/// section is itself an offense" would be the stricter rule, and arguably the
/// right one, but it can refuse a config that starts a daemon today -- so it
/// is a decision for whoever wants it, not a side effect of this one.
///
/// Kinds are tried in order and the first match wins, so an exact name may be
/// listed ahead of a prefix that would also cover it.
pub fn validateSections(
    cfg: *const Config,
    global_keys: []const []const u8,
    kinds: []const SectionKind,
) ?KeyOffense {
    for (cfg.sectionNames()) |name| {
        const sec = cfg.getSection(name) orelse continue;
        const matched = matchKind(kinds, name);
        for (sec.entry_order.items) |key| {
            if (matched) |kind| {
                if (inSet(kind.keys, key)) continue;
                return .{
                    .section = name,
                    .key = key,
                    .kind = if (inSet(global_keys, key)) .misplaced else .unknown,
                };
            }
            if (!inSet(global_keys, key))
                return .{ .section = name, .key = key, .kind = .unknown };
        }
    }
    return null;
}

fn matchKind(kinds: []const SectionKind, name: []const u8) ?SectionKind {
    for (kinds) |kind| {
        const hit = if (kind.prefix)
            mem.startsWith(u8, name, kind.name)
        else
            mem.eql(u8, name, kind.name);
        if (hit) return kind;
    }
    return null;
}

fn inSet(set: []const []const u8, key: []const u8) bool {
    for (set) |k| {
        if (mem.eql(u8, k, key)) return true;
    }
    return false;
}

/// Parse an INI file from a byte slice.
pub fn parse(allocator: Allocator, source: []const u8) !Config {
    var cfg = Config.init(allocator);
    errdefer cfg.deinit();

    var current_section: []const u8 = try allocator.dupe(u8, "global");
    ensureSection(&cfg, current_section) catch |err| {
        allocator.free(current_section);
        return err;
    };

    var line_iter = mem.splitScalar(u8, source, '\n');
    while (line_iter.next()) |raw_line| {
        const line = mem.trim(u8, raw_line, &std.ascii.whitespace);

        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;

        if (line[0] == '[') {
            const end = mem.indexOfScalar(u8, line, ']') orelse continue;
            const name = mem.trim(u8, line[1..end], &std.ascii.whitespace);
            if (name.len == 0) continue;

            const new_section = try allocator.dupe(u8, name);
            const existed = cfg.sections.contains(new_section);
            ensureSection(&cfg, new_section) catch |err| {
                allocator.free(new_section);
                return err;
            };
            if (existed) {
                allocator.free(new_section);
            }
            current_section = if (existed) cfg.sections.getPtr(name).?.name else new_section;
            continue;
        }

        const eq_pos = mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = mem.trim(u8, line[0..eq_pos], &std.ascii.whitespace);
        const val = mem.trim(u8, line[eq_pos + 1 ..], &std.ascii.whitespace);
        if (key.len == 0) continue;

        const section = cfg.sections.getPtr(current_section) orelse continue;
        const key_dup = try allocator.dupe(u8, key);
        errdefer allocator.free(key_dup);
        const val_dup = try allocator.dupe(u8, val);
        errdefer allocator.free(val_dup);

        const result = try section.entries.getOrPut(key_dup);
        if (result.found_existing) {
            allocator.free(result.value_ptr.*);
            allocator.free(key_dup);
        } else {
            const order_dup = try allocator.dupe(u8, key);
            try section.entry_order.append(allocator, order_dup);
        }
        result.value_ptr.* = val_dup;
    }

    return cfg;
}

/// Parse an INI file from a filesystem path.
pub fn parseFile(allocator: Allocator, path: []const u8) !Config {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const source = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(source);

    return parse(allocator, source);
}

fn ensureSection(cfg: *Config, name: []const u8) !void {
    const result = try cfg.sections.getOrPut(name);
    if (!result.found_existing) {
        result.value_ptr.* = .{
            .name = name,
            .entries = Config.Section.EntryMap.init(cfg.allocator),
            .entry_order = .{},
        };
        const order_dup = try cfg.allocator.dupe(u8, name);
        try cfg.section_order.append(cfg.allocator, order_dup);
    }
}

fn parseBool(val: []const u8) ?bool {
    const lower = blk: {
        if (std.ascii.eqlIgnoreCase(val, "yes")) break :blk true;
        if (std.ascii.eqlIgnoreCase(val, "true")) break :blk true;
        if (std.ascii.eqlIgnoreCase(val, "1")) break :blk true;
        if (std.ascii.eqlIgnoreCase(val, "no")) break :blk false;
        if (std.ascii.eqlIgnoreCase(val, "false")) break :blk false;
        if (std.ascii.eqlIgnoreCase(val, "0")) break :blk false;
        return null;
    };
    return lower;
}

/// Parse a byte count with an optional binary K/M/G suffix.
///
/// Returns null on anything it cannot represent exactly, including overflow.
/// Callers fall back to their default in that case: quietly wrapping a size
/// limit round to a small number would turn a typo into an outage.
fn parseSize(val: []const u8) ?usize {
    var s = std.mem.trim(u8, val, " \t");
    if (s.len == 0) return null;

    // Optional trailing "B", so "10M", "10MB" and "512B" all work. A plain
    // byte count never ends in B, so this is unconditional.
    if (s.len >= 2 and (s[s.len - 1] == 'b' or s[s.len - 1] == 'B')) {
        s = s[0 .. s.len - 1];
    }

    var multiplier: usize = 1;
    if (s.len >= 2) {
        switch (s[s.len - 1]) {
            'k', 'K' => multiplier = 1024,
            'm', 'M' => multiplier = 1024 * 1024,
            'g', 'G' => multiplier = 1024 * 1024 * 1024,
            else => {},
        }
        if (multiplier != 1) s = s[0 .. s.len - 1];
    }

    const base = std.fmt.parseInt(usize, std.mem.trim(u8, s, " \t"), 10) catch return null;
    if (multiplier == 1) return base;
    return std.math.mul(usize, base, multiplier) catch null;
}

test "parseSize accepts plain byte counts" {
    try std.testing.expectEqual(@as(?usize, 0), parseSize("0"));
    try std.testing.expectEqual(@as(?usize, 10485760), parseSize("10485760"));
    try std.testing.expectEqual(@as(?usize, 512), parseSize("  512  "));
}

test "parseSize accepts binary suffixes" {
    try std.testing.expectEqual(@as(?usize, 1024), parseSize("1K"));
    try std.testing.expectEqual(@as(?usize, 1024), parseSize("1k"));
    try std.testing.expectEqual(@as(?usize, 10 * 1024 * 1024), parseSize("10M"));
    try std.testing.expectEqual(@as(?usize, 10 * 1024 * 1024), parseSize("10MB"));
    try std.testing.expectEqual(@as(?usize, 2 * 1024 * 1024 * 1024), parseSize("2g"));
    try std.testing.expectEqual(@as(?usize, 25 * 1024 * 1024), parseSize(" 25 M "));
    // A bare "B" suffix is a byte count, not a rejected unit.
    try std.testing.expectEqual(@as(?usize, 512), parseSize("512B"));
    try std.testing.expectEqual(@as(?usize, 1), parseSize("1b"));
}

test "parseSize rejects rather than truncates" {
    try std.testing.expectEqual(@as(?usize, null), parseSize(""));
    try std.testing.expectEqual(@as(?usize, null), parseSize("M"));
    try std.testing.expectEqual(@as(?usize, null), parseSize("10X"));
    try std.testing.expectEqual(@as(?usize, null), parseSize("ten"));
    try std.testing.expectEqual(@as(?usize, null), parseSize("-1"));
    try std.testing.expectEqual(@as(?usize, null), parseSize("1.5M"));
    // Overflow must not wrap into a small, silently-enforced limit.
    try std.testing.expectEqual(@as(?usize, null), parseSize("99999999999999999999G"));
}

test "getSize falls back to the default on a bad value" {
    const source =
        \\MaxBodyBytes = 25M
        \\MaxHeaderBytes = bogus
    ;
    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();
    const global = cfg.global().?;

    try std.testing.expectEqual(@as(usize, 25 * 1024 * 1024), global.getSize("MaxBodyBytes", 1));
    try std.testing.expectEqual(@as(usize, 4096), global.getSize("MaxHeaderBytes", 4096));
    try std.testing.expectEqual(@as(usize, 7), global.getSize("NotPresent", 7));
}

test "getCsvList trims, skips empties, and applies the default" {
    const source =
        \\DnsNameserver = 10.0.0.1,  8.8.8.8 ,,
        \\LocalAuthMethods =
    ;
    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();
    const global = cfg.global().?;

    const ns = try global.getCsvList(std.testing.allocator, "DnsNameserver", "127.0.0.1");
    defer std.testing.allocator.free(ns);
    try std.testing.expectEqual(@as(usize, 2), ns.len);
    try std.testing.expectEqualStrings("10.0.0.1", ns[0]);
    try std.testing.expectEqualStrings("8.8.8.8", ns[1]);

    // Present but empty is not the same as absent: it must not fall back to the
    // default, or `LocalAuthMethods =` would silently mean something.
    const methods = try global.getCsvList(std.testing.allocator, "LocalAuthMethods", "");
    defer std.testing.allocator.free(methods);
    try std.testing.expectEqual(@as(usize, 0), methods.len);

    const absent = try global.getCsvList(std.testing.allocator, "NotPresent", "a, b");
    defer std.testing.allocator.free(absent);
    try std.testing.expectEqual(@as(usize, 2), absent.len);
    try std.testing.expectEqualStrings("b", absent[1]);
}

// The reason this function exists rather than five copies. `FailingAllocator`
// walks the failure point across every allocation the call makes, and
// `std.testing.allocator` underneath reports anything left outstanding -- so a
// missing `errdefer` in here fails this test instead of leaking in a daemon.
//
// The item count is load-bearing: only a long list (reallocated) puts failure
// after memory is owned -- the case `errdefer` exists for. Verified to fail
// when `errdefer` is removed.
test "getCsvList leaves nothing outstanding when an allocation fails" {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    try buf.appendSlice(std.testing.allocator, "DnsNameserver = a0");
    for (1..512) |i| try buf.writer(std.testing.allocator).print(",a{d}", .{i});

    var cfg = try parse(std.testing.allocator, buf.items);
    defer cfg.deinit();
    const global = cfg.global().?;

    var fail_index: usize = 0;
    while (fail_index < 24) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
            .fail_index = fail_index,
        });
        const result = global.getCsvList(failing.allocator(), "DnsNameserver", "") catch continue;
        failing.allocator().free(result);
    }
}

test "parse empty config" {
    var cfg = try parse(std.testing.allocator, "");
    defer cfg.deinit();
    try std.testing.expect(cfg.global() != null);
}

test "parse global keys" {
    const source =
        \\AuthservID = mail.example.com
        \\WorkerThreads = 8
        \\Syslog = yes
    ;
    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    const g = cfg.global().?;
    try std.testing.expectEqualStrings("mail.example.com", g.get("AuthservID").?);
    try std.testing.expectEqual(@as(u32, 8), g.getInt("WorkerThreads", u32, 0));
    try std.testing.expect(g.getBool("Syslog", false));
}

test "parse sections" {
    const source =
        \\[global]
        \\AuthservID = mail.example.com
        \\
        \\[listener:verify-inbound]
        \\Socket = inet:8891@0.0.0.0
        \\Mode = verify
        \\
        \\[listener:sign-outbound]
        \\Socket = inet:8892@0.0.0.0
        \\Mode = sign
        \\Domain = example.com
    ;
    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    const g = cfg.global().?;
    try std.testing.expectEqualStrings("mail.example.com", g.get("AuthservID").?);

    const verify = cfg.getSection("listener:verify-inbound").?;
    try std.testing.expectEqualStrings("inet:8891@0.0.0.0", verify.get("Socket").?);
    try std.testing.expectEqualStrings("verify", verify.get("Mode").?);

    const sign = cfg.getSection("listener:sign-outbound").?;
    try std.testing.expectEqualStrings("sign", sign.get("Mode").?);
    try std.testing.expectEqualStrings("example.com", sign.get("Domain").?);
}

test "parse comments and blank lines" {
    const source =
        \\# This is a comment
        \\; This is also a comment
        \\
        \\Key1 = value1
        \\  # Indented comment
        \\Key2 = value2
    ;
    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    const g = cfg.global().?;
    try std.testing.expectEqualStrings("value1", g.get("Key1").?);
    try std.testing.expectEqualStrings("value2", g.get("Key2").?);
}

test "sections with prefix" {
    const source =
        \\[global]
        \\AuthservID = test
        \\
        \\[listener:a]
        \\Mode = verify
        \\
        \\[listener:b]
        \\Mode = sign
        \\
        \\[other:x]
        \\Foo = bar
    ;
    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    var listeners = try cfg.sectionsWithPrefix("listener:");
    defer listeners.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), listeners.items.len);
}

test "bool parsing" {
    const source =
        \\Yes1 = yes
        \\Yes2 = True
        \\Yes3 = 1
        \\No1 = no
        \\No2 = False
        \\No3 = 0
    ;
    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    const g = cfg.global().?;
    try std.testing.expect(g.getBool("Yes1", false));
    try std.testing.expect(g.getBool("Yes2", false));
    try std.testing.expect(g.getBool("Yes3", false));
    try std.testing.expect(!g.getBool("No1", true));
    try std.testing.expect(!g.getBool("No2", true));
    try std.testing.expect(!g.getBool("No3", true));
    try std.testing.expect(g.getBool("Missing", true));
}

test "mode parsing is octal, and a bad value is refused rather than defaulted" {
    const source =
        \\Leading = 0117
        \\Bare = 117
        \\Zero = 0
        \\Junk = 0o117
        \\Empty =
        \\Negative = -1
    ;
    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    const g = cfg.global().?;
    try std.testing.expectEqual(@as(?std.posix.mode_t, 0o117), try g.getMode("Leading"));

    // The case the octal-only rule exists for: base-0 parsing, which is what
    // opendkim uses, reads this as decimal 117 = 0o165 and hands out a socket
    // group-writable and world-executable.
    try std.testing.expectEqual(@as(?std.posix.mode_t, 0o117), try g.getMode("Bare"));

    // Distinct from absent -- 0 is a legitimate mask meaning "filter nothing".
    try std.testing.expectEqual(@as(?std.posix.mode_t, 0), try g.getMode("Zero"));
    try std.testing.expectEqual(@as(?std.posix.mode_t, null), try g.getMode("Missing"));

    try std.testing.expectError(error.InvalidMode, g.getMode("Junk"));
    try std.testing.expectError(error.InvalidMode, g.getMode("Empty"));
    try std.testing.expectError(error.InvalidMode, g.getMode("Negative"));
}

test "duplicate key overwrites" {
    const source =
        \\Key = first
        \\Key = second
    ;
    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    const g = cfg.global().?;
    try std.testing.expectEqualStrings("second", g.get("Key").?);
}

test "validateKeys accepts a clean file" {
    var cfg = try parse(std.testing.allocator,
        \\AuthservID = mail.test
        \\WorkerThreads = 0
        \\[listener:inbound]
        \\Socket = inet:8890@127.0.0.1
        \\Mode = verify
    );
    defer cfg.deinit();

    const global_keys = [_][]const u8{ "AuthservID", "WorkerThreads" };
    const listener_keys = [_][]const u8{ "Socket", "Mode" };
    try std.testing.expect(validateKeys(&cfg, &global_keys, &listener_keys) == null);
}

test "validateKeys names a typo in global" {
    var cfg = try parse(std.testing.allocator,
        \\AuthservID = mail.test
        \\WhitelistFil = /tmp/x
    );
    defer cfg.deinit();

    const global_keys = [_][]const u8{ "AuthservID", "WhitelistFile" };
    const offense = validateKeys(&cfg, &global_keys, &.{}).?;
    try std.testing.expectEqualStrings("global", offense.section);
    try std.testing.expectEqualStrings("WhitelistFil", offense.key);
    try std.testing.expectEqual(KeyOffense.Kind.unknown, offense.kind);
}

test "validateKeys names a global key misplaced in a listener section" {
    // The trap seen twice in one day of live deployment: a key appended at
    // end-of-file lands in the last listener section and silently does
    // nothing.
    var cfg = try parse(std.testing.allocator,
        \\AuthservID = mail.test
        \\[listener:inbound]
        \\Socket = inet:8890@127.0.0.1
        \\OverSignHeaders =
    );
    defer cfg.deinit();

    const global_keys = [_][]const u8{ "AuthservID", "OverSignHeaders" };
    const listener_keys = [_][]const u8{"Socket"};
    const offense = validateKeys(&cfg, &global_keys, &listener_keys).?;
    try std.testing.expectEqualStrings("listener:inbound", offense.section);
    try std.testing.expectEqualStrings("OverSignHeaders", offense.key);
    try std.testing.expectEqual(KeyOffense.Kind.misplaced, offense.kind);
}

test "validateKeys names an unknown key in a listener section" {
    var cfg = try parse(std.testing.allocator,
        \\[listener:inbound]
        \\Sockt = inet:8890@127.0.0.1
    );
    defer cfg.deinit();

    const offense = validateKeys(&cfg, &.{"Socket"}, &.{"Socket"}).?;
    try std.testing.expectEqual(KeyOffense.Kind.unknown, offense.kind);
    try std.testing.expectEqualStrings("Sockt", offense.key);
}

test "validateSections gives each section family its own key table" {
    var cfg = try parse(std.testing.allocator,
        \\[global]
        \\WorkerThreads = 4
        \\[listener:inbound]
        \\Socket = inet:8897@127.0.0.1
        \\[modules.url_dnsbl]
        \\Weight = 6.0
        \\[modules.clamav]
        \\BudgetMs = 2000
    );
    defer cfg.deinit();

    const kinds = [_]SectionKind{
        .{ .name = "listener:", .prefix = true, .keys = &.{"Socket"} },
        .{ .name = "modules.", .prefix = true, .keys = &.{ "Weight", "BudgetMs" } },
    };
    try std.testing.expect(validateSections(&cfg, &.{"WorkerThreads"}, &kinds) == null);
}

test "validateSections still names a typo inside a module section" {
    // The point of the whole mechanism: a per-module section must not become a
    // place where a misspelt key is silently accepted, which is exactly what
    // happened before `validateKeys` existed at all.
    var cfg = try parse(std.testing.allocator,
        \\[modules.url_dnsbl]
        \\Wieght = 6.0
    );
    defer cfg.deinit();

    const kinds = [_]SectionKind{
        .{ .name = "modules.", .prefix = true, .keys = &.{"Weight"} },
    };
    const offense = validateSections(&cfg, &.{}, &kinds).?;
    try std.testing.expectEqualStrings("modules.url_dnsbl", offense.section);
    try std.testing.expectEqualStrings("Wieght", offense.key);
    try std.testing.expectEqual(KeyOffense.Kind.unknown, offense.kind);
}

test "validateSections reports a global key misplaced in any family, not just listeners" {
    var cfg = try parse(std.testing.allocator,
        \\[modules.clamav]
        \\WorkerThreads = 4
    );
    defer cfg.deinit();

    const kinds = [_]SectionKind{
        .{ .name = "modules.", .prefix = true, .keys = &.{"BudgetMs"} },
    };
    const offense = validateSections(&cfg, &.{"WorkerThreads"}, &kinds).?;
    try std.testing.expectEqual(KeyOffense.Kind.misplaced, offense.kind);
}

test "an exact-name kind listed first wins over a prefix that also covers it" {
    // Ordering is the only way to express "this one section is special", so it
    // is a documented property rather than an accident of the loop.
    var cfg = try parse(std.testing.allocator,
        \\[modules.bayes]
        \\DbPath = /var/db/securescan/bayes
    );
    defer cfg.deinit();

    const kinds = [_]SectionKind{
        .{ .name = "modules.bayes", .keys = &.{"DbPath"} },
        .{ .name = "modules.", .prefix = true, .keys = &.{"Weight"} },
    };
    try std.testing.expect(validateSections(&cfg, &.{}, &kinds) == null);
}

test "validateKeys is validateSections with one listener kind" {
    // The four shipped daemons call `validateKeys`; if the wrapper ever stopped
    // agreeing with the general form, they would silently get a different rule
    // from the one this file documents.
    var cfg = try parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.example.com
        \\[listener:inbound]
        \\Sockt = inet:8890@127.0.0.1
    );
    defer cfg.deinit();

    const via_wrapper = validateKeys(&cfg, &.{"AuthservID"}, &.{"Socket"}).?;
    const via_general = validateSections(&cfg, &.{"AuthservID"}, &.{
        .{ .name = "listener:", .prefix = true, .keys = &.{"Socket"} },
    }).?;

    try std.testing.expectEqualStrings(via_wrapper.section, via_general.section);
    try std.testing.expectEqualStrings(via_wrapper.key, via_general.key);
    try std.testing.expectEqual(via_wrapper.kind, via_general.kind);
}

test "a section matching no kind is still checked against the global table" {
    // Documented, unchanged behaviour -- not an endorsement of it. See the note
    // on `validateSections` about why tightening this is a separate decision.
    var cfg = try parse(std.testing.allocator,
        \\[providers]
        \\WorkerThreads = 4
    );
    defer cfg.deinit();

    try std.testing.expect(validateSections(&cfg, &.{"WorkerThreads"}, &.{}) == null);
    try std.testing.expect(validateSections(&cfg, &.{"Nope"}, &.{}) != null);
}
