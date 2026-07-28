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
