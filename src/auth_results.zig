const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const cfws = @import("cfws.zig");

/// RFC 8601 Authentication-Results header builder and parser.
///
/// Format: Authentication-Results: authserv-id; method=result (comment) property.type=value
///
/// Example:
///   Authentication-Results: mail.example.com;
///       spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=example.com;
///       dkim=pass header.d=example.com header.s=selector1
/// A single authentication method result.
pub const MethodResult = struct {
    method: []const u8,
    result: []const u8,
    reason: ?[]const u8 = null,
    properties: []const Property = &.{},

    pub const Property = struct {
        ptype: []const u8,
        property: []const u8,
        value: []const u8,
    };
};

/// Build an Authentication-Results header value.
///
/// Returns the header value (without the "Authentication-Results:" prefix).
/// Caller owns the returned slice.
pub fn build(allocator: Allocator, authserv_id: []const u8, results: []const MethodResult) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, authserv_id);

    for (results) |mr| {
        try buf.appendSlice(allocator, ";\r\n\t");
        try buf.appendSlice(allocator, mr.method);
        try buf.append(allocator, '=');
        try buf.appendSlice(allocator, mr.result);

        if (mr.reason) |reason| {
            try buf.appendSlice(allocator, " (");
            try buf.appendSlice(allocator, reason);
            try buf.append(allocator, ')');
        }

        for (mr.properties) |prop| {
            try buf.append(allocator, ' ');
            try buf.appendSlice(allocator, prop.ptype);
            try buf.append(allocator, '.');
            try buf.appendSlice(allocator, prop.property);
            try buf.append(allocator, '=');
            try buf.appendSlice(allocator, prop.value);
        }
    }

    return buf.toOwnedSlice(allocator);
}

/// Build the "none" result (no authentication performed).
pub fn buildNone(allocator: Allocator, authserv_id: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, authserv_id);
    try buf.appendSlice(allocator, "; none");

    return buf.toOwnedSlice(allocator);
}

/// Check if an Authentication-Results header claims a specific authserv-id.
///
/// Used for A-R header removal: before adding our own, remove any
/// pre-existing A-R headers that claim our authserv-id (RFC 8601 §5).
pub fn matchesAuthservId(header_value: []const u8, authserv_id: []const u8) bool {
    const trimmed = mem.trimLeft(u8, header_value, &std.ascii.whitespace);
    if (trimmed.len < authserv_id.len) return false;

    const candidate = trimmed[0..authserv_id.len];
    if (!std.ascii.eqlIgnoreCase(candidate, authserv_id)) return false;

    if (trimmed.len == authserv_id.len) return true;
    const next_char = trimmed[authserv_id.len];
    return next_char == ';' or next_char == ' ' or next_char == '\t';
}

/// Extract the authserv-id from an Authentication-Results header value.
pub fn authservId(header_value: []const u8) []const u8 {
    const trimmed = mem.trimLeft(u8, header_value, &std.ascii.whitespace);
    const first_semi = mem.indexOfScalar(u8, trimmed, ';') orelse return trimmed;
    return mem.trim(u8, trimmed[0..first_semi], &std.ascii.whitespace);
}

/// Iterator over the `method=result` pairs of an Authentication-Results value.
///
/// `parseResults` is a thin allocating wrapper around this iterator, so any
/// code that decides whether a header *asserts* a given method sees exactly
/// what a consumer of that header would read. That equivalence is what makes
/// forged-header removal sound: a header cannot be interpreted as carrying a
/// result that the removal logic failed to notice.
pub const ResultIterator = struct {
    rest: []const u8,

    pub fn init(header_value: []const u8) ResultIterator {
        const first_semi = cfws.indexOfScalar(header_value, 0, ';') orelse return .{ .rest = "" };
        return .{ .rest = header_value[first_semi + 1 ..] };
    }

    pub fn next(self: *ResultIterator) ?ParsedHeader.ParsedResult {
        while (self.rest.len > 0) {
            // One `method = result *( CFWS property )` group, ending at the
            // next semicolon that is real syntax rather than comment text.
            const group_end = cfws.indexOfScalar(self.rest, 0, ';') orelse self.rest.len;
            const group = self.rest[0..group_end];
            self.rest = if (group_end < self.rest.len) self.rest[group_end + 1 ..] else "";

            const parsed = parseGroup(group) orelse continue;
            return parsed;
        }
        return null;
    }
};

/// Split one `method=result properties...` group. Null when it carries no
/// method/result pair, which is how `none` and stray whitespace are skipped.
fn parseGroup(group: []const u8) ?ParsedHeader.ParsedResult {
    const m_start = cfws.skip(group, 0);
    if (m_start >= group.len) return null;

    const eq = cfws.indexOfScalar(group, m_start, '=') orelse return null;
    const method = mem.trim(u8, group[m_start..eq], &std.ascii.whitespace);
    if (method.len == 0) return null;

    const r_start = cfws.skip(group, eq + 1);
    if (r_start >= group.len) return null;
    const r_end = cfws.tokenEnd(group, r_start, "");
    const result = group[r_start..r_end];
    if (result.len == 0) return null;

    return .{ .method = method, .result = result, .props = group[r_end..] };
}

/// Iterator over the `ptype.property=value` items attached to one result.
pub const PropertyIterator = struct {
    rest: []const u8,

    pub fn next(self: *PropertyIterator) ?ParsedHeader.Property {
        while (true) {
            const start = cfws.skip(self.rest, 0);
            if (start >= self.rest.len) {
                self.rest = "";
                return null;
            }
            const end = cfws.tokenEnd(self.rest, start, "");
            const token = self.rest[start..end];
            self.rest = self.rest[end..];

            const eq = mem.indexOfScalar(u8, token, '=') orelse continue;
            const name = token[0..eq];
            if (name.len == 0 or eq + 1 >= token.len) continue;
            return .{ .name = name, .value = token[eq + 1 ..] };
        }
    }
};

/// True if the header asserts a result for any of `methods` (case-insensitive,
/// RFC 8601 §2.2: method names are not case-sensitive).
pub fn assertsAnyMethod(header_value: []const u8, methods: []const []const u8) bool {
    var it = ResultIterator.init(header_value);
    while (it.next()) |r| {
        for (methods) |m| {
            if (std.ascii.eqlIgnoreCase(r.method, m)) return true;
        }
    }
    return false;
}

/// True if the header asserts a result for any method *outside* `allowed`.
///
/// Used at a trust boundary: a header claiming our authserv-id may only carry
/// results for methods this ADMD actually evaluates.
pub fn assertsMethodOutside(header_value: []const u8, allowed: []const []const u8) bool {
    var it = ResultIterator.init(header_value);
    while (it.next()) |r| {
        var permitted = false;
        for (allowed) |m| {
            if (std.ascii.eqlIgnoreCase(r.method, m)) {
                permitted = true;
                break;
            }
        }
        if (!permitted) return true;
    }
    return false;
}

/// Parse an Authentication-Results header to extract method results.
///
/// This is a simplified parser that extracts method=result pairs.
/// Used by SecureDMARC to read SPF and DKIM results from upstream milters.
pub fn parseResults(allocator: Allocator, header_value: []const u8) !ParsedHeader {
    var parsed = ParsedHeader{
        .authserv_id = authservId(header_value),
        .results = .{},
    };
    errdefer parsed.deinit(allocator);

    var it = ResultIterator.init(header_value);
    while (it.next()) |r| {
        try parsed.results.append(allocator, r);
    }

    return parsed;
}

pub const ParsedHeader = struct {
    authserv_id: []const u8,
    results: std.ArrayList(ParsedResult),

    /// One `ptype.property=value` item.
    pub const Property = struct {
        /// The full dotted name, e.g. `header.d`.
        name: []const u8,
        value: []const u8,
    };

    pub const ParsedResult = struct {
        method: []const u8,
        result: []const u8,
        /// The properties belonging to *this* result: the text between its
        /// result token and the next real semicolon.
        ///
        /// Keeping the span per result is the whole point (audit M-6). Reading
        /// `header.d=` by searching the entire header value lets DMARC pair a
        /// domain from one assertion with the result of another, which is a
        /// bypass when the two disagree.
        props: []const u8 = "",

        pub fn properties(self: ParsedResult) PropertyIterator {
            return .{ .rest = self.props };
        }

        /// The value of a property of this result, by dotted name.
        pub fn property(self: ParsedResult, name: []const u8) ?[]const u8 {
            var it = self.properties();
            while (it.next()) |p| {
                if (std.ascii.eqlIgnoreCase(p.name, name)) return p.value;
            }
            return null;
        }

        pub fn passed(self: ParsedResult) bool {
            return std.ascii.eqlIgnoreCase(self.result, "pass");
        }
    };

    pub fn deinit(self: *ParsedHeader, allocator: Allocator) void {
        self.results.deinit(allocator);
    }

    pub fn getResult(self: *const ParsedHeader, method: []const u8) ?[]const u8 {
        for (self.results.items) |r| {
            if (std.ascii.eqlIgnoreCase(r.method, method)) return r.result;
        }
        return null;
    }
};

test "build simple spf result" {
    const results = &[_]MethodResult{.{
        .method = "spf",
        .result = "pass",
        .reason = "sender IP is 192.0.2.1",
        .properties = &.{.{
            .ptype = "smtp",
            .property = "mailfrom",
            .value = "example.com",
        }},
    }};

    const header = try build(std.testing.allocator, "mail.example.com", results);
    defer std.testing.allocator.free(header);

    try std.testing.expect(mem.startsWith(u8, header, "mail.example.com;"));
    try std.testing.expect(mem.indexOf(u8, header, "spf=pass") != null);
    try std.testing.expect(mem.indexOf(u8, header, "smtp.mailfrom=example.com") != null);
    try std.testing.expect(mem.indexOf(u8, header, "(sender IP is 192.0.2.1)") != null);
}

test "build multiple results" {
    const results = &[_]MethodResult{
        .{ .method = "spf", .result = "pass" },
        .{ .method = "dkim", .result = "pass", .properties = &.{.{
            .ptype = "header",
            .property = "d",
            .value = "example.com",
        }} },
    };

    const header = try build(std.testing.allocator, "mail.example.com", results);
    defer std.testing.allocator.free(header);

    try std.testing.expect(mem.indexOf(u8, header, "spf=pass") != null);
    try std.testing.expect(mem.indexOf(u8, header, "dkim=pass") != null);
    try std.testing.expect(mem.indexOf(u8, header, "header.d=example.com") != null);
}

test "matches authserv id" {
    try std.testing.expect(matchesAuthservId("mail.example.com; spf=pass", "mail.example.com"));
    try std.testing.expect(matchesAuthservId("  mail.example.com; dkim=fail", "mail.example.com"));
    try std.testing.expect(!matchesAuthservId("other.host.com; spf=pass", "mail.example.com"));
    try std.testing.expect(!matchesAuthservId("mail.example.com.evil.com; spf=pass", "mail.example.com"));
}

test "parse results" {
    const header = "mail.example.com; spf=pass smtp.mailfrom=example.com; dkim=fail header.d=bad.com";
    var parsed = try parseResults(std.testing.allocator, header);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("mail.example.com", parsed.authserv_id);
    try std.testing.expectEqualStrings("pass", parsed.getResult("spf").?);
    try std.testing.expectEqualStrings("fail", parsed.getResult("dkim").?);
    try std.testing.expect(parsed.getResult("dmarc") == null);
}

test "parse results is case-insensitive in method names" {
    var parsed = try parseResults(std.testing.allocator, "mail.example.com; SPF=pass; DKIM=fail");
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("pass", parsed.getResult("spf").?);
    try std.testing.expectEqualStrings("fail", parsed.getResult("dkim").?);
}

test "asserts any method matches what a consumer would read" {
    const forged = "mail.example.com; spf=pass smtp.mailfrom=boss@victim.test; dkim=pass header.d=victim.test";

    try std.testing.expect(assertsAnyMethod(forged, &.{"spf"}));
    try std.testing.expect(assertsAnyMethod(forged, &.{"DKIM"}));
    try std.testing.expect(!assertsAnyMethod(forged, &.{"dmarc"}));
    try std.testing.expect(!assertsAnyMethod("mail.example.com; none", &.{"spf"}));
}

test "asserts method outside allowed set" {
    const chain_result = "mail.example.com; spf=pass smtp.mailfrom=example.com";

    try std.testing.expect(!assertsMethodOutside(chain_result, &.{ "spf", "dkim", "dmarc" }));
    try std.testing.expect(assertsMethodOutside(chain_result, &.{"dkim"}));
    // A header asserting nothing parseable claims no results to steal.
    try std.testing.expect(!assertsMethodOutside("mail.example.com", &.{}));
}

test "build none" {
    const header = try buildNone(std.testing.allocator, "mail.example.com");
    defer std.testing.allocator.free(header);
    try std.testing.expectEqualStrings("mail.example.com; none", header);
}

test "M-6: a semicolon in a comment does not manufacture a result" {
    // Everything from '(' is one comment. There is no spf result in this
    // header; a scan for ';' used to find one and report spf=pass.
    const forged = "mail.example.com; dkim=fail (note; spf=pass ) header.d=a.test";

    var parsed = try parseResults(std.testing.allocator, forged);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expect(parsed.getResult("spf") == null);
    try std.testing.expectEqualStrings("fail", parsed.getResult("dkim").?);
}

test "M-6: the scrubber and the consumer agree about the comment" {
    // The X-1 removal is only sound while these two see the same results. If
    // the parser ever stops treating the comment as opaque, this fails next to
    // the test above rather than silently opening a strip bypass.
    const forged = "mail.example.com; dkim=fail (note; spf=pass ) header.d=a.test";

    try std.testing.expect(!assertsAnyMethod(forged, &.{"spf"}));
    try std.testing.expect(assertsAnyMethod(forged, &.{"dkim"}));
}

test "M-6: a property belongs to its own result" {
    // The bypass: 'header.d=victim.test' sits in a comment on the spf result,
    // and a whole-value search for "header.d=" paired it with the dkim=pass.
    const value = "mail.example.com; spf=fail (header.d=victim.test ) ; dkim=pass header.d=attacker.test";

    var parsed = try parseResults(std.testing.allocator, value);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.results.items.len);

    const spf = parsed.results.items[0];
    try std.testing.expectEqualStrings("spf", spf.method);
    try std.testing.expect(spf.property("header.d") == null);

    const dkim = parsed.results.items[1];
    try std.testing.expectEqualStrings("dkim", dkim.method);
    try std.testing.expectEqualStrings("attacker.test", dkim.property("header.d").?);
}

test "M-6: each of several signatures keeps its own domain" {
    const value = "mail.example.com; dkim=fail header.d=noise.test; dkim=pass header.d=real.test";

    var parsed = try parseResults(std.testing.allocator, value);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.results.items.len);
    try std.testing.expect(!parsed.results.items[0].passed());
    try std.testing.expectEqualStrings("noise.test", parsed.results.items[0].property("header.d").?);
    try std.testing.expect(parsed.results.items[1].passed());
    try std.testing.expectEqualStrings("real.test", parsed.results.items[1].property("header.d").?);
}

test "M-6: a quoted property value may contain a semicolon" {
    var parsed = try parseResults(std.testing.allocator, "mail.example.com; dkim=pass header.i=\"a;b\" header.d=real.test");
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.results.items.len);
    try std.testing.expectEqualStrings("real.test", parsed.results.items[0].property("header.d").?);
}

test "M-6: a result followed only by a comment still parses" {
    var parsed = try parseResults(std.testing.allocator, "mail.example.com; spf=pass (good sender)");
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("pass", parsed.getResult("spf").?);
}
