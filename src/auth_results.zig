const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const cfws = @import("cfws.zig");

/// A single RFC 8601 Authentication-Results method result.
///
/// Serialized as `method=result (reason) ptype.property=value`.
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

/// Marker for a DKIM result produced with a testing (`t=y`) key.
///
/// SecureDKIM reports the verification result and adds this local `policy`
/// property; SecureDMARC preserves the result but excludes it from alignment.
pub const testing_key_marker = struct {
    pub const ptype = "policy";
    pub const property = "dkim-rules";
    pub const value = "testing-key";
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
            try appendComment(allocator, &buf, reason);
            try buf.append(allocator, ')');
        }

        for (mr.properties) |prop| {
            try buf.append(allocator, ' ');
            try buf.appendSlice(allocator, prop.ptype);
            try buf.append(allocator, '.');
            try buf.appendSlice(allocator, prop.property);
            try buf.append(allocator, '=');
            try appendPvalue(allocator, &buf, prop.value);
        }
    }

    return buf.toOwnedSlice(allocator);
}

/// May this byte stand unquoted in a `pvalue`?
///
/// RFC 8601 §2.2 permits an RFC 2045 `value` (token / quoted-string) or an
/// address/domain. This safe bare subset covers common domain, address, and
/// selector forms; every other value, including `;` and SP, is quoted.
fn isPvalueSafe(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        '-', '.', '_', '@' => true,
        else => false,
    };
}

/// Write one `pvalue`, quoting it when it cannot stand bare.
///
/// Values may originate with the sender. Quoting keeps delimiters inside the
/// property value; control bytes are replaced because they cannot appear in a
/// quoted string without creating a header-injection boundary.
fn appendPvalue(allocator: Allocator, buf: *std.ArrayList(u8), value: []const u8) !void {
    var needs_quoting = value.len == 0;
    for (value) |ch| {
        if (!isPvalueSafe(ch)) {
            needs_quoting = true;
            break;
        }
    }

    if (!needs_quoting) {
        try buf.appendSlice(allocator, value);
        return;
    }

    try buf.append(allocator, '"');
    for (value) |ch| {
        if (ch < 0x20 or ch == 0x7f) {
            try buf.append(allocator, '?');
        } else if (ch == '"' or ch == '\\') {
            try buf.append(allocator, '\\');
            try buf.append(allocator, ch);
        } else {
            try buf.append(allocator, ch);
        }
    }
    try buf.append(allocator, '"');
}

/// Write comment text, escaping comment delimiters and control bytes.
///
/// This keeps future sender-derived reasons inside the RFC 8601 comment.
fn appendComment(allocator: Allocator, buf: *std.ArrayList(u8), text: []const u8) !void {
    for (text) |ch| {
        if (ch < 0x20 or ch == 0x7f) {
            try buf.append(allocator, '?');
        } else if (ch == '(' or ch == ')' or ch == '\\') {
            try buf.append(allocator, '\\');
            try buf.append(allocator, ch);
        } else {
            try buf.append(allocator, ch);
        }
    }
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
/// Consumers and forged-header removal share this parser so they cannot disagree
/// about which methods a header asserts.
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

/// Parse method results from an Authentication-Results header.
///
/// SecureDMARC uses these upstream SPF and DKIM results.
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
        /// Properties between this result token and the next syntactic semicolon.
        ///
        /// Keeping this span prevents a property from one assertion being paired
        /// with the verdict of another.
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

test "D-11: a testing-key result keeps its real verdict and carries the policy marker" {
    const results = &[_]MethodResult{.{
        .method = "dkim",
        .result = "pass",
        .properties = &.{
            .{ .ptype = "header", .property = "d", .value = "example.com" },
            .{
                .ptype = testing_key_marker.ptype,
                .property = testing_key_marker.property,
                .value = testing_key_marker.value,
            },
        },
    }};

    const header = try build(std.testing.allocator, "mail.example.com", results);
    defer std.testing.allocator.free(header);

    // A testing key reports its actual DKIM verdict.
    try std.testing.expect(mem.indexOf(u8, header, "dkim=pass") != null);
    try std.testing.expect(mem.indexOf(u8, header, "header.d=example.com") != null);

    // Pin the cross-daemon wire format independently of the shared constants.
    try std.testing.expect(mem.indexOf(u8, header, "policy.dkim-rules=testing-key") != null);
}

test "D-11: the testing-key marker survives the parser that reads it" {
    // The marker crosses daemons, so it must round-trip through the parser.
    const results = &[_]MethodResult{.{
        .method = "dkim",
        .result = "pass",
        .properties = &.{
            .{ .ptype = "header", .property = "d", .value = "example.com" },
            .{
                .ptype = testing_key_marker.ptype,
                .property = testing_key_marker.property,
                .value = testing_key_marker.value,
            },
        },
    }};

    const header = try build(std.testing.allocator, "mail.example.com", results);
    defer std.testing.allocator.free(header);

    var found = false;
    var it = ResultIterator.init(header);
    while (it.next()) |method_result| {
        if (!mem.eql(u8, method_result.method, "dkim")) continue;
        try std.testing.expectEqualStrings("pass", method_result.result);

        var props = PropertyIterator{ .rest = method_result.props };
        while (props.next()) |p| {
            if (mem.eql(u8, p.name, testing_key_marker.ptype ++ "." ++ testing_key_marker.property) and
                mem.eql(u8, p.value, testing_key_marker.value))
            {
                found = true;
            }
        }
    }
    try std.testing.expect(found);
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
    // A semicolon inside a comment is not a result separator.
    const forged = "mail.example.com; dkim=fail (note; spf=pass ) header.d=a.test";

    var parsed = try parseResults(std.testing.allocator, forged);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expect(parsed.getResult("spf") == null);
    try std.testing.expectEqualStrings("fail", parsed.getResult("dkim").?);
}

test "M-6: the scrubber and the consumer agree about the comment" {
    // Scrubbing must use the same comment-aware interpretation as consumers.
    const forged = "mail.example.com; dkim=fail (note; spf=pass ) header.d=a.test";

    try std.testing.expect(!assertsAnyMethod(forged, &.{"spf"}));
    try std.testing.expect(assertsAnyMethod(forged, &.{"dkim"}));
}

test "M-6: a property belongs to its own result" {
    // Properties in comments cannot be paired with another result's verdict.
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

// Sender-controlled property values must not forge additional results.
test "a semicolon in a property value cannot open a new result group" {
    const value = try build(std.testing.allocator, "mail.example.org", &.{
        .{
            .method = "spf",
            .result = "fail",
            .properties = &.{
                .{ .ptype = "smtp", .property = "mailfrom", .value = "bambania.com" },
                .{ .ptype = "smtp", .property = "helo", .value = "x;spf=pass header.d=victim.example" },
            },
        },
    });
    defer std.testing.allocator.free(value);

    var parsed = try parseResults(std.testing.allocator, value);
    defer parsed.deinit(std.testing.allocator);

    // Counting detects the forged duplicate even when the method name matches.
    try std.testing.expectEqual(@as(usize, 1), parsed.results.items.len);
    try std.testing.expectEqualStrings("fail", parsed.results.items[0].result);

    // The value remains data and stays quoted; parsing does not unquote pvalues.
    try std.testing.expectEqualStrings(
        "\"x;spf=pass header.d=victim.example\"",
        parsed.results.items[0].property("smtp.helo").?,
    );
    try std.testing.expect(parsed.results.items[0].property("header.d") == null);
}

test "a control byte in a property value cannot end the header field" {
    // A control byte must not terminate this field and inject another.
    const value = try build(std.testing.allocator, "mail.example.org", &.{
        .{
            .method = "dkim",
            .result = "pass",
            .properties = &.{
                .{ .ptype = "header", .property = "d", .value = "a\r\nX-Injected: yes" },
            },
        },
    });
    defer std.testing.allocator.free(value);

    // `build` adds only its own folding CRLF.
    try std.testing.expectEqual(@as(usize, 1), mem.count(u8, value, "\r\n"));
    try std.testing.expect(mem.indexOf(u8, value, "\r\nX-Injected") == null);
}

test "a quote in a property value cannot end the quoted string" {
    const value = try build(std.testing.allocator, "mail.example.org", &.{
        .{
            .method = "dkim",
            .result = "pass",
            .properties = &.{
                .{ .ptype = "header", .property = "d", .value = "a\" b;dkim=pass" },
            },
        },
    });
    defer std.testing.allocator.free(value);

    var parsed = try parseResults(std.testing.allocator, value);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.results.items.len);
}

test "ordinary values are still emitted bare" {
    // Common emitted values retain their standard unquoted representation.
    const value = try build(std.testing.allocator, "mail.example.org", &.{
        .{
            .method = "dkim",
            .result = "pass",
            .properties = &.{
                .{ .ptype = "header", .property = "d", .value = "example.com" },
                .{ .ptype = "header", .property = "s", .value = "sel-2026_1" },
                .{ .ptype = "smtp", .property = "mailfrom", .value = "user@example.com" },
            },
        },
    });
    defer std.testing.allocator.free(value);

    try std.testing.expect(mem.indexOfScalar(u8, value, '"') == null);
    try std.testing.expect(mem.indexOf(u8, value, "header.d=example.com") != null);
    try std.testing.expect(mem.indexOf(u8, value, "smtp.mailfrom=user@example.com") != null);
}

test "a reason comment cannot escape its parentheses" {
    const value = try build(std.testing.allocator, "mail.example.org", &.{
        .{
            .method = "spf",
            .result = "pass",
            .reason = "client is ) evil; spf=fail",
            .properties = &.{},
        },
    });
    defer std.testing.allocator.free(value);

    var parsed = try parseResults(std.testing.allocator, value);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.results.items.len);
    try std.testing.expectEqualStrings("pass", parsed.results.items[0].result);
}
