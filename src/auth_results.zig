const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

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

/// Parse an Authentication-Results header to extract method results.
///
/// This is a simplified parser that extracts method=result pairs.
/// Used by SecureDMARC to read SPF and DKIM results from upstream milters.
pub fn parseResults(allocator: Allocator, header_value: []const u8) !ParsedHeader {
    var parsed = ParsedHeader{
        .authserv_id = "",
        .results = .{},
    };

    const trimmed = mem.trimLeft(u8, header_value, &std.ascii.whitespace);
    const first_semi = mem.indexOfScalar(u8, trimmed, ';') orelse {
        parsed.authserv_id = trimmed;
        return parsed;
    };

    parsed.authserv_id = mem.trim(u8, trimmed[0..first_semi], &std.ascii.whitespace);

    var rest = trimmed[first_semi + 1 ..];
    while (rest.len > 0) {
        rest = mem.trimLeft(u8, rest, &std.ascii.whitespace);
        if (rest.len == 0) break;

        const eq_pos = mem.indexOfScalar(u8, rest, '=') orelse break;
        const method = mem.trim(u8, rest[0..eq_pos], &std.ascii.whitespace);

        rest = rest[eq_pos + 1 ..];

        const next_semi = mem.indexOfScalar(u8, rest, ';');
        const result_part = if (next_semi) |s| rest[0..s] else rest;
        rest = if (next_semi) |s| rest[s + 1 ..] else "";

        const result_trimmed = mem.trim(u8, result_part, &std.ascii.whitespace);
        const result_end = mem.indexOfAny(u8, result_trimmed, &.{ ' ', '\t', '(' }) orelse result_trimmed.len;
        const result_value = result_trimmed[0..result_end];

        if (method.len > 0 and result_value.len > 0) {
            try parsed.results.append(allocator, .{
                .method = method,
                .result = result_value,
            });
        }
    }

    return parsed;
}

pub const ParsedHeader = struct {
    authserv_id: []const u8,
    results: std.ArrayList(ParsedResult),

    pub const ParsedResult = struct {
        method: []const u8,
        result: []const u8,
    };

    pub fn deinit(self: *ParsedHeader, allocator: Allocator) void {
        self.results.deinit(allocator);
    }

    pub fn getResult(self: *const ParsedHeader, method: []const u8) ?[]const u8 {
        for (self.results.items) |r| {
            if (mem.eql(u8, r.method, method)) return r.result;
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

test "build none" {
    const header = try buildNone(std.testing.allocator, "mail.example.com");
    defer std.testing.allocator.free(header);
    try std.testing.expectEqualStrings("mail.example.com; none", header);
}
