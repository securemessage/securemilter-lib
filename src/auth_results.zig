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

/// The marker `securedkim` puts on a result from a key published `t=y`, and that
/// `securedmarc` refuses to count as an aligned pass (audit D-11).
///
/// RFC 6376 §3.6.1 requires that verifiers "MUST NOT treat messages from Signers
/// in testing mode differently from unsigned email", while also allowing that
/// "Verifiers MAY wish to track testing mode results to assist the Signer". Those
/// pull in opposite directions only if the result and the action are conflated.
/// The result is reported truthfully -- a signer publishes a testing key precisely
/// to learn whether it verifies, and `dkim=none` would withhold the one fact they
/// asked for -- and the *action* is suppressed instead.
///
/// OpenDKIM draws the line in the same place, and its A-R output was checked
/// rather than assumed: `dkimf_ar_all_sigs` never consults `DKIM_SIGFLAG_TESTKEY`,
/// so a test key is reported as a plain `dkim=pass` with no annotation whatever.
/// The flag is read in exactly two places, both of which skip the signature when
/// choosing a domain for *reputation*. Result reported, action suppressed.
///
/// We need the marker OpenDKIM does without because the boundary is different.
/// Its reputation code is in-process and reads `DKIM_SIGINFO` flags directly;
/// `securedmarc` is a separate daemon whose only input is this header, so the fact
/// has to survive serialization or it does not reach the code that must act on it.
///
/// RFC 8601 §2.4 defines exactly this mechanism -- the `policy` ptype indicates
/// "some local policy mechanism was applied that augments or even replaces ... the
/// result returned by the authentication mechanism" -- and its worked example is
/// nearly ours: `dkim=policy policy.dkim-rules=unsigned-subject`. It notes these
/// are "arbitrary names selected by (and presumably used within) the ADMD", not
/// registered with IANA. We augment rather than replace, which §2.4's "augments or
/// even replaces" permits, because replacing would discard the real result.
///
/// Safe for anyone else's parser: §2.3 says "Results reported using unknown ptypes
/// MUST NOT be used in making handling decisions. They can be safely ignored."
///
/// One definition, referenced by both daemons. Two hand-typed copies is how the
/// four daemons came to disagree about the space after a colon.
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
/// RFC 8601 §2.2 gives `pvalue` as an RFC 2045 `value` (token / quoted-string) or
/// an address/domain. The set below is the intersection that needs no quoting and
/// still covers every legitimate value we emit -- domains, addresses and
/// selectors. Everything else, `;` and SP included, gets quoted.
fn isPvalueSafe(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        '-', '.', '_', '@' => true,
        else => false,
    };
}

/// Write one `pvalue`, quoting it when it cannot stand bare.
///
/// THE VALUES REACHING HERE ARE CHOSEN BY THE SENDER: `smtp.helo` is the SMTP
/// HELO string verbatim, `smtp.mailfrom` comes off the envelope, and
/// `header.d`/`header.s` are tags lifted from a DKIM-Signature. Appended raw --
/// as they were -- a `;` closed our result group and opened one of the sender's,
/// inside a header carrying our own authserv-id and written after the X-1
/// scrubber had already run. Measured against the lab, not reasoned about:
/// `HELO x;spf=pass header.d=victim.example` was delivered as
/// `spf=fail ... smtp.helo=x;spf=pass header.d=victim.example`, and through the
/// relay that text ended up inside the AAR, under the seal. Postfix rewrites both
/// the `;` and the space to `?` in Received while handing the milter the original
/// string, which is why nothing downstream of us ever showed it.
///
/// Quoting rather than stripping: a quoted-string is what the grammar already
/// provides for, `parseResults` has always read one, and it keeps the operator's
/// diagnostic -- the odd HELO stays legible instead of being silently mangled.
///
/// Control bytes are replaced, never merely quoted. CR and LF are illegal inside
/// a quoted-string and would end the header field outright; X-5 established that
/// header-derived values reach a milter with bare-LF folding intact, so this is a
/// reachable path to injecting a whole header rather than a stray token.
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

/// Write comment text, keeping it inside its parentheses.
///
/// Every `reason` we pass today is one of our own literals, so nothing here is
/// sender-chosen yet. It is escaped anyway because the parenthesis is one
/// unbalanced character away from being the same defect as `appendPvalue`
/// documents, and the next caller to pass a sender-derived reason will not think
/// to check.
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

    // The real result survives. `dkim=none` here would withhold from the signer
    // the single fact a testing key is published to establish.
    try std.testing.expect(mem.indexOf(u8, header, "dkim=pass") != null);
    try std.testing.expect(mem.indexOf(u8, header, "header.d=example.com") != null);

    // The exact octets `securedmarc` matches on. Pinned as a literal rather than
    // built from the constants: a test assembled from the same constants as the
    // code would still pass if someone renamed the property, and the whole point
    // of this string is that two separate daemons agree on it.
    try std.testing.expect(mem.indexOf(u8, header, "policy.dkim-rules=testing-key") != null);
}

test "D-11: the testing-key marker survives the parser that reads it" {
    // The producing side is only half of it. This marker crosses a process
    // boundary, so what matters is that the parser on the far side recovers the
    // same ptype/property/value -- if the emitted form did not round-trip,
    // securedkim would be marking results that securedmarc could never see.
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
            // The iterator hands back the whole `ptype.property` token as `name`,
            // so that is what the far side has to compare against.
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

// A sender-chosen property value must not be able to forge a result.
//
// The lab payload, verbatim: `HELO x;spf=pass header.d=victim.example`. Both the
// semicolon and the space reach the milter -- Postfix rewrites them to `?` in
// Received, which is why this never showed downstream -- and appended raw they
// closed our `spf=fail` group and opened one of the sender's, inside a header
// carrying our own authserv-id. `spf` is the method used here on purpose: the
// X-1 scrubber in each daemon removes only the methods that daemon produces, and
// securespf's has already run by the time it stamps, so nothing downstream
// removes it. Delivered intact, and through the relay it landed inside the AAR
// under the ARC seal.
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

    // One group, not two. The forged one would also be an `spf`, so counting is
    // what catches it -- `getResult("spf")` returns the first either way.
    try std.testing.expectEqual(@as(usize, 1), parsed.results.items.len);
    try std.testing.expectEqualStrings("fail", parsed.results.items[0].result);

    // And the payload survives as data: still one property, still the whole
    // string, so an operator reading the header sees the odd HELO rather than a
    // silently truncated one.
    //
    // Returned WITH its quotes, because `property` hands back the pvalue as it
    // appears rather than unquoting it. That is the safe direction and is left
    // alone deliberately: a quoted value can only fail to match a domain it is
    // compared against, never match one it should not, so alignment cannot be
    // talked into a pass by quoting. Unquoting here would be more faithful to
    // RFC 8601 and is a separate change with its own alignment analysis.
    try std.testing.expectEqualStrings(
        "\"x;spf=pass header.d=victim.example\"",
        parsed.results.items[0].property("smtp.helo").?,
    );
    // Nothing acquired a domain it was not given.
    try std.testing.expect(parsed.results.items[0].property("header.d") == null);
}

test "a control byte in a property value cannot end the header field" {
    // Reachable per X-5: header-derived values arrive with bare-LF folding
    // intact, and securedkim puts a signature's `d=` into `header.d`. A raw LF
    // here would terminate the field and make the rest a new header.
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

    // The only CRLF in the output is the one `build` folds with.
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
    // The quoting must not fire on the values we actually emit, or every A-R in
    // production changes shape and the diff hides the one case that matters.
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
