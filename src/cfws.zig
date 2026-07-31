const std = @import("std");
const mem = std.mem;

/// RFC 5322 lexical structure: comments and quoted strings.
///
/// Structured header fields are not flat text. A `;` inside a comment or a
/// quoted string is ordinary data, not a separator, and a parser that scans
/// with `indexOfScalar` cannot tell the difference. That mattered in the
/// `Authentication-Results` parser (audit M-6): a comment containing
/// `; spf=pass` was read as a genuine SPF result, and a `header.d=` written
/// inside a comment on one method was picked up as the property of another.
///
/// The scanners here are shared so that every consumer of a structured field
/// agrees on where the tokens are. That agreement is load-bearing for the X-1
/// forged-header removal, which is only sound while the code deciding *whether
/// to strip* sees exactly what the code *reading the value* sees.
/// Advance past folding whitespace and complete comments, including nested
/// ones. Returns the index of the first character that is neither.
///
/// An unterminated comment consumes the remainder: the alternative is to treat
/// its contents as live tokens, which is precisely the confusion being removed.
pub fn skip(s: []const u8, start: usize) usize {
    var i = start;
    while (i < s.len) {
        switch (s[i]) {
            ' ', '\t', '\r', '\n' => i += 1,
            '(' => i = skipComment(s, i),
            else => return i,
        }
    }
    return i;
}

/// Index just past the comment beginning at `s[start] == '('`.
fn skipComment(s: []const u8, start: usize) usize {
    var i = start;
    var depth: usize = 0;
    while (i < s.len) : (i += 1) {
        switch (s[i]) {
            '\\' => i += 1, // quoted-pair: the next octet is data, even ')'
            '(' => depth += 1,
            ')' => {
                // Guarded rather than `depth -= 1`: every call site enters on a
                // '(' so depth is at least 1, but this runs on attacker bytes
                // and an underflow panic in ReleaseSafe would be a denial of
                // service earned by a single stray parenthesis.
                if (depth <= 1) return i + 1;
                depth -= 1;
            },
            else => {},
        }
    }
    return s.len;
}

/// Index just past the quoted string beginning at `s[start] == '"'`.
fn skipQuoted(s: []const u8, start: usize) usize {
    var i = start + 1;
    while (i < s.len) : (i += 1) {
        switch (s[i]) {
            '\\' => i += 1,
            '"' => return i + 1,
            else => {},
        }
    }
    return s.len;
}

/// Index of the first `needle` that is real syntax — not inside a comment or a
/// quoted string — at or after `start`.
pub fn indexOfScalar(s: []const u8, start: usize, needle: u8) ?usize {
    var i = start;
    while (i < s.len) {
        const c = s[i];
        if (c == needle) return i;
        switch (c) {
            '(' => i = skipComment(s, i),
            '"' => i = skipQuoted(s, i),
            else => i += 1,
        }
    }
    return null;
}

/// Index of the first byte in `set` that is real syntax, at or after `start`.
pub fn indexOfAny(s: []const u8, start: usize, set: []const u8) ?usize {
    var i = start;
    while (i < s.len) {
        const c = s[i];
        if (mem.indexOfScalar(u8, set, c) != null) return i;
        switch (c) {
            '(' => i = skipComment(s, i),
            '"' => i = skipQuoted(s, i),
            else => i += 1,
        }
    }
    return null;
}

/// End of the token starting at `start`: the first real-syntax character that
/// is whitespace, a comment, or one of `stop`.
pub fn tokenEnd(s: []const u8, start: usize, stop: []const u8) usize {
    var i = start;
    while (i < s.len) {
        const c = s[i];
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n' or c == '(') return i;
        if (mem.indexOfScalar(u8, stop, c) != null) return i;
        if (c == '"') {
            i = skipQuoted(s, i);
            continue;
        }
        i += 1;
    }
    return i;
}

/// Remove the surrounding quotes from a quoted string and undo quoted-pairs.
/// Returns the input unchanged when it is not quoted, so callers can apply it
/// unconditionally. Allocates only when unescaping is actually required.
pub fn unquote(allocator: mem.Allocator, s: []const u8) !struct { value: []const u8, owned: bool } {
    if (s.len < 2 or s[0] != '"' or s[s.len - 1] != '"') return .{ .value = s, .owned = false };
    const inner = s[1 .. s.len - 1];
    if (mem.indexOfScalar(u8, inner, '\\') == null) return .{ .value = inner, .owned = false };

    var out = try std.ArrayListUnmanaged(u8).initCapacity(allocator, inner.len);
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < inner.len) : (i += 1) {
        if (inner[i] == '\\' and i + 1 < inner.len) i += 1;
        out.appendAssumeCapacity(inner[i]);
    }
    return .{ .value = try out.toOwnedSlice(allocator), .owned = true };
}

// =============================================================================
// Tests
// =============================================================================

test "skip passes over whitespace and comments" {
    try std.testing.expectEqual(@as(usize, 0), skip("abc", 0));
    try std.testing.expectEqual(@as(usize, 3), skip("   abc", 0));
    try std.testing.expectEqual(@as(usize, 8), skip(" (note) abc", 0));
    // Nested comments are one comment.
    try std.testing.expectEqual(@as(usize, 11), skip("((a(b)c)d) xy", 0));
    // Unterminated comment swallows the rest rather than exposing its contents.
    try std.testing.expectEqual(@as(usize, 8), skip(" (a; b=c", 0));
}

test "a semicolon inside a comment is not a separator" {
    const s = "dkim=fail (note; spf=pass ) ; dmarc=none";
    const semi = indexOfScalar(s, 0, ';').?;
    try std.testing.expectEqual(@as(usize, 28), semi);
    try std.testing.expectEqualStrings(" dmarc=none", s[semi + 1 ..]);
}

test "a semicolon inside a quoted string is not a separator" {
    const s = "header.d=\"a;b\"; dkim=pass";
    const semi = indexOfScalar(s, 0, ';').?;
    try std.testing.expectEqual(@as(usize, 14), semi);
}

test "an escaped paren does not close a comment" {
    // The ')' is quoted, so the comment runs to the real one.
    const s = "a (note \\) still; inside) ; b";
    const semi = indexOfScalar(s, 0, ';').?;
    try std.testing.expectEqual(@as(usize, 26), semi);
}

test "tokenEnd stops at whitespace, comments and stop bytes" {
    try std.testing.expectEqual(@as(usize, 4), tokenEnd("pass more", 0, ";"));
    try std.testing.expectEqual(@as(usize, 4), tokenEnd("pass(c)", 0, ";"));
    try std.testing.expectEqual(@as(usize, 4), tokenEnd("pass;x", 0, ";"));
    // A quoted string is one token even though it contains spaces.
    try std.testing.expectEqual(@as(usize, 8), tokenEnd("\"a b c\"x", 0, ";"));
}

test "unquote" {
    const a = try unquote(std.testing.allocator, "plain");
    try std.testing.expect(!a.owned);
    try std.testing.expectEqualStrings("plain", a.value);

    const b = try unquote(std.testing.allocator, "\"quoted\"");
    try std.testing.expect(!b.owned);
    try std.testing.expectEqualStrings("quoted", b.value);

    const c = try unquote(std.testing.allocator, "\"a\\\"b\"");
    defer if (c.owned) std.testing.allocator.free(c.value);
    try std.testing.expect(c.owned);
    try std.testing.expectEqualStrings("a\"b", c.value);
}
