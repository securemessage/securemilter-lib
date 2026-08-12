//! RFC 5322 header folding for generated header field bodies.
//!
//! RFC 5322 §2.1.1 sets two limits on a line, excluding the CRLF: it "MUST be
//! no more than 998 characters, and SHOULD be no more than 78". A generated
//! DKIM-Signature or Authentication-Results field runs past both without help:
//! an RSA-4096 signature alone is 736 base64 characters, so the MUST is
//! reachable, not merely the SHOULD.
//!
//! §2.2.3 gives the mechanism: "wherever this specification allows for folding
//! white space ... a CRLF may be inserted before any WSP". This module inserts
//! CRLF + TAB at points the caller declares safe.
//!
//! WHAT MAKES THIS SAFE INSIDE A SIGNATURE. Folding changes bytes, and a DKIM
//! or ARC signature covers its own header field, so the rule is that whatever
//! is hashed must be the bytes that are emitted. Two things make that hold:
//!
//!   - the b= and bh= values are exempt by specification. RFC 6376 §3.5 says of
//!     each that "Whitespace is ignored in this value and MUST be ignored when
//!     reassembling the original signature. In particular, the signing process
//!     can safely insert FWS in this value in arbitrary places to conform to
//!     line-length limits."
//!   - everywhere else, the signer folds ONCE and hashes the folded form. Under
//!     relaxed header canonicalization the folding is unfolded away again
//!     (RFC 6376 §3.4.2); under simple it is hashed literally, which still
//!     verifies because the verifier reads back the same bytes.
//!
//! The caller therefore must build the folded value first and hash that, never
//! fold a value that has already been signed.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cfws = @import("cfws.zig");

/// RFC 5322 §2.1.1 SHOULD. The target this module folds to.
pub const SOFT_LIMIT: usize = 78;

/// RFC 5322 §2.1.1 MUST. Never exceeded for a value built through here.
pub const HARD_LIMIT: usize = 998;

/// Continuation prefix. A single TAB, which is WSP, so the fold is legal FWS
/// and unfolding restores the original single logical line.
const CONTINUATION = "\r\n\t";

/// Appends a header field body, folding it to stay inside the line limits.
///
/// Tracks the current column so the caller does not have to. Start it with the
/// field name's own width, because "DKIM-Signature:" occupies the first line
/// too and the limit applies to the whole line, not to the body alone.
pub const Folder = struct {
    buf: *std.ArrayList(u8),
    allocator: Allocator,
    /// Characters already on the current line, including the field name.
    column: usize,
    limit: usize = SOFT_LIMIT,

    pub fn init(
        buf: *std.ArrayList(u8),
        allocator: Allocator,
        field_name_len: usize,
    ) Folder {
        return .{ .buf = buf, .allocator = allocator, .column = field_name_len };
    }

    /// Write `text` on the current line, or on a fresh continuation line when it
    /// would not fit. `text` is never split; use `appendChunked` for a value
    /// that may exceed a whole line on its own.
    ///
    /// `separator` precedes `text`. When a fold happens its WHITESPACE is
    /// replaced by the fold, but any non-whitespace is still emitted first.
    ///
    /// That distinction is the whole correctness of this function. A separator
    /// like "; " carries syntax, and an earlier version dropped it wholesale on
    /// folding, which silently deleted the semicolon between two DKIM tags:
    /// `d=example.com` and `s=sel` merged into one malformed tag, the b= value
    /// parsed as empty, and every signature failed its own verification with
    /// permerror. The fold supplies whitespace, never punctuation.
    pub fn append(self: *Folder, separator: []const u8, text: []const u8) !void {
        if (self.column + separator.len + text.len > self.limit and self.column > 1) {
            const syntax = std.mem.trimRight(u8, separator, " \t");
            try self.buf.appendSlice(self.allocator, syntax);
            try self.buf.appendSlice(self.allocator, CONTINUATION);
            self.column = 1; // the TAB
        } else {
            try self.buf.appendSlice(self.allocator, separator);
            self.column += separator.len;
        }
        try self.buf.appendSlice(self.allocator, text);
        self.column += text.len;
    }

    /// Write a value that may be longer than a line, splitting it across as many
    /// continuation lines as it needs.
    ///
    /// Only for values whose internal whitespace is insignificant: the base64 of
    /// b= and bh=, which RFC 6376 §3.5 exempts explicitly. Splitting anything
    /// else changes its meaning.
    pub fn appendChunked(self: *Folder, text: []const u8) !void {
        var rest = text;
        while (rest.len > 0) {
            if (self.column >= self.limit and self.column > 1) {
                try self.buf.appendSlice(self.allocator, CONTINUATION);
                self.column = 1;
            }
            const room = self.limit - @min(self.column, self.limit - 1);
            const take = @min(room, rest.len);
            try self.buf.appendSlice(self.allocator, rest[0..take]);
            self.column += take;
            rest = rest[take..];
        }
    }

    /// End the line unconditionally: emit `separator`'s punctuation, then the
    /// continuation prefix. This is `append` with the fit test removed, for a
    /// value whose layout convention fixes some fold points regardless of
    /// length — Authentication-Results puts one method per line.
    pub fn breakLine(self: *Folder, separator: []const u8) !void {
        const syntax = std.mem.trimRight(u8, separator, " \t");
        try self.buf.appendSlice(self.allocator, syntax);
        try self.buf.appendSlice(self.allocator, CONTINUATION);
        self.column = 1; // the TAB
    }

    /// Write a structured value (tag lists, Authentication-Results bodies),
    /// folding before whichever token would cross the limit.
    ///
    /// `text` is split at its whitespace runs; each maximal non-whitespace run
    /// is one token except that a comment and a quoted string are each indivisible —
    /// a fold must never land inside either. A whitespace run that survives
    /// becomes exactly one space, so a value inherited from an earlier
    /// emission (already folded, at columns right for its old field name) is
    /// unfolded and refolded by the same call. As everywhere in this module, a
    /// fold replaces whitespace but never deletes punctuation: a `;` abutting
    /// a token stays abutting it.
    pub fn appendStructured(self: *Folder, separator: []const u8, text: []const u8) !void {
        var i: usize = 0;
        var first = true;
        while (i < text.len) {
            var wsp_end = i;
            while (wsp_end < text.len and std.ascii.isWhitespace(text[wsp_end])) wsp_end += 1;
            if (wsp_end == text.len) break; // trailing whitespace carries no token
            const sep: []const u8 = if (first) separator else if (wsp_end > i) " " else "";
            i = wsp_end;

            // tokenEnd skips a quoted string but stops at a comment start, so
            // the comment case is taken explicitly.
            const tok_end = if (text[i] == '(') cfws.skipComment(text, i) else cfws.tokenEnd(text, i, "");
            try self.append(sep, text[i..tok_end]);
            i = tok_end;
            first = false;
        }
    }
};

/// Longest line in `text`, excluding CRLF. For asserting the limits.
pub fn longestLine(text: []const u8) usize {
    var longest: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trimRight(u8, line, "\r");
        longest = @max(longest, trimmed.len);
    }
    return longest;
}

// =============================================================================
// Tests
// =============================================================================

test "a short value is not folded at all" {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(std.testing.allocator);

    var f = Folder.init(&buf, std.testing.allocator, "X-Test:".len);
    try f.append(" ", "v=1");
    try f.append(";", " a=rsa-sha256");

    try std.testing.expectEqualStrings(" v=1; a=rsa-sha256", buf.items);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\r\n") == null);
}

test "a token that would pass the limit moves to a continuation line" {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(std.testing.allocator);

    var f = Folder.init(&buf, std.testing.allocator, "DKIM-Signature:".len);
    try f.append(" ", "v=1");
    try f.append(";", " d=a-fairly-long-domain-name.example.com");
    try f.append(";", " s=a-selector-that-pushes-past-seventy-eight");

    try std.testing.expect(std.mem.indexOf(u8, buf.items, CONTINUATION) != null);
    // Every line, counting the field name on the first, stays inside the SHOULD.
    const whole = try std.mem.concat(std.testing.allocator, u8, &.{ "DKIM-Signature:", buf.items });
    defer std.testing.allocator.free(whole);
    try std.testing.expect(longestLine(whole) <= SOFT_LIMIT);
}

test "a value longer than a whole line is split across continuations" {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(std.testing.allocator);

    // 736 characters: an RSA-4096 signature, the case that reaches the MUST.
    const b64 = "A" ** 736;
    var f = Folder.init(&buf, std.testing.allocator, "DKIM-Signature:".len);
    try f.append(" ", "b=");
    try f.appendChunked(b64);

    const whole = try std.mem.concat(std.testing.allocator, u8, &.{ "DKIM-Signature:", buf.items });
    defer std.testing.allocator.free(whole);

    try std.testing.expect(longestLine(whole) <= SOFT_LIMIT);
    try std.testing.expect(longestLine(whole) <= HARD_LIMIT);

    // Every base64 character survives, in order: whitespace is ignored on the
    // way back in, but nothing may be lost or reordered.
    var recovered: std.ArrayList(u8) = .{};
    defer recovered.deinit(std.testing.allocator);
    for (buf.items) |ch| {
        if (ch != '\r' and ch != '\n' and ch != '\t') try recovered.append(std.testing.allocator, ch);
    }
    // The leading separator is part of the emitted body, hence " b=".
    try std.testing.expectEqualStrings(" b=" ++ b64, recovered.items);
}

test "unfolding a folded value restores one logical line" {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(std.testing.allocator);

    var f = Folder.init(&buf, std.testing.allocator, "DKIM-Signature:".len);
    try f.append(" ", "v=1");
    try f.append(";", " h=from:to:subject:date:message-id:reply-to:cc:sender:mime-version");
    try f.append(";", " bh=" ++ "B" ** 44);
    try f.append(";", " b=");
    try f.appendChunked("C" ** 344);

    // RFC 5322 unfolding: remove a CRLF that precedes WSP.
    var unfolded: std.ArrayList(u8) = .{};
    defer unfolded.deinit(std.testing.allocator);
    var i: usize = 0;
    while (i < buf.items.len) {
        if (i + 2 < buf.items.len and buf.items[i] == '\r' and buf.items[i + 1] == '\n' and
            (buf.items[i + 2] == ' ' or buf.items[i + 2] == '\t'))
        {
            i += 2; // drop CRLF, keep the WSP
            continue;
        }
        try unfolded.append(std.testing.allocator, buf.items[i]);
        i += 1;
    }

    // No CRLF survives, and the tags are intact and in order.
    try std.testing.expect(std.mem.indexOf(u8, unfolded.items, "\r\n") == null);
    try std.testing.expect(std.mem.indexOf(u8, unfolded.items, "v=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, unfolded.items, "b=") != null);
    try std.testing.expect(std.mem.indexOf(u8, unfolded.items, "bh=") != null);
}

/// RFC 5322 unfolding: remove a CRLF that precedes WSP.
fn testUnfold(allocator: Allocator, folded: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .{};
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < folded.len) {
        if (i + 2 < folded.len and folded[i] == '\r' and folded[i + 1] == '\n' and
            (folded[i + 2] == ' ' or folded[i + 2] == '\t'))
        {
            i += 2;
            continue;
        }
        try out.append(allocator, folded[i]);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

test "folding is lossless: unfolding restores the unfolded form exactly" {
    // THE INVARIANT THAT MATTERS, and the one whose absence let a dropped
    // semicolon reach the lab. Every earlier test here asserted line lengths and
    // that a fold had occurred -- both of which a corrupted value satisfies.
    const allocator = std.testing.allocator;

    const tags = [_]struct { sep: []const u8, text: []const u8 }{
        .{ .sep = " ", .text = "v=1" },
        .{ .sep = "; ", .text = "a=rsa-sha256" },
        .{ .sep = "; ", .text = "c=relaxed/relaxed" },
        .{ .sep = "; ", .text = "d=a-domain-long-enough-to-force-a-fold.example.com" },
        .{ .sep = "; ", .text = "s=test2026" },
        .{ .sep = "; ", .text = "h=from:to:subject:date:message-id:reply-to:cc" },
        .{ .sep = "; ", .text = "t=1786521741" },
    };

    var folded_buf: std.ArrayList(u8) = .{};
    defer folded_buf.deinit(allocator);
    var plain: std.ArrayList(u8) = .{};
    defer plain.deinit(allocator);

    var f = Folder.init(&folded_buf, allocator, "DKIM-Signature:".len);
    for (tags) |t| {
        try f.append(t.sep, t.text);
        try plain.appendSlice(allocator, t.sep);
        try plain.appendSlice(allocator, t.text);
    }

    // It must actually have folded, or the test proves nothing.
    try std.testing.expect(std.mem.indexOf(u8, folded_buf.items, CONTINUATION) != null);

    const unfolded = try testUnfold(allocator, folded_buf.items);
    defer allocator.free(unfolded);

    // Unfolding leaves the TAB the fold introduced where the separator's space
    // used to be, so compare with whitespace runs normalised to one space.
    const norm_a = try normalizeWsp(allocator, unfolded);
    defer allocator.free(norm_a);
    const norm_b = try normalizeWsp(allocator, plain.items);
    defer allocator.free(norm_b);
    try std.testing.expectEqualStrings(norm_b, norm_a);

    // Specifically: every semicolon survived. Six separators, six semicolons.
    var semicolons: usize = 0;
    for (unfolded) |ch| {
        if (ch == ';') semicolons += 1;
    }
    try std.testing.expectEqual(@as(usize, 6), semicolons);
}

fn normalizeWsp(allocator: Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .{};
    errdefer out.deinit(allocator);
    var in_wsp = false;
    for (text) |ch| {
        const is_wsp = ch == ' ' or ch == '\t';
        if (is_wsp) {
            if (!in_wsp) try out.append(allocator, ' ');
        } else {
            try out.append(allocator, ch);
        }
        in_wsp = is_wsp;
    }
    return out.toOwnedSlice(allocator);
}

test "breakLine folds regardless of fit" {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(std.testing.allocator);

    var f = Folder.init(&buf, std.testing.allocator, "Authentication-Results:".len + 1);
    try f.append("", "mail.example.org");
    try f.breakLine(";");
    try f.append("", "spf=pass");

    try std.testing.expectEqualStrings("mail.example.org;\r\n\tspf=pass", buf.items);
}

test "appendStructured folds at token boundaries and loses nothing" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(allocator);

    const text = "spf=pass smtp.mailfrom=a-rather-long-domain-name.example.com " ++
        "smtp.helo=another.long-hostname.example.org";
    var f = Folder.init(&buf, allocator, "Authentication-Results:".len + 1);
    try f.appendStructured("", text);

    // It folded, and every line counting the field name stays inside the SHOULD.
    try std.testing.expect(std.mem.indexOf(u8, buf.items, CONTINUATION) != null);
    const whole = try std.mem.concat(allocator, u8, &.{ "Authentication-Results: ", buf.items });
    defer allocator.free(whole);
    try std.testing.expect(longestLine(whole) <= SOFT_LIMIT);

    // Fold, unfold, compare with runs of whitespace normalised: equal, and the
    // semicolon count survives — the invariant whose absence once let a
    // swallowed separator reach the lab.
    const unfolded = try testUnfold(allocator, buf.items);
    defer allocator.free(unfolded);
    const norm_a = try normalizeWsp(allocator, unfolded);
    defer allocator.free(norm_a);
    const norm_b = try normalizeWsp(allocator, text);
    defer allocator.free(norm_b);
    try std.testing.expectEqualStrings(norm_b, norm_a);
}

test "appendStructured refolds an already-folded value at the new columns" {
    // A value inherited from an earlier emission — folded for a narrower field
    // name — unfolds and refolds for this one rather than keeping folds that
    // no longer land inside the limit.
    const allocator = std.testing.allocator;
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(allocator);

    const inherited = "mail.example.org;\r\n\tspf=pass smtp.mailfrom=a-rather-long-domain.example.com;\r\n\tdkim=pass header.d=a-rather-long-domain.example.com";
    var f = Folder.init(&buf, allocator, "ARC-Authentication-Results:".len + 1);
    try f.appendStructured("i=1; ", inherited);

    const whole = try std.mem.concat(allocator, u8, &.{ "ARC-Authentication-Results: ", buf.items });
    defer allocator.free(whole);
    try std.testing.expect(longestLine(whole) <= SOFT_LIMIT);

    const unfolded = try testUnfold(allocator, buf.items);
    defer allocator.free(unfolded);
    const norm_a = try normalizeWsp(allocator, unfolded);
    defer allocator.free(norm_a);
    try std.testing.expectEqualStrings(
        "i=1; mail.example.org; spf=pass smtp.mailfrom=a-rather-long-domain.example.com; dkim=pass header.d=a-rather-long-domain.example.com",
        norm_a,
    );
    // Every semicolon survived: three separators in, three out.
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, unfolded, ";"));
}

test "appendStructured never splits a comment or a quoted string" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(allocator);

    const text = "dmarc=fail (p=reject and a reason long enough to matter) header.from=\"a quoted; value with spaces.example\"";
    var f = Folder.init(&buf, allocator, "Authentication-Results:".len + 1);
    try f.appendStructured("", text);

    try std.testing.expect(std.mem.indexOf(u8, buf.items, CONTINUATION) != null);

    // Both indivisible tokens survive whole and in order, however the lines
    // fell around them.
    const unfolded = try testUnfold(allocator, buf.items);
    defer allocator.free(unfolded);
    const norm = try normalizeWsp(allocator, unfolded);
    defer allocator.free(norm);
    try std.testing.expectEqualStrings(text, norm);
}

test "longestLine measures without the CRLF" {
    try std.testing.expectEqual(@as(usize, 5), longestLine("abcde"));
    try std.testing.expectEqual(@as(usize, 5), longestLine("abcde\r\n"));
    try std.testing.expectEqual(@as(usize, 5), longestLine("ab\r\nabcde\r\nx"));
}
