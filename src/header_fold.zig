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
    /// `separator` is written before `text` on the same line when no fold
    /// happens, and dropped when one does -- the fold supplies the whitespace.
    pub fn append(self: *Folder, separator: []const u8, text: []const u8) !void {
        if (self.column + separator.len + text.len > self.limit and self.column > 1) {
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

test "longestLine measures without the CRLF" {
    try std.testing.expectEqual(@as(usize, 5), longestLine("abcde"));
    try std.testing.expectEqual(@as(usize, 5), longestLine("abcde\r\n"));
    try std.testing.expectEqual(@as(usize, 5), longestLine("ab\r\nabcde\r\nx"));
}
