//! Turning a message *file* into the view of a message a milter receives.
//!
//! **This exists so a conformance checker cannot model the message differently
//! from the daemon it certifies.** That is not a tidiness argument. A checker
//! that parses a file its own way still produces a score, and the score looks
//! like a statement about the product when it is a statement about the harness.
//! It has happened three times on this project, each time arriving disguised as
//! something else:
//!
//!  - the `c=simple/*` cases in the ARC validation suite, reported as a pile of
//!    product defects;
//!  - the DNS server in the DKIM suite that served key records one character at
//!    a time, likewise;
//!  - 2026-08-04, the dkimpy differential and the ARC signing suite sitting
//!    green while the path they cover was completely dead, because the fixtures
//!    wrote their key at 0644 and nothing re-ran them after the key-permission
//!    check landed.
//!
//! Before this module was promoted here there were three copies of the same
//! parser -- `securearc/msgfile.zig`, `securedkim/check.zig` and
//! `securedkim/sign_cli.zig` -- and they had already drifted: only one of them
//! could be told not to rewrite line endings, which is the switch the D-22
//! differential needs, so the other two could not have found D-22 at all. Three
//! copies is three chances to disagree with production and with each other.
//!
//! It lives in the library rather than in one daemon because it models
//! `connection.Header` and `connection.splitLeadingSpace`, which live here, and
//! because all four products' checkers must share it or the premise fails.
//!
//! The rules encoded here are deliberate models of production, each documented
//! at its site: CRLF normalisation, folding preserved, and one space dropped
//! after the colon. **Anything a milter does not do, this must not do either.**
//!
//! WHICH SUITE HAS TEETH FOR THIS FILE, measured on 2026-08-05 by forcing
//! `had_space` to false and re-running everything:
//!
//!   dkimpy differential   204 -> 93 disagree      CATCHES IT
//!   rfc6376 + 8463         26/26 still passed     blind
//!   ARC validation        171/171 still passed    blind
//!   ARC signing            17/17 still passed     blind
//!
//! So three of the four suites do not exercise the D-23 separator bit at all,
//! and only the independent verifier notices when it is dropped. That is worth
//! knowing before trusting a green run here: the unit tests in this file caught
//! it immediately (2 failures), which is the argument for pinning behaviour
//! beside the code rather than relying on the conformance totals.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const connection = @import("connection.zig");

/// The daemon's own header type, not a copy of it.
///
/// The earlier securearc copy defined its own structurally identical `Field` on
/// the grounds that the module "sits below both and should not have to pick
/// one". Here that reasoning inverts: this module sits beside `connection`, and
/// picking its type is the whole point -- `had_space` is exactly the field a
/// re-typed copy loses without saying so (audit D-23), and every consumer was
/// converting back to it anyway.
pub const Header = connection.Header;

const splitLeadingSpace = connection.splitLeadingSpace;

/// A parsed message: header fields in order, plus the body. Owns its storage.
pub const Message = struct {
    headers: []const Header,
    body: []const u8,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Message) void {
        self.arena.deinit();
    }

    /// Every field rendered back to the `Name: value` line a milter would have
    /// accumulated, in order.
    ///
    /// The round trip through name and value is the point, not an oversight: the
    /// daemon signs and verifies what the MTA hands it, so passing the file's
    /// original octets instead would exercise a byte sequence production never
    /// produces. `Header.render` is the one place that decides the separator, so
    /// a field whose colon was followed by a TAB, or by nothing, comes back
    /// verbatim rather than normalised to one space.
    ///
    /// Allocated from the message's own arena, so `deinit` is the only cleanup.
    /// Both callers previously kept a hand-rolled free loop for this, and one of
    /// them rendered the same field twice.
    pub fn rendered(self: *Message) ![]const []const u8 {
        const a = self.arena.allocator();
        const out = try a.alloc([]const u8, self.headers.len);
        for (self.headers, 0..) |hdr, i| out[i] = try hdr.render(a);
        return out;
    }
};

/// Split an RFC 5322 message into header fields and a body.
///
/// Folded values keep their line breaks. That is not a convenience: DKIM and ARC
/// `relaxed` canonicalization is defined as an operation *on* the folded form
/// (RFC 6376 §3.4.2, "Unfold all header field continuation lines"), and the
/// milter receives values from Postfix with folding intact, so unfolding here
/// would test a canonicalizer against input it never sees in production.
///
/// `normalize_eol` rewrites bare CR and bare LF to CRLF. Callers should pass
/// `true` unless they know better: a message arrives over SMTP with CRLF, both
/// canonicalizations in RFC 6376 §3.4 are specified in terms of it, and a file
/// on disk -- or a ValiMail YAML block scalar -- carries bare LF.
/// **If cases fail with a body-hash mismatch, check this first.**
///
/// It is a parameter rather than always-on because of D-22. Unlike the header
/// space-stripping below, normalisation models *nothing* the MTA does: a milter
/// receives body octets verbatim over `SMFIC_BODY`, bare CR and LF included. So
/// the default is wrong for exactly one job -- testing what body canonicalization
/// does to a bare CR or LF, which RFC 5234 says are not WSP and RFC 6376
/// therefore leaves as data. The normalisation destroys those octets before the
/// canonicalizer sees them, and D-22 was invisible until the differential suite
/// could turn it off.
pub fn parseMessage(allocator: Allocator, raw: []const u8, normalize_eol: bool) !Message {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const text = if (normalize_eol) try toCrlf(a, raw) else raw;

    // Header section ends at the first empty line. A message with no empty line
    // is all headers and an empty body.
    const sep = mem.indexOf(u8, text, "\r\n\r\n");
    const header_block = if (sep) |s| text[0..s] else text;
    const body = if (sep) |s| text[s + 4 ..] else "";

    var headers: std.ArrayListUnmanaged(Header) = .{};

    // Walk the header block, starting a new field on a line that does not begin
    // with WSP and folding the rest into the value.
    var field_start: ?usize = null;
    var i: usize = 0;
    while (i <= header_block.len) {
        const line_end = mem.indexOfPos(u8, header_block, i, "\r\n") orelse header_block.len;
        const line = header_block[i..line_end];
        const is_continuation = line.len > 0 and (line[0] == ' ' or line[0] == '\t');

        if (!is_continuation and field_start != null) {
            try appendField(a, &headers, header_block[field_start.?..i]);
            field_start = null;
        }
        if (line.len > 0 and !is_continuation) field_start = i;

        if (line_end >= header_block.len) break;
        i = line_end + 2;
    }
    if (field_start) |s| try appendField(a, &headers, header_block[s..]);

    return .{
        .headers = try headers.toOwnedSlice(a),
        .body = body,
        .arena = arena,
    };
}

/// Record one complete field, trailing CRLF trimmed, split at the first colon.
///
/// A field with no colon is skipped rather than guessed at: it is not a header
/// field, and inventing a name for it would put a fabricated entry into the list
/// the signature covers.
///
/// **The space after the colon is split off, not discarded.** A milter receives
/// header values with one leading space already removed by the MTA; the daemons
/// negotiate `SMFIP_HDR_LEADSPC` and recover the bit that says whether there was
/// one, so this models both halves — `value` as the daemon sees it, and
/// `had_space` so the field can be rebuilt verbatim for `simple`.
///
/// **Exactly one SP, and never a TAB.** D-23's open question is answered: both
/// Postfix 3.11.5 and FreeBSD base sendmail strip one leading SP if and only if
/// one is present, and leave a TAB alone (§11.40, and
/// `securemilter/measurements/d23-header-wsp/` in engineering-docs). This line
/// used to strip a leading TAB
/// as well, which no MTA does — so for `Name:<TAB>value` it handed the verifier
/// a byte sequence production never produces, in the module whose one job is to
/// predict production.
///
/// Continuation lines keep their own leading whitespace, which is also what the
/// MTA delivers.
fn appendField(
    a: Allocator,
    headers: *std.ArrayListUnmanaged(Header),
    field_raw: []const u8,
) !void {
    const field = mem.trimRight(u8, field_raw, "\r\n");
    if (field.len == 0) return;
    const colon = mem.indexOfScalar(u8, field, ':') orelse return;
    const split = splitLeadingSpace(field[colon + 1 ..]);
    try headers.append(a, .{
        .name = field[0..colon],
        .value = split.value,
        .had_space = split.had_space,
    });
}

/// Normalise CR, LF and CRLF to CRLF.
pub fn toCrlf(a: Allocator, raw: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .{};
    try out.ensureTotalCapacity(a, raw.len + raw.len / 8 + 2);
    var i: usize = 0;
    while (i < raw.len) {
        const c = raw[i];
        if (c == '\r') {
            try out.appendSlice(a, "\r\n");
            i += if (i + 1 < raw.len and raw[i + 1] == '\n') 2 else 1;
        } else if (c == '\n') {
            try out.appendSlice(a, "\r\n");
            i += 1;
        } else {
            try out.append(a, c);
            i += 1;
        }
    }
    return out.toOwnedSlice(a);
}

test "one space after the colon is removed, further whitespace is data" {
    const a = std.testing.allocator;
    var msg = try parseMessage(a, "From: a@b.c\r\nX-Two:  two spaces\r\nX-None:none\r\n\r\nbody\r\n", true);
    defer msg.deinit();

    try std.testing.expectEqual(@as(usize, 3), msg.headers.len);
    try std.testing.expectEqualStrings("a@b.c", msg.headers[0].value);
    // The second space survives, and D-23's question is now answered by
    // measurement rather than pinned as a guess: the MTA removes one, not all.
    try std.testing.expectEqualStrings(" two spaces", msg.headers[1].value);
    try std.testing.expectEqualStrings("none", msg.headers[2].value);
    try std.testing.expectEqualStrings("body\r\n", msg.body);

    // And the bit that lets `simple` rebuild the field verbatim.
    try std.testing.expect(msg.headers[0].had_space);
    try std.testing.expect(msg.headers[1].had_space);
    try std.testing.expect(!msg.headers[2].had_space);
}

test "a leading TAB is data, not a separator" {
    // Measured: neither Postfix nor sendmail strips a TAB. This parser used to,
    // which made `Name:<TAB>value` unhashable under c=simple in exactly the tool
    // that exists to predict the daemon.
    const a = std.testing.allocator;
    var msg = try parseMessage(a, "X-Tab:\tvalue\r\n\r\n", true);
    defer msg.deinit();

    try std.testing.expectEqual(@as(usize, 1), msg.headers.len);
    try std.testing.expectEqualStrings("\tvalue", msg.headers[0].value);
    try std.testing.expect(!msg.headers[0].had_space);
}

test "folding is preserved and bare LF is normalised" {
    const a = std.testing.allocator;
    var msg = try parseMessage(a, "Subject: one\n\ttwo\nFrom: x@y\n\nb\n", true);
    defer msg.deinit();

    try std.testing.expectEqual(@as(usize, 2), msg.headers.len);
    try std.testing.expectEqualStrings("one\r\n\ttwo", msg.headers[0].value);
    try std.testing.expectEqualStrings("x@y", msg.headers[1].value);
}

test "a field with no colon is skipped rather than guessed at" {
    const a = std.testing.allocator;
    var msg = try parseMessage(a, "From: a@b\r\ngarbage-no-colon\r\nTo: c@d\r\n\r\n", true);
    defer msg.deinit();

    try std.testing.expectEqual(@as(usize, 2), msg.headers.len);
    try std.testing.expectEqualStrings("From", msg.headers[0].name);
    try std.testing.expectEqualStrings("To", msg.headers[1].name);
}

// normalize_eol = false is not a convenience switch, so it is pinned rather than
// left to the one caller that passes it. D-22 was invisible for as long as every
// parser normalised unconditionally: a bare CR in the body is DATA (RFC 5234 does
// not make it WSP, RFC 6376 §3.4 therefore leaves it alone), and rewriting it
// before the canonicalizer runs destroys the only octet the case turns on.
test "normalisation off leaves a bare CR in the body as data" {
    const a = std.testing.allocator;
    const raw = "From: a@b\r\n\r\nline\rstill one line\r\n";

    var kept = try parseMessage(a, raw, false);
    defer kept.deinit();
    try std.testing.expectEqualStrings("line\rstill one line\r\n", kept.body);

    var rewritten = try parseMessage(a, raw, true);
    defer rewritten.deinit();
    try std.testing.expectEqualStrings("line\r\nstill one line\r\n", rewritten.body);
}

test "rendered fields come back exactly as the file had them" {
    // The separator is not normalised on the way out: `simple` hashes the field
    // verbatim, so a colon followed by a TAB, or by nothing, has to survive the
    // round trip (audit D-23).
    const a = std.testing.allocator;
    var msg = try parseMessage(a, "From: a@b\r\nX-None:none\r\nX-Tab:\tv\r\n\r\n", true);
    defer msg.deinit();

    const lines = try msg.rendered();
    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings("From: a@b", lines[0]);
    try std.testing.expectEqualStrings("X-None:none", lines[1]);
    try std.testing.expectEqualStrings("X-Tab:\tv", lines[2]);
}
