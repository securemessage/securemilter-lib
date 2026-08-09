//! One header field as a milter sees it, and how to put it back together.
//!
//! Extracted from `connection.zig` when D-23 gave the field a third component.
//! A connection is a lifecycle -- accept, accumulate, reset, close -- and how a
//! header field is represented is a separate concern with its own invariant,
//! used by four daemons and three CLIs. `connection.zig` re-exports these names,
//! so nothing had to move to follow them here.

const std = @import("std");

/// Accumulated message header for product-specific processing.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
    /// Was there a space between the colon and the value on the wire?
    ///
    /// **The authoritative explanation of D-23; other sites point here.** A milter
    /// is handed a name and a value, not the field's original octets, so every
    /// site that needed the field back used to write `name ++ ": " ++ value` and
    /// hope. `c=simple` hashes the field verbatim, so that guess is the difference
    /// between a signature verifying and not.
    ///
    /// Measured, not assumed (audit §11.40): without `SMFIP_HDR_LEADSPC` an MTA
    /// strips exactly one leading SP if and only if one is present, and never a
    /// TAB. The guess is therefore right whenever the field had at least one
    /// leading space and wrong in exactly two shapes -- `Name:value` and
    /// `Name:<TAB>value`. What is lost is precisely one bit per header, and it is
    /// unrecoverable after the fact: `Name:value` and `Name: value` reach a milter
    /// byte-identical.
    ///
    /// This is that bit. It defaults to `true`, reproducing what the MTA has
    /// always done and what every caller already assumed; the worker sets it from
    /// the wire once the flag is negotiated.
    had_space: bool = true,

    /// Rebuild the field as it appeared on the wire. The only place that decides
    /// what separates a header name from its value -- it was eight places, each
    /// with its own copy of `"{s}: {s}"`, which is why D-23 had to be fixed in
    /// eight places instead of one.
    pub fn render(self: Header, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{s}{s}", .{
            self.name,
            if (self.had_space) " " else "",
            self.value,
        });
    }
};

pub const HeaderSplit = struct { value: []const u8, had_space: bool };

/// Split a header value as the MTA would have, recovering `Header.had_space`.
///
/// For a value received with `SMFIP_HDR_LEADSPC` negotiated, which still carries
/// its original leading whitespace. Performs exactly the transformation the MTA
/// performs without the flag -- remove one leading SP if present -- and reports
/// whether it removed one.
///
/// This is what keeps `Header.value` byte-identical to what every consumer has
/// always been handed, so negotiating the flag cannot leak a new leading space
/// into every `From:` parse and tag list across four daemons. The blast radius is
/// one field, provable by the round-trip test rather than surveyed and hoped for.
pub fn splitLeadingSpace(raw: []const u8) HeaderSplit {
    if (raw.len > 0 and raw[0] == ' ') return .{ .value = raw[1..], .had_space = true };
    return .{ .value = raw, .had_space = false };
}

// The nine shapes measured against Postfix 3.11.5 and FreeBSD base sendmail,
// recorded in engineering-docs securemilter/measurements/d23-header-wsp/README.md.
// Both MTAs behaved identically: exactly one leading SP is stripped if and only
// if one is present, and a TAB is never stripped.
//
// `wire` is what follows the colon in the delivered message, which with
// SMFIP_HDR_LEADSPC negotiated is also what the milter receives. `classic` is
// what the milter receives WITHOUT the flag -- the MTA having eaten one space.
const d23_shapes = [_]struct { wire: []const u8, classic: []const u8 }{
    .{ .wire = "zero", .classic = "zero" },
    .{ .wire = " one", .classic = "one" },
    .{ .wire = "  two", .classic = " two" },
    .{ .wire = "   three", .classic = "  three" },
    .{ .wire = "\ttab", .classic = "\ttab" },
    .{ .wire = " \t sptabsp", .classic = "\t sptabsp" },
    .{ .wire = "", .classic = "" },
    .{ .wire = " ", .classic = "" },
    .{ .wire = "  ", .classic = " " },
};

test "D-23: every measured shape round-trips through split and render" {
    const allocator = std.testing.allocator;

    for (d23_shapes) |shape| {
        const split = splitLeadingSpace(shape.wire);
        const hdr = Header{
            .name = "X-D23",
            .value = split.value,
            .had_space = split.had_space,
        };
        const rendered = try hdr.render(allocator);
        defer allocator.free(rendered);

        const want = try std.fmt.allocPrint(allocator, "X-D23:{s}", .{shape.wire});
        defer allocator.free(want);

        // The whole point of the finding: `c=simple` hashes these bytes verbatim,
        // so anything but an exact match is a signature that does not verify.
        try std.testing.expectEqualStrings(want, rendered);
    }
}

test "D-23: the split leaves Header.value exactly what the MTA delivers today" {
    // This is what makes the fix safe without auditing every consumer in four
    // daemons. Negotiating SMFIP_HDR_LEADSPC changes the bytes on the wire, and
    // if that change reached `Header.value` it would surface in every `From:`
    // parse, every tag list and every comparison in the codebase. It does not:
    // the split performs precisely the transformation the MTA was performing,
    // so `value` is bit-identical to the pre-flag behaviour in all nine shapes
    // and the only new information is one bool.
    for (d23_shapes) |shape| {
        const split = splitLeadingSpace(shape.wire);
        try std.testing.expectEqualStrings(shape.classic, split.value);
    }
}

test "D-23: without the flag, rendering reproduces the old fabricated separator" {
    // An MTA that declines the flag must leave behaviour exactly as it was --
    // `had_space` defaults to true, which is the `": "` this code always wrote.
    const allocator = std.testing.allocator;
    const hdr = Header{ .name = "Subject", .value = "hello" };
    const rendered = try hdr.render(allocator);
    defer allocator.free(rendered);
    try std.testing.expectEqualStrings("Subject: hello", rendered);
}
