//! Header field representation, extracted from `connection.zig` for D-23.
//! A connection is a lifecycle; field representation is a shared concern used
//! by four daemons and three CLIs. `connection.zig` re-exports these names.

const std = @import("std");

/// Accumulated message header for product-specific processing.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
    /// Whether a space followed the colon on the wire (D-23).
    /// Without `SMFIP_HDR_LEADSPC` the MTA strips one leading SP if present (never
    /// TAB). `c=simple` hashes the field verbatim, so the wrong separator breaks
    /// verification. This bit is unrecoverable after stripping: `Name:value` and
    /// `Name: value` reach a milter identically.
    /// Defaults `true` (pre-flag MTA behaviour); worker sets from wire once negotiated.
    had_space: bool = true,

    /// Rebuild field as it appeared on the wire. Single definition of the
    /// name:value separator (was 8 copies of `"{s}: {s}"`).
    pub fn render(self: Header, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{s}{s}", .{
            self.name,
            if (self.had_space) " " else "",
            self.value,
        });
    }
};

pub const HeaderSplit = struct { value: []const u8, had_space: bool };

/// Split leading space from a value received with `SMFIP_HDR_LEADSPC`.
/// Performs the same transformation the MTA does without the flag (strip one
/// leading SP if present) and reports whether it was present. Keeps
/// `Header.value` byte-identical to pre-flag behaviour.
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

        try std.testing.expectEqualStrings(want, rendered);
    }
}

test "D-23: the split leaves Header.value exactly what the MTA delivers today" {
    // `value` is bit-identical to pre-flag behaviour in all nine shapes;
    // the only new information is one bool.
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
