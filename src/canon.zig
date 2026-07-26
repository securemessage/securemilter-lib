const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Canonicalization algorithm (RFC 6376 §3.4).
pub const Algorithm = enum {
    simple,
    relaxed,
};

/// Canonicalization pair: header algorithm / body algorithm.
pub const CanonicalizationPair = struct {
    header: Algorithm = .simple,
    body: Algorithm = .simple,
};

/// Parse a "c=" tag value like "relaxed/simple", "relaxed", "simple/relaxed".
/// Default is simple/simple per RFC 6376 §3.4.
pub fn parseCanonicalization(value: []const u8) !CanonicalizationPair {
    if (value.len == 0) return .{};

    if (mem.indexOfScalar(u8, value, '/')) |slash| {
        return .{
            .header = try parseAlgorithm(value[0..slash]),
            .body = try parseAlgorithm(value[slash + 1 ..]),
        };
    }
    // Only header algorithm specified; body defaults to simple
    return .{
        .header = try parseAlgorithm(value),
        .body = .simple,
    };
}

fn parseAlgorithm(s: []const u8) !Algorithm {
    if (mem.eql(u8, s, "simple")) return .simple;
    if (mem.eql(u8, s, "relaxed")) return .relaxed;
    return error.InvalidCanonicalization;
}

// =============================================================================
// Header Canonicalization (RFC 6376 §3.4.1 / §3.4.2)
// =============================================================================

/// Canonicalize a single header field (name: value) for signing/verification.
///
/// Simple (§3.4.1): No change. Headers are used exactly as presented.
///
/// Relaxed (§3.4.2):
///   1. Header field name → lowercase
///   2. Unfold continuation lines (remove CRLF before WSP)
///   3. Collapse sequential WSP to single SP
///   4. Strip trailing WSP before CRLF
///   5. Strip WSP around the colon separator
///
/// The returned slice does NOT include a trailing CRLF — the caller appends it.
pub fn canonicalizeHeader(allocator: Allocator, algorithm: Algorithm, header: []const u8) ![]u8 {
    return switch (algorithm) {
        .simple => allocator.dupe(u8, header),
        .relaxed => canonicalizeHeaderRelaxed(allocator, header),
    };
}

fn canonicalizeHeaderRelaxed(allocator: Allocator, header: []const u8) ![]u8 {
    // Find the colon separating name from value
    const colon_pos = mem.indexOfScalar(u8, header, ':') orelse return error.MalformedHeader;

    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    // Step 1: lowercase header name, strip trailing whitespace before colon
    const name_raw = header[0..colon_pos];
    const name = mem.trimRight(u8, name_raw, " \t");
    for (name) |c| {
        try result.append(allocator, toLower(c));
    }
    try result.append(allocator, ':');

    // Step 5: strip leading whitespace after colon
    var value = header[colon_pos + 1 ..];
    value = mem.trimLeft(u8, value, " \t");
    // Strip trailing whitespace
    value = mem.trimRight(u8, value, " \t\r\n");

    // Steps 2-4: unfold + collapse whitespace
    var in_wsp = false;
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        const c = value[i];
        // Unfold: skip CRLF if followed by WSP (continuation line)
        if (c == '\r' and i + 1 < value.len and value[i + 1] == '\n') {
            if (i + 2 < value.len and (value[i + 2] == ' ' or value[i + 2] == '\t')) {
                // CRLF followed by WSP = folding, treat as WSP
                i += 1; // skip \n, the \t/space will be handled next iteration
                in_wsp = true;
                continue;
            }
        }
        if (c == ' ' or c == '\t') {
            in_wsp = true;
        } else {
            if (in_wsp) {
                try result.append(allocator, ' ');
                in_wsp = false;
            }
            try result.append(allocator, c);
        }
    }

    return result.toOwnedSlice(allocator);
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

// =============================================================================
// Body Canonicalization (RFC 6376 §3.4.3 / §3.4.4)
// =============================================================================

/// Streaming body canonicalization state machine.
///
/// Feed body chunks via `update()`, then call `finish()` to get the final
/// canonicalized body (or use the incrementally-hashed result).
///
/// Simple (§3.4.3):
///   - Ignore all empty lines at the end of the body
///   - Ensure body ends with CRLF (if non-empty)
///   - Everything else verbatim
///
/// Relaxed (§3.4.4):
///   - Same trailing-empty-line stripping as simple
///   - Reduce all sequences of WSP within a line to single SP
///   - Strip all trailing WSP on each line before CRLF
///   - Ignore all empty lines at the end
pub const BodyCanonicalizer = struct {
    algorithm: Algorithm,
    allocator: Allocator,
    /// Accumulated canonicalized body lines (not including trailing empty lines).
    output: std.ArrayList(u8),
    /// Number of trailing CRLF bytes pending (deferred until we know they aren't
    /// the final empty lines that should be stripped).
    pending_crlf_count: usize,
    /// For relaxed: tracks whether we are in a whitespace run within the current line.
    in_wsp: bool,
    /// For relaxed: current line buffer being built.
    line_buf: std.ArrayList(u8),

    pub fn init(allocator: Allocator, algorithm: Algorithm) BodyCanonicalizer {
        return .{
            .algorithm = algorithm,
            .allocator = allocator,
            .output = .{},
            .pending_crlf_count = 0,
            .in_wsp = false,
            .line_buf = .{},
        };
    }

    pub fn deinit(self: *BodyCanonicalizer) void {
        self.output.deinit(self.allocator);
        self.line_buf.deinit(self.allocator);
    }

    /// Feed a chunk of body data.
    pub fn update(self: *BodyCanonicalizer, data: []const u8) !void {
        switch (self.algorithm) {
            .simple => try self.updateSimple(data),
            .relaxed => try self.updateRelaxed(data),
        }
    }

    /// Finalize and return the canonicalized body.
    /// For an empty body, returns CRLF (RFC 6376 §3.4.3/§3.4.4: "a body
    /// with a zero-length body is canonicalized as a single CRLF").
    pub fn finish(self: *BodyCanonicalizer) ![]u8 {
        // Flush any remaining line content (for relaxed, if body doesn't end with CRLF)
        if (self.algorithm == .relaxed and self.line_buf.items.len > 0) {
            try self.flushRelaxedLine();
        }

        // RFC 6376 §3.4.3/§3.4.4: ignore trailing empty lines, then ensure
        // the body ends with CRLF. An empty body is treated as single CRLF.
        // pending_crlf_count holds deferred trailing CRLFs — we discard them.
        if (self.output.items.len == 0) {
            try self.output.appendSlice(self.allocator, "\r\n");
        } else {
            // Ensure non-empty body ends with exactly one CRLF
            const len = self.output.items.len;
            if (len < 2 or self.output.items[len - 2] != '\r' or self.output.items[len - 1] != '\n') {
                try self.output.appendSlice(self.allocator, "\r\n");
            }
        }

        return self.output.toOwnedSlice(self.allocator);
    }

    // ---- Simple canonicalization ----

    fn updateSimple(self: *BodyCanonicalizer, data: []const u8) !void {
        var i: usize = 0;
        while (i < data.len) {
            // Find next CRLF
            if (data[i] == '\r' and i + 1 < data.len and data[i + 1] == '\n') {
                self.pending_crlf_count += 1;
                i += 2;
            } else {
                // Non-CRLF byte: flush all pending CRLFs (they weren't trailing)
                try self.flushPendingCrlf();
                try self.output.append(self.allocator, data[i]);
                i += 1;
            }
        }
    }

    // ---- Relaxed canonicalization ----

    fn updateRelaxed(self: *BodyCanonicalizer, data: []const u8) !void {
        for (data) |c| {
            if (c == '\r') {
                // Might be start of CRLF, will handle on next byte
                continue;
            }
            if (c == '\n') {
                // End of line — flush this line
                try self.flushRelaxedLine();
                continue;
            }
            if (c == ' ' or c == '\t') {
                self.in_wsp = true;
            } else {
                if (self.in_wsp) {
                    try self.line_buf.append(self.allocator, ' ');
                    self.in_wsp = false;
                }
                try self.line_buf.append(self.allocator, c);
            }
        }
    }

    fn flushRelaxedLine(self: *BodyCanonicalizer) !void {
        // Strip trailing WSP already handled by not appending trailing WSP
        self.in_wsp = false;

        if (self.line_buf.items.len == 0) {
            // Empty line — defer (might be trailing)
            self.pending_crlf_count += 1;
        } else {
            // Non-empty line: flush pending CRLFs first
            try self.flushPendingCrlf();
            try self.output.appendSlice(self.allocator, self.line_buf.items);
            try self.output.appendSlice(self.allocator, "\r\n");
        }
        self.line_buf.clearRetainingCapacity();
    }

    fn flushPendingCrlf(self: *BodyCanonicalizer) !void {
        while (self.pending_crlf_count > 0) : (self.pending_crlf_count -= 1) {
            try self.output.appendSlice(self.allocator, "\r\n");
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "parse canonicalization pair" {
    const pair1 = try parseCanonicalization("relaxed/simple");
    try std.testing.expectEqual(Algorithm.relaxed, pair1.header);
    try std.testing.expectEqual(Algorithm.simple, pair1.body);

    const pair2 = try parseCanonicalization("simple/relaxed");
    try std.testing.expectEqual(Algorithm.simple, pair2.header);
    try std.testing.expectEqual(Algorithm.relaxed, pair2.body);

    const pair3 = try parseCanonicalization("relaxed");
    try std.testing.expectEqual(Algorithm.relaxed, pair3.header);
    try std.testing.expectEqual(Algorithm.simple, pair3.body);

    const pair4 = try parseCanonicalization("");
    try std.testing.expectEqual(Algorithm.simple, pair4.header);
    try std.testing.expectEqual(Algorithm.simple, pair4.body);
}

test "header canonicalization simple" {
    const allocator = std.testing.allocator;
    const input = "Subject: A Simple Test";
    const result = try canonicalizeHeader(allocator, .simple, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Subject: A Simple Test", result);
}

test "header canonicalization relaxed basic" {
    const allocator = std.testing.allocator;
    const input = "Subject:  A   Simple   Test  ";
    const result = try canonicalizeHeader(allocator, .relaxed, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("subject:A Simple Test", result);
}

test "header canonicalization relaxed folded" {
    const allocator = std.testing.allocator;
    const input = "Subject: A\r\n\t Folded Header";
    const result = try canonicalizeHeader(allocator, .relaxed, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("subject:A Folded Header", result);
}

test "header canonicalization relaxed colon whitespace" {
    const allocator = std.testing.allocator;
    const input = "From \t:  user@example.com  ";
    const result = try canonicalizeHeader(allocator, .relaxed, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("from:user@example.com", result);
}

test "body canonicalization simple strips trailing empty lines" {
    const allocator = std.testing.allocator;
    var bc = BodyCanonicalizer.init(allocator, .simple);
    defer bc.deinit();

    try bc.update("Hello\r\n");
    try bc.update("\r\n");
    try bc.update("\r\n");

    const result = try bc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello\r\n", result);
}

test "body canonicalization simple empty body" {
    const allocator = std.testing.allocator;
    var bc = BodyCanonicalizer.init(allocator, .simple);
    defer bc.deinit();

    const result = try bc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("\r\n", result);
}

test "body canonicalization relaxed whitespace" {
    const allocator = std.testing.allocator;
    var bc = BodyCanonicalizer.init(allocator, .relaxed);
    defer bc.deinit();

    try bc.update("Hello  \t World  \r\n");
    try bc.update("\r\n");

    const result = try bc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello World\r\n", result);
}

test "body canonicalization relaxed multiple lines" {
    const allocator = std.testing.allocator;
    var bc = BodyCanonicalizer.init(allocator, .relaxed);
    defer bc.deinit();

    try bc.update("Line 1\r\n");
    try bc.update("  Line  2  \r\n");
    try bc.update("\r\n");
    try bc.update("Line 3\r\n");
    try bc.update("\r\n");
    try bc.update("\r\n");

    const result = try bc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Line 1\r\n Line 2\r\n\r\nLine 3\r\n", result);
}
