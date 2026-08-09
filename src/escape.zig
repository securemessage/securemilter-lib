const std = @import("std");
const mem = std.mem;
const Writer = std.io.Writer;

/// Escaping attacker-controlled strings for structured output (audit X-5).
///
/// Two output formats have attacker-reachable delimiters:
///   * Syslog: CR/LF forges log lines; space breaks `key=value` structure.
///   * ZMQ JSON: unescaped `"` ends the string, reinterpreting the payload.
///
/// Formatters (use with `{f}`); allocate nothing.
/// Render untrusted value as a single bare token for `key=value` log lines.
///
/// Non-printable and space → `_` (1:1, no expansion into logger's 1 KiB buffer).
/// Empty value → `-` (prevents `from=` from merging with the next field).
pub const LogField = struct {
    raw: []const u8,

    pub fn format(self: LogField, writer: *Writer) Writer.Error!void {
        if (self.raw.len == 0) {
            try writer.writeByte('-');
            return;
        }
        for (self.raw) |ch| {
            try writer.writeByte(if (isBareToken(ch)) ch else '_');
        }
    }
};

/// Printable ASCII excluding the space: the set that cannot break a
/// space-separated `key=value` line.
fn isBareToken(ch: u8) bool {
    return ch > 0x20 and ch < 0x7f;
}

/// Render an untrusted value as one bare log token. Use with `{f}`.
pub fn logField(raw: []const u8) LogField {
    return .{ .raw = raw };
}

/// An untrusted value rendered as the *contents* of a JSON string, escaped per
/// RFC 8259 §7. The caller supplies the surrounding quotes.
///
/// Unlike `LogField` this does not substitute, it escapes: an event payload is
/// machine-read, so the consumer must receive the value the daemon actually saw.
/// Expansion is bounded at 6x by `\u00XX`, and the payload is heap-allocated by
/// the caller, so there is no buffer to overrun.
pub const JsonString = struct {
    raw: []const u8,

    pub fn format(self: JsonString, writer: *Writer) Writer.Error!void {
        for (self.raw) |ch| {
            switch (ch) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                '\r' => try writer.writeAll("\\r"),
                '\t' => try writer.writeAll("\\t"),
                0x08 => try writer.writeAll("\\b"),
                0x0c => try writer.writeAll("\\f"),
                // RFC 8259 requires escaping every character below 0x20. The
                // ones without a shorthand take the \u form.
                0x00...0x07, 0x0b, 0x0e...0x1f => {
                    try writer.print("\\u{x:0>4}", .{ch});
                },
                else => try writer.writeByte(ch),
            }
        }
    }
};

/// Render an untrusted value as escaped JSON string contents. Use with `{f}`,
/// inside quotes supplied by the caller.
pub fn jsonString(raw: []const u8) JsonString {
    return .{ .raw = raw };
}

/// Backstop: replace control bytes (< 0x20, 0x7F) in an assembled log message.
/// Guarantees no CR/LF in output regardless of call-site errors. Does NOT touch
/// spaces (indistinguishable from field separators at this stage).
pub fn scrubControlBytes(msg: []u8) void {
    for (msg) |*ch| {
        if (ch.* < 0x20 or ch.* == 0x7f) ch.* = '_';
    }
}

// --- tests -------------------------------------------------------------------

fn expectLogField(expected: []const u8, raw: []const u8) !void {
    var buf: [256]u8 = undefined;
    const out = try std.fmt.bufPrint(&buf, "{f}", .{logField(raw)});
    try std.testing.expectEqualStrings(expected, out);
}

test "logField renders an ordinary value unchanged" {
    try expectLogField("example.com", "example.com");
    try expectLogField("user@example.com", "user@example.com");
    try expectLogField("<user@example.com>", "<user@example.com>");
    try expectLogField("192.0.2.1", "192.0.2.1");
    try expectLogField("2001:db8::1", "2001:db8::1");
}

test "logField cannot forge a log line" {
    // The security property: no value can introduce a line break, so no value
    // can fabricate a second syslog line attributing an action to another host.
    try expectLogField("a_b", "a\nb");
    try expectLogField("a_b", "a\rb");
    try expectLogField("a__b", "a\r\nb");
    // Colons and brackets are printable and survive; only the newline and the
    // spaces are neutralised, which is enough to keep it on one line and inside
    // one field.
    try expectLogField(
        "evil_Jul_28_18:00:00_host_sshd[1]:_accepted",
        "evil\nJul 28 18:00:00 host sshd[1]: accepted",
    );
}

test "logField keeps the value to a single token" {
    // A space would make the remainder of the value look like the next field.
    try expectLogField("a_b", "a b");
    try expectLogField("a_b_c", "a\tb c");
    try expectLogField("_leading", " leading");
    try expectLogField("trailing_", "trailing ");
}

test "logField renders an empty value as a placeholder" {
    // `from=` followed by a space makes the next key look like this value, to a
    // human and to a parser alike. This is the case the x5a probe reported.
    try expectLogField("-", "");
}

test "logField replaces every byte outside printable ASCII" {
    // One byte in, one byte out, so a hostile value cannot expand the line.
    var raw: [256]u8 = undefined;
    for (&raw, 0..) |*ch, i| ch.* = @intCast(i);

    var buf: [512]u8 = undefined;
    const out = try std.fmt.bufPrint(&buf, "{f}", .{logField(&raw)});

    // One byte out per byte in: no expansion, so no truncation to engineer.
    try std.testing.expectEqual(raw.len, out.len);

    // Byte for byte: a printable input survives exactly, anything else becomes
    // the replacement. Checked per index rather than by counting, because the
    // replacement character is itself printable and a count cannot tell a
    // surviving `_` from a replaced one.
    var survived: usize = 0;
    for (out, raw) |out_ch, raw_ch| {
        if (isBareToken(raw_ch)) {
            try std.testing.expectEqual(raw_ch, out_ch);
            survived += 1;
        } else {
            try std.testing.expectEqual(@as(u8, '_'), out_ch);
        }
    }

    // 0x21..0x7e inclusive is 94 bytes. The other 162 -- every control byte, the
    // space, DEL, and all of high ASCII -- are replaced. Pinned as a number so
    // widening `isBareToken` cannot quietly let more reach the log.
    try std.testing.expectEqual(@as(usize, 94), survived);
}

fn expectJson(expected: []const u8, raw: []const u8) !void {
    var buf: [512]u8 = undefined;
    const out = try std.fmt.bufPrint(&buf, "{f}", .{jsonString(raw)});
    try std.testing.expectEqualStrings(expected, out);
}

test "jsonString escapes the characters that break a JSON string" {
    try expectJson("example.com", "example.com");
    try expectJson("evil\\\"quote.pentest", "evil\"quote.pentest");
    try expectJson("back\\\\slash", "back\\slash");
    try expectJson("line\\nbreak", "line\nbreak");
    try expectJson("carriage\\rreturn", "carriage\rreturn");
    try expectJson("tab\\there", "tab\there");
}

test "jsonString escapes every control character, per RFC 8259" {
    try expectJson("\\u0000", "\x00");
    try expectJson("\\u001f", "\x1f");
    try expectJson("\\b", "\x08");
    try expectJson("\\f", "\x0c");
    // 0x7f is legal unescaped in JSON, unlike in a log field.
    try expectJson("\x7f", "\x7f");
}

test "a hostile value round-trips through std.json as one string" {
    // The x5b property, stated the way the probe checks it: whatever the sender
    // put in `d=`, the published payload must still parse, and the parsed value
    // must be exactly what was sent.
    const hostile = "evil\"quote\\and\nnewline\tand\x01ctl.pentest";

    var buf: [1024]u8 = undefined;
    const payload = try std.fmt.bufPrint(&buf,
        \\{{"domain":"{f}","result":"pass"}}
    , .{jsonString(hostile)});

    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        payload,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(hostile, parsed.value.object.get("domain").?.string);
    try std.testing.expectEqualStrings("pass", parsed.value.object.get("result").?.string);
}

test "scrubControlBytes guarantees one line per message" {
    // The backstop: even a call site that forgets logField cannot emit a second
    // line. Spaces are deliberately left alone -- at this point they are the
    // field separators.
    var msg = "<22>securespf[1]: from=a\nb client=1.2.3.4\r\n".*;
    scrubControlBytes(&msg);

    try std.testing.expect(mem.indexOfScalar(u8, &msg, '\n') == null);
    try std.testing.expect(mem.indexOfScalar(u8, &msg, '\r') == null);
    try std.testing.expect(mem.indexOfScalar(u8, &msg, ' ') != null);
    try std.testing.expectEqualStrings("<22>securespf[1]: from=a_b client=1.2.3.4__", &msg);
}
