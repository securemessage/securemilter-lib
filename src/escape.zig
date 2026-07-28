const std = @import("std");
const mem = std.mem;
const Writer = std.io.Writer;

/// Rendering untrusted strings into structured output (audit X-5).
///
/// Every daemon interpolates attacker-controlled strings -- HELO, MAIL FROM, a
/// DKIM `d=`, a `From:` domain, a header value -- into two structured formats
/// that both have delimiters an attacker can reach:
///
///   * **syslog lines**, whose shape is space-separated `key=value` pairs, one
///     line per event. A CR or LF in a value forges an additional log line; a
///     space or an empty value silently shifts what the following key appears to
///     hold. Log forgery is the security half: an attacker who can inject a
///     newline can write a plausible line attributing an action to another host.
///   * **ZMQ event JSON**, consumed by SecureMessageWebhooks. A `"` in a value
///     ends the string early and the rest of the payload is reinterpreted --
///     invalid JSON at best, an attacker-chosen field value at worst.
///
/// Both helpers are formatters rather than functions returning a slice, so they
/// allocate nothing and cannot leave a caller holding a pointer into a dead
/// buffer. Use them with the `{f}` specifier.
/// An untrusted value rendered as exactly one bare token, safe in a `key=value`
/// log line.
///
/// **Every byte outside printable ASCII, and the space itself, becomes `_`.**
/// One byte in, one byte out: the substitution cannot expand the line into the
/// logger's 1 KiB buffer and cannot change how many characters the operator
/// sees. That does discard *which* control character was sent -- a tab and a
/// NUL both read as `_` -- and that is a deliberate trade. The alternative,
/// expanding to `\xNN`, means an attacker can triple the length of a field and
/// push the useful part of the line past truncation, which costs more than the
/// distinction is worth. The count and position of the offending bytes survive,
/// which is what tells an operator the value was hostile.
///
/// An empty value renders as `-`, not as nothing. `from=` followed by a space
/// makes the *next* field look like this one's value, both to a human and to a
/// parser reading `key=(.*)`; `-` is the placeholder the rest of the codebase
/// already uses for an absent macro.
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

/// Replace every control byte in an already-formatted log message.
///
/// The backstop behind `logField`. `logField` has to be applied per value at
/// every call site, and a call site that is added later, or one that was missed,
/// would silently reopen the log-forgery hole. This runs once over the assembled
/// message inside the logger, so **no log line can contain a CR or LF no matter
/// what any call site does**.
///
/// It deliberately does not touch spaces: at this point the separators between
/// fields are indistinguishable from a space inside a value, so squashing them
/// would corrupt every message. Holding the `key=value` shape is `logField`'s
/// job; this only guarantees one line per line.
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
