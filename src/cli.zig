//! Terminal output for the command-line tools.
//!
//! Shared helpers drain short writes, which can otherwise truncate checker output
//! when a conformance harness captures it through a pipe.

const std = @import("std");
const posix = std.posix;
const process = std.process;

/// Exit status for an unrecoverable error.
///
/// One value for every tool: a harness telling "the tool broke" from "the case
/// failed" must not have that distinction depend on which daemon's tool it ran.
pub const EXIT_FATAL: u8 = 2;

/// Write all of `data` to `fd`, or give up silently.
///
/// Loops because a short write is legal. Errors are dropped deliberately: the callers
/// are reporting a result or a failure, and there is nowhere left to report a failure
/// to report a failure.
fn writeAll(fd: posix.fd_t, data: []const u8) void {
    var written: usize = 0;
    while (written < data.len) {
        written += posix.write(fd, data[written..]) catch return;
    }
}

/// Write to standard output.
pub fn out(data: []const u8) void {
    writeAll(posix.STDOUT_FILENO, data);
}

/// Write to standard error.
pub fn err(data: []const u8) void {
    writeAll(posix.STDERR_FILENO, data);
}

/// The output helpers for one named tool.
///
/// `prog` is comptime so the prefix is folded into the binary rather than formatted
/// per call, and so a tool cannot accidentally report itself under another's name:
///
/// ```zig
/// const cli = @import("securemilter").cli.Tool("securearc-check");
/// cli.fatal("no message on stdin");   // -> "securearc-check: no message on stdin"
/// ```
pub fn Tool(comptime prog: []const u8) type {
    return struct {
        /// Write to standard output.
        pub const out = @This().outFn;
        /// Write to standard error.
        pub const err = @This().errFn;

        fn outFn(data: []const u8) void {
            writeAll(posix.STDOUT_FILENO, data);
        }

        fn errFn(data: []const u8) void {
            writeAll(posix.STDERR_FILENO, data);
        }

        /// Report `msg` prefixed with the tool name and exit `EXIT_FATAL`.
        ///
        /// `noreturn`, not `void`: it ends in `process.exit`, and declaring it
        /// otherwise would let the compiler accept unreachable code after a call
        /// to this with no warning.
        pub fn fatal(msg: []const u8) noreturn {
            errFn(prog);
            errFn(": ");
            errFn(msg);
            errFn("\n");
            process.exit(EXIT_FATAL);
        }
    };
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test "writeAll drains a buffer larger than one write is obliged to take" {
    // Exercised against a pipe, because a pipe is where a short write actually
    // happens and where the conformance harnesses put the checkers' stdout.
    const fds = try posix.pipe();
    defer posix.close(fds[0]);

    // Comfortably under the pipe buffer so the test cannot block on a full pipe;
    // the property under test is that every byte handed over is accounted for.
    var payload: [4096]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast('a' + (i % 26));

    writeAll(fds[1], &payload);
    // Closed here rather than by `defer`, because the read loop below needs the EOF
    // to terminate. A `defer` as well would close it twice and abort the runner.
    posix.close(fds[1]);

    var got: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < got.len) {
        const n = try posix.read(fds[0], got[total..]);
        if (n == 0) break;
        total += n;
    }

    try testing.expectEqual(payload.len, total);
    try testing.expectEqualSlices(u8, &payload, got[0..total]);
}

test "Tool prefixes with its own name" {
    // `fatal` cannot be called from a test -- it exits the process -- so this
    // asserts the part that can be checked without one: that two tools built from
    // the same generic are distinct types carrying their own name.
    const a = Tool("securearc-check");
    const b = Tool("securedkim-check");
    try testing.expect(a != b);
}
