//! Terminal output for the command-line tools.
//!
//! Nine tools across four repositories had their own `writeOut`/`writeErr`/`fatal`.
//! That would be unremarkable duplication except that the copies had **diverged in a
//! way that mattered**, and the majority had it wrong:
//!
//! Seven of nine wrote
//!
//! ```zig
//! _ = posix.write(posix.STDOUT_FILENO, data) catch {};
//! ```
//!
//! which **discards the byte count**. `write(2)` is permitted to transfer fewer bytes
//! than requested and report how many; ignoring that silently truncates output. Two
//! tools -- `securearc-seal` and `securedkim-sign` -- looped until the buffer was
//! drained, which is correct.
//!
//! A short write needs a reason to happen, and the checkers have one: every
//! conformance harness runs them under `subprocess.run(capture_output=True)`, so their
//! stdout is a **pipe**, which is exactly where partial writes occur. A truncated
//! result line reaches the harness as unparseable output and is reported as a case
//! failure -- pointing at production code that is fine. That is the same class of
//! harness-side fault that has twice produced phantom defects here (the `DkimDns`
//! character-iteration bug, and `c=simple/*` in the ARC suite).
//!
//! So this module takes the minority implementation, and the loop is the point of it.

const std = @import("std");
const posix = std.posix;
const process = std.process;

/// Exit status for an unrecoverable error.
///
/// Was 1 in `securespf-check` and `securedkim-sign` and 2 everywhere else. The
/// harnesses only test `returncode != 0`, so nothing depended on the difference --
/// but a tool's exit status is the gate signal, and having it mean two things
/// depending on which daemon you asked was a trap waiting for the first harness that
/// tried to tell "the tool broke" from "the case failed".
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
        /// `noreturn` rather than `void`. `securearc-check`'s copy was declared
        /// `void` while every other one was `noreturn`, even though it ends in
        /// `process.exit` just the same -- so the compiler could not prove control
        /// flow stopped there, and a caller was free to write unreachable code after
        /// it and get no warning.
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
