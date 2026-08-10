const std = @import("std");
const posix = std.posix;
const c = std.c;
const log_mod = @import("log.zig");

/// Ready byte: 'K' signals the daemon is serving.
/// A fixed value prevents misreading an unrelated descriptor value as success.
const ready_byte: u8 = 'K';

/// Startup timeout in seconds. A blocked daemon must fail; a blocked `service start`
/// must fail rather than hang forever.
pub const startup_timeout_s: isize = 60;

/// Double-fork daemonization: setsid, close fds, return readiness pipe.
/// The parent reads the pipe; a byte means the daemon is serving, EOF means failure.
/// Must signal via `signalReady` once listeners and workers are running, not
/// merely once daemonization completes: `service start` reporting success while
/// nothing listened would let a typo in a listener address silently produce
/// exit 0, no listener, and unauthenticated mail (audit X-16).
pub fn daemonize() !posix.fd_t {
    // Create before first fork so both ends survive into grandchild.
    // CLOEXEC prevents exec'd children from inheriting the write end, which
    // would keep the parent blocked on a dead descriptor.
    const ready = try posix.pipe2(.{ .CLOEXEC = true });

    // Per-fork cleanup: the child closes the read end below. A single errdefer
    // covering both would double-close it on failure, and by then the fd number
    // may belong to something else.
    const pid1 = posix.fork() catch |e| {
        posix.close(ready[0]);
        posix.close(ready[1]);
        return e;
    };
    if (pid1 != 0) {
        // The original process: the one whose exit status the caller reads.
        posix.close(ready[1]);
        defer posix.close(ready[0]);
        awaitReady(ready[0], startup_timeout_s) catch posix.exit(1);
        posix.exit(0);
    }
    posix.close(ready[0]);

    _ = c.setsid();

    const pid2 = posix.fork() catch |e| {
        posix.close(ready[1]);
        return e;
    };
    // Intermediate parent exits; its write-end copy closes on exit.
    // EOF only reports when the LAST copy (daemon's) is gone.
    if (pid2 != 0) posix.exit(0);

    const devnull = try posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    try posix.dup2(devnull, 0);
    try posix.dup2(devnull, 1);
    try posix.dup2(devnull, 2);
    if (devnull > 2) posix.close(devnull);

    return ready[1];
}

/// Signal readiness once listeners and workers are running.
/// Calling earlier reports success before work is done.
pub fn signalReady(wr: posix.fd_t) void {
    _ = posix.write(wr, &[_]u8{ready_byte}) catch {};
    posix.close(wr);
}

/// Wait for daemon readiness or timeout.
/// EOF without byte = startup failure. Timeout = alive but not serving.
fn awaitReady(rd: posix.fd_t, timeout_s: isize) !void {
    const kq = try posix.kqueue();
    defer posix.close(kq);

    // Single kevent call for registration and wait; avoids poll.
    var changes = [_]posix.Kevent{.{
        .ident = @intCast(rd),
        .filter = c.EVFILT.READ,
        .flags = c.EV.ADD | c.EV.ENABLE,
        .fflags = 0,
        .data = 0,
        .udata = 0,
        ._ext = .{ 0, 0, 0, 0 },
    }};
    var events: [1]posix.Kevent = undefined;
    const ts = posix.timespec{ .sec = timeout_s, .nsec = 0 };

    if (try posix.kevent(kq, &changes, &events, &ts) == 0) return error.StartupTimedOut;

    var buf: [1]u8 = undefined;
    const n = try posix.read(rd, &buf);
    if (n == 0 or buf[0] != ready_byte) return error.StartupFailed;
}

/// Read PID from `path`. Return `null` if file is missing, unreadable, not a PID,
/// or names a dead process. EPERM counts as alive (process exists but is owned
/// by someone else). Any error besides ProcessNotFound returns the PID.
///
/// LIMIT: recycled PID numbers read as live; distinguishing that requires
/// `KERN_PROC_PATHNAME`, which is not implemented. `rc.subr` pidfile handling
/// covers most cases; this covers foreground runs, monit, and containers.
fn livePidFileHolder(path: []const u8) ?c.pid_t {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    var buf: [32]u8 = undefined;
    const n = file.readAll(&buf) catch return null;
    const text = std.mem.trim(u8, buf[0..n], " \t\r\n");
    const pid = std.fmt.parseInt(c.pid_t, text, 10) catch return null;
    if (pid <= 0) return null;

    posix.kill(pid, 0) catch |e| switch (e) {
        error.ProcessNotFound => return null,
        else => return pid,
    };
    return pid;
}

/// Check no other instance holds the PID file. Must run before `daemonize`.
///
/// Running this after the fork would make the file name our own ancestor under
/// `daemon -p`, refusing to start against itself. Running before the fork
/// eliminates the ambiguity (audit X-16).
pub fn checkNotAlreadyRunning(path: []const u8) !void {
    const holder = livePidFileHolder(path) orelse return;
    if (holder == c.getpid() or holder == c.getppid()) return;

    log_mod.err(
        "pid file {s} is held by live process {d}; refusing to start a second instance",
        .{ path, holder },
    );
    return error.AlreadyRunning;
}

/// Ensure the PID file's parent directory exists and is writable by the
/// target user, so `removePidFile` succeeds after privilege drop.
/// Must be called while still root (before `dropPrivileges`).
pub fn ensurePidDirectory(pid_path: []const u8, user_spec: ?[]const u8) void {
    const dir = std.fs.path.dirnamePosix(pid_path) orelse return;
    if (dir.len == 0) return;

    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {
            log_mod.warn("pid directory: {}", .{err});
            return;
        },
    };

    const user = user_spec orelse return;
    const sep = std.mem.indexOfScalar(u8, user, ':');
    const username = if (sep) |i| user[0..i] else user;

    var name_buf: [256:0]u8 = undefined;
    if (username.len == 0 or username.len >= name_buf.len) return;
    @memcpy(name_buf[0..username.len], username);
    name_buf[username.len] = 0;

    const pw = c.getpwnam(&name_buf) orelse return;

    var d = std.fs.openDirAbsolute(dir, .{}) catch return;
    defer d.close();
    posix.fchown(d.fd, pw.uid, pw.gid) catch {};
}

/// Write current PID to file. Unconditional; the pre-fork `checkNotAlreadyRunning`
/// handles conflicts. Repeating the test here would re-introduce the `daemon -p`
/// failure: the file now names a process (us) that is not the supervisor's.
pub fn writePidFile(path: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();

    const pid = c.getpid();
    var buf: [20]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&buf, "{d}\n", .{pid}) catch return error.FormatError;
    try file.writeAll(pid_str);
}

/// Remove a PID file.
pub fn removePidFile(path: []const u8) void {
    std.fs.cwd().deleteFile(path) catch {};
}

/// Raise the file descriptor soft limit to the specified value.
///
/// Must be called BEFORE dropPrivileges() since setrlimit requires root
/// to raise above the default soft limit. If the requested value exceeds
/// the hard limit, it is clamped to the hard limit.
///
/// Use calculateFdNeed() to compute the value from MaxConnections config.
pub fn raiseFileLimit(needed: u64) void {
    var lim: c.rlimit = undefined;

    if (c.getrlimit(.NOFILE, &lim) == 0) {
        const target = @min(needed, lim.max);
        lim.cur = target;
        _ = c.setrlimit(.NOFILE, &lim);
        log_mod.info("file descriptor limit set to {d} (requested {d}, hard max {d})", .{ target, needed, lim.max });
    }
}

/// Calculate the file descriptor budget from worker count and max connections.
///
/// Formula: num_workers × (max_conn_per_worker + listeners + kqueue + pipe + dns_socket) + margin
/// Each worker needs: max_conn fds + 1 kqueue + N listeners + 1 pipe read-end + 1 DNS UDP socket
/// Plus global margin for: stdin/stdout/stderr(closed), PID file, config file, etc.
pub fn calculateFdNeed(num_workers: u32, max_connections: u32, num_listeners: u32) u64 {
    const per_worker: u64 = @as(u64, max_connections) + @as(u64, num_listeners) + 3; // +3 = kqueue + pipe + dns
    return @as(u64, num_workers) * per_worker + 64; // +64 margin for global fds
}

/// Signal set for kqueue-based signal handling.
///
/// The main thread registers these signals with EVFILT_SIGNAL
/// in its kqueue and blocks them with sigprocmask so they're
/// delivered via kevent rather than the default handler.
pub const ManagedSignals = struct {
    pub const SIGHUP = 1;
    pub const SIGTERM = 15;
    pub const SIGINT = 2;
    pub const SIGPIPE = 13;

    /// Block signals before spawning any thread. A thread inherits the mask
    /// in force at creation; unblocked threads receive the default handler
    /// (e.g., SIGHUP terminates with no core, audit X-7). Must be called
    /// before any thread creation, not only before the worker pool.
    pub fn blockForKqueue() void {
        var set = std.mem.zeroes(c.sigset_t);
        _ = c.sigaddset(&set, SIGHUP);
        _ = c.sigaddset(&set, SIGTERM);
        _ = c.sigaddset(&set, SIGINT);
        _ = c.sigaddset(&set, SIGPIPE);
        _ = c.sigprocmask(c.SIG.BLOCK, &set, null);
    }

    /// Wait for SIGTERM/SIGINT via sigwait, then close the shutdown pipe.
    /// Closing triggers EV_EOF on all worker kqueues, waking every worker.
    /// Call `blockForKqueue()` before spawning threads.
    pub fn waitForShutdown(shutdown_pipe_wr: posix.fd_t) void {
        var set = std.mem.zeroes(c.sigset_t);
        _ = c.sigaddset(&set, SIGTERM);
        _ = c.sigaddset(&set, SIGINT);

        var sig: c_int = 0;
        _ = c.sigwait(&set, &sig);

        log_mod.info("shutdown signal {d} received, draining connections...", .{sig});

        // Close write end — triggers EV_EOF on all worker kqueues
        // (persistent state, wakes all N workers regardless of timing)
        posix.close(shutdown_pipe_wr);
    }

    /// Signal loop: SIGHUP triggers reload; SIGTERM/SIGINT closes the shutdown
    /// pipe and exits. Only a sigwait candidate when actually parked in sigwait;
    /// during reload, signals go to unblocked threads.
    /// Call `blockForKqueue()` before spawning threads.
    pub fn signalLoop(shutdown_pipe_wr: posix.fd_t, reload_fn: ?*const fn () void) void {
        var set = std.mem.zeroes(c.sigset_t);
        _ = c.sigaddset(&set, SIGTERM);
        _ = c.sigaddset(&set, SIGINT);
        _ = c.sigaddset(&set, SIGHUP);

        while (true) {
            var sig: c_int = 0;
            _ = c.sigwait(&set, &sig);

            if (sig == SIGHUP) {
                log_mod.info("SIGHUP received, reloading configuration...", .{});
                if (reload_fn) |cb| cb();
            } else {
                log_mod.info("shutdown signal {d} received, draining connections...", .{sig});
                posix.close(shutdown_pipe_wr);
                return;
            }
        }
    }
};

test "write and remove pid file" {
    const path = "/tmp/securemilter-test.pid";

    try writePidFile(path);
    defer removePidFile(path);

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buf: [64]u8 = undefined;
    const n = try file.readAll(&buf);
    const content = std.mem.trimRight(u8, buf[0..n], "\n");
    const pid = try std.fmt.parseInt(i32, content, 10);
    try std.testing.expect(pid > 0);
}

// --- L-5: PID file held by live process ----------------------------------
// The self-case and rival-case are asserted separately, because "some live PID"
// and "a different live PID" are not the same fact and must not be conflated.

test "a pid file naming ourselves is not a second instance" {
    const path = "/tmp/securemilter-test-self.pid";
    defer removePidFile(path);

    // `daemon -p` leaves the supervisor's PID (us) before `writePidFile` runs.
    try writePidFile(path);

    try checkNotAlreadyRunning(path);
}

test "a pid file held by another live process is refused" {
    const path = "/tmp/securemilter-test-live.pid";
    defer removePidFile(path);

    // PID 1 is alive, not us, not our parent. `kill(1, 0)` may fail EPERM,
    // which `livePidFileHolder` reads as "exists" not "gone".
    {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("1\n");
    }

    // `AlreadyRunning` is the specific fault `bootstrap` refuses on; others
    // are logged and survived (a daemon that cannot write a PID file carries mail).
    try std.testing.expectError(error.AlreadyRunning, checkNotAlreadyRunning(path));

    // The refusal must not truncate the file.
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buf: [64]u8 = undefined;
    const n = try file.readAll(&buf);
    const held = try std.fmt.parseInt(c.pid_t, std.mem.trim(u8, buf[0..n], " \t\r\n"), 10);
    try std.testing.expectEqual(@as(c.pid_t, 1), held);
}

test "writing the pid file does not re-test for a rival" {
    // The pre-fork check must not be duplicated in `writePidFile`.
    // At this point the file names a live process (us), so a duplicate
    // check would break `daemon -p`.
    const path = "/tmp/securemilter-test-nocheck.pid";
    defer removePidFile(path);

    {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("1\n");
    }

    try writePidFile(path);

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buf: [64]u8 = undefined;
    const n = try file.readAll(&buf);
    const held = try std.fmt.parseInt(c.pid_t, std.mem.trim(u8, buf[0..n], " \t\r\n"), 10);
    try std.testing.expectEqual(c.getpid(), held);
}

test "a stale pid file is taken over" {
    const path = "/tmp/securemilter-test-stale.pid";
    defer removePidFile(path);

    // PID 0x7FFFFFFE: within pid_t, above any live process on a running system,
    // and not a wildcard the way 0 and -1 are in kill(2). A number that reads as
    // "no such process" is the whole point, so it must not be one kill()
    // interprets as a process group.
    {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("2147483646\n");
    }

    try writePidFile(path);

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buf: [64]u8 = undefined;
    const n = try file.readAll(&buf);
    const held = try std.fmt.parseInt(c.pid_t, std.mem.trim(u8, buf[0..n], " \t\r\n"), 10);
    try std.testing.expectEqual(c.getpid(), held);
}

test "a malformed pid file is taken over rather than refused" {
    const path = "/tmp/securemilter-test-junk.pid";
    defer removePidFile(path);

    // Malformed files mean no running instance; must not permanently block start.
    for ([_][]const u8{ "not-a-pid\n", "", "-1\n", "0\n" }) |content| {
        {
            const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
            defer file.close();
            try file.writeAll(content);
        }
        try writePidFile(path);
    }
}

// --- X-16: readiness handshake -------------------------------------------
// Tests the protocol (byte = up, EOF = failed, silence = wedged) without real forks.

test "X-16: the ready byte releases the parent" {
    const fds = try posix.pipe();
    defer posix.close(fds[0]);

    signalReady(fds[1]); // closes the write end
    try awaitReady(fds[0], 5);
}

test "X-16: a child that dies before signalling fails the parent" {
    // If the child exits before signalling, the parent must see EOF with no byte
    // as a failure, not as a successful start with nothing listening.
    const fds = try posix.pipe();
    defer posix.close(fds[0]);

    posix.close(fds[1]); // the child exits without signalling
    try std.testing.expectError(error.StartupFailed, awaitReady(fds[0], 5));
}

test "X-16: a wedged child does not hang the parent forever" {
    // Open write end with no signal = wedged daemon (e.g., blocked on DNS/lock).
    // A bounded timeout prevents `service start` from hanging forever.
    const fds = try posix.pipe();
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    try std.testing.expectError(error.StartupTimedOut, awaitReady(fds[0], 0));
}

test "X-16: the parent rejects a byte it did not agree to" {
    // An unrelated inherited descriptor writing into the pipe must not be read as
    // a successful start.
    const fds = try posix.pipe();
    defer posix.close(fds[0]);

    _ = try posix.write(fds[1], "?");
    posix.close(fds[1]);
    try std.testing.expectError(error.StartupFailed, awaitReady(fds[0], 5));
}
