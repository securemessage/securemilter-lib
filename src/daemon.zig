const std = @import("std");
const posix = std.posix;
const c = std.c;
const log_mod = @import("log.zig");
const credentials = @import("credentials.zig");

/// Ready byte: 'K' signals the daemon is serving.
/// A fixed value prevents misreading an unrelated descriptor value as success.
const ready_byte: u8 = 'K';

/// Startup timeout in seconds. A blocked daemon must fail; a blocked `service start`
/// must fail rather than hang forever.
pub const startup_timeout_s: isize = 60;

/// Double-fork daemonization: setsid, close fds, return the readiness
/// pipe's write end. The parent (see `awaitReady`) reads the other end: a
/// byte means the daemon is serving, EOF means it failed before that.
///
/// The caller must not treat a returned fd alone as success and must wait
/// for `signalReady` to actually be called once listeners are bound and
/// workers are running — daemonizing only forks and detaches, it proves
/// nothing about whether the daemon goes on to listen.
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
/// After the fork, the file may name our own ancestor (`daemon -p`) rather
/// than a rival, and the two cannot be told apart; running before the fork
/// avoids that ambiguity.
pub fn checkNotAlreadyRunning(path: []const u8) !void {
    const holder = livePidFileHolder(path) orelse return;
    if (holder == c.getpid() or holder == c.getppid()) return;

    log_mod.err(
        "pid file {s} is held by live process {d}; refusing to start a second instance",
        .{ path, holder },
    );
    return error.AlreadyRunning;
}

/// Create the directory containing `file_path` if it does not exist, and
/// chown it to `owner` if given. Used for the PID file directory and for
/// Unix socket directories. Must be called while still root, since only
/// root can chown; only unprivileged code writes into the directory
/// afterward (writePidFile, bind()).
///
/// Chowning lets the unprivileged process later unlink its PID file and
/// socket at shutdown. It also sets the group new files get created with
/// inside the directory (BSD group-inheritance), which determines the
/// group of any Unix socket bound there and therefore who can connect to it.
///
/// All failures are logged and non-fatal: `writePidFile` and `bind()` fail
/// on the same underlying condition and are already handled there.
pub fn ensureRuntimeDirectory(file_path: []const u8, owner: ?credentials.UserGroup) void {
    const dir = std.fs.path.dirnamePosix(file_path) orelse return;
    if (dir.len == 0) return;

    ensureDirectory(dir);
    if (owner) |ug| chownDirectory(dir, ug);
}

/// Create `dir` at mode 0755 if it does not exist: owner rwx, group/other
/// r-x, so the directory is traversable.
///
/// The mode is set explicitly with `fchmod` after creation because
/// `makeDirAbsolute` applies the process umask, and a milter's umask
/// (typically 0117) would strip the execute bits a directory needs to be
/// traversable. Does not touch the mode of a directory that already exists.
fn ensureDirectory(dir: []const u8) void {
    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        else => {
            log_mod.warn("mkdir {s}: {}", .{ dir, err });
            return;
        },
    };

    var d = std.fs.openDirAbsolute(dir, .{}) catch |err| {
        log_mod.warn("open {s}: {}", .{ dir, err });
        return;
    };
    defer d.close();
    posix.fchmod(d.fd, 0o755) catch |err| log_mod.warn("chmod {s}: {}", .{ dir, err });
}

/// chown `dir` to `owner`. Also chowns directories that already existed
/// (e.g. created by the operator and left root-owned), since the daemon has
/// no way to fix ownership itself once privileges are dropped.
fn chownDirectory(dir: []const u8, owner: credentials.UserGroup) void {
    var d = std.fs.openDirAbsolute(dir, .{}) catch |err| {
        log_mod.warn("open {s}: {}", .{ dir, err });
        return;
    };
    defer d.close();
    posix.fchown(d.fd, owner.uid, owner.gid) catch |err|
        log_mod.warn("chown {s}: {}", .{ dir, err });
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
    /// in force at creation; an unblocked thread would receive these
    /// signals via the default handler (e.g. SIGHUP terminates the process
    /// with no core). Must be called before any thread creation, not only
    /// before the worker pool.
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

// --- PID file held by a live process --------------------------------------
// The self-case and rival-case are asserted separately: "a live PID" and
// "a different live PID" are distinct conditions with different outcomes.

test "a pid file naming ourselves is not a second instance" {
    const path = "/tmp/securemilter-test-self.pid";
    defer removePidFile(path);

    // Simulates `daemon -p`, which writes the supervisor's PID (us) before
    // `writePidFile` runs.
    try writePidFile(path);

    try checkNotAlreadyRunning(path);
}

test "a pid file held by another live process is refused" {
    const path = "/tmp/securemilter-test-live.pid";
    defer removePidFile(path);

    // PID 1 is alive, not us, not our parent. `kill(1, 0)` may fail EPERM,
    // which `livePidFileHolder` must still read as "exists", not "gone".
    {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("1\n");
    }

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

// --- readiness handshake ---------------------------------------------------
// Tests the pipe protocol (byte = up, EOF = failed, no event = wedged)
// directly, without a real fork.

test "the ready byte releases the parent" {
    const fds = try posix.pipe();
    defer posix.close(fds[0]);

    signalReady(fds[1]); // closes the write end
    try awaitReady(fds[0], 5);
}

test "a child that dies before signalling fails the parent" {
    // EOF with no byte read must be reported as a failure, not as a
    // successful start with nothing listening.
    const fds = try posix.pipe();
    defer posix.close(fds[0]);

    posix.close(fds[1]); // the child exits without signalling
    try std.testing.expectError(error.StartupFailed, awaitReady(fds[0], 5));
}

test "a wedged child does not hang the parent forever" {
    // Write end open with nothing written simulates a daemon blocked before
    // it can signal (e.g. on DNS or a lock). The bounded timeout must fire
    // rather than hang `service start` forever.
    const fds = try posix.pipe();
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    try std.testing.expectError(error.StartupTimedOut, awaitReady(fds[0], 0));
}

test "the parent rejects a byte it did not agree to" {
    // Any byte other than `ready_byte` must not be read as a successful
    // start, in case an unrelated inherited descriptor writes into the pipe.
    const fds = try posix.pipe();
    defer posix.close(fds[0]);

    _ = try posix.write(fds[1], "?");
    posix.close(fds[1]);
    try std.testing.expectError(error.StartupFailed, awaitReady(fds[0], 5));
}
