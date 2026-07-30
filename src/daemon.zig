const std = @import("std");
const posix = std.posix;
const c = std.c;
const log_mod = @import("log.zig");

extern "c" fn setgroups(ngroups: c_int, gidset: ?[*]const c.gid_t) c_int;

/// The byte a daemon sends its waiting parent once it is actually serving.
///
/// A specific value rather than any byte: the write end is inherited across two
/// forks and nothing stops an unrelated descriptor from landing on the same
/// number. Success is the one claim this protocol must not make by accident.
const ready_byte: u8 = 'K';

/// How long the parent waits for that byte before giving up, in seconds.
///
/// Waiting forever would convert a daemon wedged during startup into a wedged
/// `service start`, which is a different failure with the same symptom as the one
/// being fixed. Generous enough to cover a slow first DNS resolution.
pub const startup_timeout_s: isize = 60;

/// Daemonize the current process (double-fork, setsid, close fds).
///
/// Returns the write end of the readiness pipe. The caller MUST hand it to
/// `signalReady` once the daemon is genuinely serving, and must otherwise leave
/// it alone: the parent is blocked on the read end and treats its closure without
/// a byte as a failed start.
///
/// THE PARENT NO LONGER EXITS IMMEDIATELY, and that is the entire point (X-16).
/// `daemonize` is bootstrap's first step and listeners are bound long after it
/// returns, so the original process used to answer `service start` with 0 before
/// anything had been tried. Measured: an unbindable listener gave exit 0, nothing
/// listening, and no process. `rc.d` reported a started service; Postfix could
/// not reach the milter, and a receiver running `milter_default_action=accept`
/// takes mail unauthenticated. One typo in a listener address reaches that.
pub fn daemonize() !posix.fd_t {
    // Created before the first fork so both ends survive into the grandchild.
    //
    // CLOEXEC does not affect fork, which is what carries the write end where it
    // needs to go. It covers the other direction: anything this daemon ever execs
    // would otherwise inherit a live write end, and the parent would then wait on a
    // pipe that no longer closes when the daemon dies.
    const ready = try posix.pipe2(.{ .CLOEXEC = true });

    // Cleanup is per-fork rather than a function-wide errdefer: the child closes the
    // read end below, so a single errdefer covering both would double-close it on any
    // later failure -- and by then the number may belong to something else.
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
    // The intermediate process exits without signalling. Its copy of the write end
    // is closed by exiting, which is why the parent must not treat one closure as
    // EOF -- the read only reports EOF once the LAST copy is gone, and the daemon
    // still holds one.
    if (pid2 != 0) posix.exit(0);

    const devnull = try posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    try posix.dup2(devnull, 0);
    try posix.dup2(devnull, 1);
    try posix.dup2(devnull, 2);
    if (devnull > 2) posix.close(devnull);

    return ready[1];
}

/// Tell the waiting parent the daemon is up, then close the pipe.
///
/// Call this only once listeners are bound and workers are running. Signalling
/// earlier would restore the defect with extra steps: the parent would again be
/// reporting success for work that had not happened yet.
pub fn signalReady(wr: posix.fd_t) void {
    _ = posix.write(wr, &[_]u8{ready_byte}) catch {};
    posix.close(wr);
}

/// Block until the daemon reports readiness, it dies, or `timeout_s` elapses.
///
/// Three outcomes, and they are deliberately distinct. EOF without a byte means
/// the daemon exited during startup -- the case that used to report success.
/// A timeout means it is still alive but not serving, which is neither a clean
/// start nor a clean failure and should not be reported as either.
fn awaitReady(rd: posix.fd_t, timeout_s: isize) !void {
    const kq = try posix.kqueue();
    defer posix.close(kq);

    // Registration and wait in one syscall, which is the reason to use kqueue at
    // all rather than reaching for poll.
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

/// Write the current PID to a file.
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

/// Drop privileges to the specified user.
///
/// Looks up the user by name via getpwnam, then calls setgroups (clear
/// supplementary groups) + setgid + setuid. Order matters: setgroups
/// requires root, so it must come before setuid.
/// Must be called as root before entering the event loop.
pub fn dropPrivileges(username: []const u8) !void {
    var name_buf: [256:0]u8 = undefined;
    if (username.len >= name_buf.len) return error.UsernameTooLong;
    @memcpy(name_buf[0..username.len], username);
    name_buf[username.len] = 0;

    const pw = c.getpwnam(&name_buf);
    if (pw == null) return error.UserNotFound;

    const passwd = pw.?;

    // Clear supplementary groups — prevents inheriting root's group memberships
    if (setgroups(0, null) != 0) return error.SetgroupsFailed;
    if (c.setgid(passwd.gid) != 0) return error.SetgidFailed;
    if (c.setuid(passwd.uid) != 0) return error.SetuidFailed;
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

    /// Block the managed signals in the calling thread so they can only be
    /// taken by `sigwait` in the signal loop.
    ///
    /// Call this before spawning *any* thread, not merely before the worker
    /// pool. `sigprocmask` affects one thread, and a new thread inherits the
    /// mask in force when it is created, so every thread spawned before this
    /// call keeps the signals unblocked. That is not cosmetic: while the main
    /// thread is away from `sigwait` running a reload, the kernel delivers a
    /// SIGHUP to the first thread that does not block it, and the default
    /// action there terminates the process — with no core and no kernel log
    /// line, because SIGHUP does not dump core (audit X-7).
    pub fn blockForKqueue() void {
        var set = std.mem.zeroes(c.sigset_t);
        _ = c.sigaddset(&set, SIGHUP);
        _ = c.sigaddset(&set, SIGTERM);
        _ = c.sigaddset(&set, SIGINT);
        _ = c.sigaddset(&set, SIGPIPE);
        _ = c.sigprocmask(c.SIG.BLOCK, &set, null);
    }

    /// Wait for a shutdown signal (SIGTERM/SIGINT) using sigwait,
    /// then write to the shutdown pipe to wake all worker threads.
    ///
    /// Call blockForKqueue() before spawning any thread so signals are
    /// blocked in all of them and delivered only via sigwait here.
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

    /// Signal loop that handles both SIGHUP (reload) and SIGTERM/SIGINT (shutdown).
    ///
    /// On SIGHUP: calls the reload callback, then continues waiting.
    /// On SIGTERM/SIGINT: closes the shutdown pipe and returns.
    ///
    /// This replaces waitForShutdown() when live reload is desired.
    ///
    /// Call blockForKqueue() before spawning any thread. Note that this loop is
    /// only a sigwait candidate while it is actually parked in sigwait: for as
    /// long as `reload_fn` is running, a signal arriving must go to some other
    /// thread, and any thread that does not block it will act on it.
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

// --- X-16(a): the readiness handshake ----------------------------------------
//
// These run against a real pipe rather than a real fork. The protocol is what is
// worth testing and it is fully observable from one process: a byte means the
// daemon came up, EOF without a byte means it died on the way, and neither
// arriving means it is wedged. Forking inside the test runner would test
// `posix.fork` and cost the ability to assert anything.

test "X-16: the ready byte releases the parent" {
    const fds = try posix.pipe();
    defer posix.close(fds[0]);

    signalReady(fds[1]); // closes the write end
    try awaitReady(fds[0], 5);
}

test "X-16: a child that dies before signalling fails the parent" {
    // This is the measured defect. The daemon exits during startup, its copy of
    // the write end closes, and the parent sees EOF with no byte. Before this
    // handshake existed the parent had already exited 0 and `rc.d` reported a
    // started service with nothing listening.
    const fds = try posix.pipe();
    defer posix.close(fds[0]);

    posix.close(fds[1]); // the child exits without signalling
    try std.testing.expectError(error.StartupFailed, awaitReady(fds[0], 5));
}

test "X-16: a wedged child does not hang the parent forever" {
    // The write end stays open and silent, which is what a daemon stuck resolving
    // DNS or blocked on a lock looks like. Waiting forever would turn a hung start
    // into a hung `service start`, so the wait is bounded and the timeout is
    // distinguishable from a clean failure.
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
