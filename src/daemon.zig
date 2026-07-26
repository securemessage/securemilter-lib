const std = @import("std");
const posix = std.posix;
const c = std.c;

/// Daemonize the current process (double-fork, setsid, close fds).
///
/// After this call, the process is running as a background daemon
/// with no controlling terminal. stdin/stdout/stderr are redirected
/// to /dev/null.
pub fn daemonize() !void {
    const pid1 = try posix.fork();
    if (pid1 != 0) posix.exit(0);

    _ = c.setsid();

    const pid2 = try posix.fork();
    if (pid2 != 0) posix.exit(0);

    const devnull = try posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    try posix.dup2(devnull, 0);
    try posix.dup2(devnull, 1);
    try posix.dup2(devnull, 2);
    if (devnull > 2) posix.close(devnull);
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

/// Raise the file descriptor limit to the system maximum.
///
/// Must be called BEFORE dropPrivileges() since setrlimit may require
/// root to raise above the default soft limit. Sets both soft and hard
/// limits to the kernel's maximum (typically 1048576 on FreeBSD).
pub fn raiseFileLimit() void {
    var lim: c.rlimit = undefined;

    if (c.getrlimit(.NOFILE, &lim) == 0) {
        lim.cur = lim.max;
        _ = c.setrlimit(.NOFILE, &lim);
        std.log.info("file descriptor limit raised to {d}", .{lim.max});
    }
}

/// Drop privileges to the specified user.
///
/// Looks up the user by name via getpwnam, then calls setgid + setuid.
/// Must be called as root before entering the event loop.
pub fn dropPrivileges(username: []const u8) !void {
    var name_buf: [256:0]u8 = undefined;
    if (username.len >= name_buf.len) return error.UsernameTooLong;
    @memcpy(name_buf[0..username.len], username);
    name_buf[username.len] = 0;

    const pw = c.getpwnam(&name_buf);
    if (pw == null) return error.UserNotFound;

    const passwd = pw.?;
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

    /// Block signals so they're delivered via kqueue EVFILT_SIGNAL.
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
    /// Call blockForKqueue() before spawning workers so signals are
    /// blocked in all threads and delivered only via sigwait here.
    pub fn waitForShutdown(shutdown_pipe_wr: posix.fd_t) void {
        var set = std.mem.zeroes(c.sigset_t);
        _ = c.sigaddset(&set, SIGTERM);
        _ = c.sigaddset(&set, SIGINT);

        var sig: c_int = 0;
        _ = c.sigwait(&set, &sig);

        std.log.info("shutdown signal {d} received, draining connections...", .{sig});

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
    /// Call blockForKqueue() before spawning workers.
    pub fn signalLoop(shutdown_pipe_wr: posix.fd_t, reload_fn: ?*const fn () void) void {
        var set = std.mem.zeroes(c.sigset_t);
        _ = c.sigaddset(&set, SIGTERM);
        _ = c.sigaddset(&set, SIGINT);
        _ = c.sigaddset(&set, SIGHUP);

        while (true) {
            var sig: c_int = 0;
            _ = c.sigwait(&set, &sig);

            if (sig == SIGHUP) {
                std.log.info("SIGHUP received, reloading configuration...", .{});
                if (reload_fn) |cb| cb();
            } else {
                std.log.info("shutdown signal {d} received, draining connections...", .{sig});
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
