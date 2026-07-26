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

    /// Wait for a shutdown signal (SIGTERM/SIGINT) using kqueue EVFILT_SIGNAL.
    ///
    /// Blocks until a signal is received, then sets the shutdown flag.
    /// Call blockForKqueue() before spawning workers so signals are
    /// delivered via kqueue rather than the default handler.
    pub fn waitForShutdown(shutdown: *std.atomic.Value(bool)) void {
        const kq = posix.kqueue() catch return;
        defer posix.close(kq);

        const events = [_]posix.Kevent{
            .{
                .ident = @intCast(SIGTERM),
                .filter = c.EVFILT.SIGNAL,
                .flags = c.EV.ADD | c.EV.ENABLE,
                .fflags = 0,
                .data = 0,
                .udata = 0,
                ._ext = .{ 0, 0, 0, 0 },
            },
            .{
                .ident = @intCast(SIGINT),
                .filter = c.EVFILT.SIGNAL,
                .flags = c.EV.ADD | c.EV.ENABLE,
                .fflags = 0,
                .data = 0,
                .udata = 0,
                ._ext = .{ 0, 0, 0, 0 },
            },
        };

        var out: [2]posix.Kevent = undefined;
        _ = posix.kevent(kq, &events, &out, null) catch return;

        std.log.info("shutdown signal received, draining connections...", .{});
        shutdown.store(true, .release);
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
