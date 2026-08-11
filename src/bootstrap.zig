//! Orchestrates daemon startup in the required order.
//!
//! `daemon.zig` implements the individual privileged operations (fork, write
//! a PID file, raise a limit, drop privileges); this module sequences them.
//! Changes to one operation belong in `daemon.zig`; changes to the startup
//! order belong here.

const std = @import("std");
const posix = std.posix;
const daemon = @import("daemon.zig");
const credentials = @import("credentials.zig");
const log_mod = @import("log.zig");
const listener_mod = @import("listener.zig");

/// What a daemon needs to come up, in one place.
pub const Options = struct {
    /// Skip `daemonize`, staying attached to the terminal.
    foreground: bool,
    pid_file: []const u8,
    /// Unprivileged user to become, as `user` or `user:group`. Null leaves
    /// privileges alone.
    user: ?[]const u8,

    /// File-creation mask applied before the PID file and any Unix listener
    /// are created. Null leaves the supervisor's umask in place.
    ///
    /// This is the only supported way to control a Unix socket's
    /// permissions: `bind()` applies the umask at creation, and a `chmod`
    /// afterward would leave the socket briefly at the wider mode.
    umask: ?posix.mode_t = null,
    /// 0 means "one per CPU", resolved by `run` and reported back.
    worker_threads: u32,
    max_connections: u32,
    num_listeners: u32,

    /// Listener addresses. For each `.unix` entry, the parent directory is
    /// created and chowned to `user` while still privileged (see
    /// `ensure_runtime_dir` in `Ops`), so `bind()` succeeds after the
    /// privilege drop without requiring the directory to exist beforehand.
    listen_addresses: []const listener_mod.ListenAddress = &.{},

    /// Spawn long-lived threads (e.g. DNS health monitor). Passed as a
    /// callback to avoid an import cycle (`dns` imports `daemon`), and
    /// invoked only after `daemonize` (fork keeps only the calling thread)
    /// and after signals are blocked (a new thread inherits the mask in
    /// force when it is created).
    spawn_threads: ?*const fn () void = null,
};

/// What the caller needs back afterwards.
pub const Bootstrap = struct {
    pid_file: []const u8,
    /// `worker_threads` with 0 resolved to the CPU count.
    workers: u32,

    /// Write end of the readiness pipe, or null in the foreground (no fork,
    /// nobody waiting). Signalled by `notifyReady`, not set here.
    ready_fd: ?posix.fd_t = null,
    signal_ready: *const fn (posix.fd_t) void = daemon.signalReady,

    /// Signal readiness on the pipe `run` returned. Call once listeners are
    /// bound and workers are running: `run` itself returns before either
    /// happens, so it cannot call this on the caller's behalf. Idempotent
    /// (clears `ready_fd` after signalling); no-op in the foreground, where
    /// there is no pipe.
    pub fn notifyReady(self: *Bootstrap) void {
        if (self.ready_fd) |fd| {
            self.ready_fd = null;
            self.signal_ready(fd);
        }
    }

    /// Remove the PID file. Call via `defer` in `main`, not inside `run`:
    /// the file must outlive `run`'s stack frame for the rest of the
    /// process's life, and Zig's `defer` is scoped to the function that
    /// registers it.
    pub fn deinit(self: Bootstrap) void {
        daemon.removePidFile(self.pid_file);
    }
};

/// Injectable syscall-level steps, defaulting to the real implementations in
/// `daemon.zig`/`credentials.zig`. Tests substitute recording stubs to
/// assert call order in `runWithOps`, since fork/setuid/signal-masking
/// cannot run inside the test process itself.
pub const Ops = struct {
    daemonize: *const fn () anyerror!posix.fd_t = daemon.daemonize,
    reinit_log: *const fn () void = log_mod.initThread,
    block_signals: *const fn () void = daemon.ManagedSignals.blockForKqueue,
    signal_ready: *const fn (posix.fd_t) void = daemon.signalReady,
    check_not_running: *const fn ([]const u8) anyerror!void = daemon.checkNotAlreadyRunning,
    ensure_runtime_dir: *const fn ([]const u8, ?credentials.UserGroup) void = daemon.ensureRuntimeDirectory,
    write_pid_file: *const fn ([]const u8) anyerror!void = daemon.writePidFile,
    remove_pid_file: *const fn ([]const u8) void = daemon.removePidFile,
    raise_file_limit: *const fn (u64) void = daemon.raiseFileLimit,
    drop_privileges: *const fn ([]const u8) anyerror!void = credentials.dropPrivileges,
    set_umask: *const fn (posix.mode_t) void = credentials.setUmask,
};

/// Bring the daemon up: daemonize, block signals, spawn threads, claim the PID file,
/// raise the fd budget, drop privileges.
///
/// Ordering constraints enforced by the sequence below:
/// 0. Check for a running instance before `daemonize` (only answerable before the fork).
/// 1. `daemonize` before spawning threads (`fork` carries only the calling thread).
/// 2. Block signals before spawning threads (a new thread inherits the mask in force at creation).
/// 3. Reinit the log after `daemonize` (the PID changed).
/// 4. Write the PID file before dropping privileges (`/var/run` is not writable by the unprivileged user).
/// 5. Raise the fd limit before dropping privileges (raising above the soft limit needs root).
/// 6. Set the umask first (it only filters mode at file-creation time).
///
/// A failed PID file write is logged and non-fatal. A failed `daemonize` or
/// privilege drop is fatal, as is a confirmed running instance (`SO_REUSEPORT`
/// would let a second copy bind and split mail between two configurations).
/// The readiness pipe (`Bootstrap.notifyReady`) reports startup failure back
/// to the parent/`service start`.
pub fn run(opts: Options) !Bootstrap {
    return runWithOps(opts, .{});
}

/// `run` with the steps substituted. For tests; production calls `run`.
pub fn runWithOps(opts: Options, ops: Ops) !Bootstrap {
    // (6) Set first, so it applies to the PID file below and to the
    // listeners the caller binds after `run` returns.
    if (opts.umask) |mask| ops.set_umask(mask);

    // (0) Must run before `daemonize`. Before the fork, a live PID-file
    // holder that is not us is unambiguously a second instance. After the
    // fork this is no longer decidable: `daemon -p` writes our own
    // ancestor's pid into the file, and the double fork has orphaned us to
    // init (see `checkNotAlreadyRunning`).
    //
    // Fatal rather than a warning: `SO_REUSEPORT` lets a second instance
    // bind successfully, and two daemons would then split mail between two
    // configurations. The caller's readiness pipe reports this failure
    // back to `service start`.
    try ops.check_not_running(opts.pid_file);

    var ready_fd: ?posix.fd_t = null;
    if (!opts.foreground) {
        ready_fd = ops.daemonize() catch |err| {
            log_mod.err("daemonize failed: {}", .{err});
            return err;
        };
        // (3) after the fork, because the PID in every subsequent line changed.
        ops.reinit_log();
    }

    // (2) Must run before `spawn_threads` below and before the worker pool
    // the caller starts after `run` returns: a new thread inherits whatever
    // signal mask is in force when it is created.
    ops.block_signals();

    // (1) and (2) are both satisfied at this point, and nowhere earlier.
    if (opts.spawn_threads) |spawn| spawn();

    // (4) still privileged here. Create and chown the PID file's directory
    // and each Unix listener's directory before dropping privileges, since
    // only root can chown. `resolveUserGroup` runs once so these directories
    // and the drop below use the same uid/gid. If resolution fails here, the
    // chown is skipped, but `drop_privileges` resolves the same spec below
    // and fails the start on the same error.
    const owner: ?credentials.UserGroup = if (opts.user) |spec|
        credentials.resolveUserGroup(spec) catch |err| blk: {
            log_mod.warn("resolving '{s}' for runtime directories failed: {}", .{ spec, err });
            break :blk null;
        }
    else
        null;

    ops.ensure_runtime_dir(opts.pid_file, owner);
    for (opts.listen_addresses) |la| {
        switch (la) {
            .unix => |ux| ops.ensure_runtime_dir(ux.path, owner),
            .tcp => {},
        }
    }

    // `pid_file_is_ours` is tracked rather than inferred later from the file
    // existing: if the write failed, some other instance may own that path,
    // and removing it on the way out would be wrong. A write failure is
    // logged and non-fatal — the fatal case, another live instance, was
    // already ruled out by `check_not_running` above, so this daemon should
    // keep serving mail even without a PID file.
    var pid_file_is_ours = false;
    if (ops.write_pid_file(opts.pid_file)) {
        pid_file_is_ours = true;
    } else |err| {
        log_mod.err("pid file write failed: {}", .{err});
    }

    // Covers the window between claiming the PID file and `run` returning.
    // The caller's `defer boot.deinit()` cannot cover it: that defer is only
    // registered once `run` has already returned. Without this, a
    // privilege drop that fails below would leave a PID file naming a
    // process that no longer exists.
    errdefer if (pid_file_is_ours) ops.remove_pid_file(opts.pid_file);

    const workers = if (opts.worker_threads == 0)
        @as(u32, @intCast(std.Thread.getCpuCount() catch 4))
    else
        opts.worker_threads;

    // (5) still privileged here too.
    ops.raise_file_limit(daemon.calculateFdNeed(workers, opts.max_connections, opts.num_listeners));

    if (opts.user) |user| {
        ops.drop_privileges(user) catch |err| {
            log_mod.err("privilege drop to '{s}' failed: {}", .{ user, err });
            return err;
        };
    }

    // `ready_fd` is returned unsignalled: nothing above proves the daemon
    // can serve, since the listeners are not bound yet. If an error path
    // above had returned instead, the fd would close with the process and
    // the parent would read EOF.
    return .{
        .pid_file = opts.pid_file,
        .workers = workers,
        .ready_fd = ready_fd,
        .signal_ready = ops.signal_ready,
    };
}

/// Format a fatal-exit message that names `e`, so an operator can tell which
/// of several possible startup failures occurred.
pub fn fatalMessage(buf: []u8, e: anyerror) []const u8 {
    return std.fmt.bufPrint(buf, "fatal: exiting on {s}", .{@errorName(e)}) catch
        // Only reachable if `buf` cannot hold even the error name. Still says the one
        // thing that must never be lost: this process is stopping on an error.
        "fatal: exiting on an error whose name did not fit";
}

/// Log `e` and return it unchanged, for use as `main`'s top-level catch
/// body (so the process still exits non-zero). After `daemonize`, stderr is
/// /dev/null, so `log_mod.err` (syslog) is the only channel this reaches.
pub fn fatal(e: anyerror) anyerror {
    var buf: [256]u8 = undefined;
    log_mod.err("{s}", .{fatalMessage(&buf, e)});
    return e;
}

// --- ordering ----------------------------------------------------------------
//
// Each test asserts a pairwise ordering constraint (e.g. "signals before
// threads"), not one fixed overall sequence. Steps with no constraint
// between them, like the PID file write and the fd-limit raise, are free to
// reorder without failing a test.

const Step = enum { check_running, daemonize, reinit_log, block_signals, spawn_threads, ensure_runtime_dir, write_pid, remove_pid, raise_fd, drop_privs, signal_ready, set_umask };

var recorded: [16]Step = undefined;
var recorded_len: usize = 0;

fn record(s: Step) void {
    if (recorded_len < recorded.len) {
        recorded[recorded_len] = s;
        recorded_len += 1;
    }
}

/// Stand-in for the readiness pipe's write end. Never actually written to:
/// `signal_ready` is recorded, not invoked, so this only needs to be a
/// distinguishable value.
const fake_ready_fd: posix.fd_t = 4242;

fn recCheckRunning(_: []const u8) anyerror!void {
    record(.check_running);
}
fn recDaemonize() anyerror!posix.fd_t {
    record(.daemonize);
    return fake_ready_fd;
}
fn recReinitLog() void {
    record(.reinit_log);
}
fn recBlockSignals() void {
    record(.block_signals);
}
fn recSpawnThreads() void {
    record(.spawn_threads);
}
fn recEnsureRuntimeDir(_: []const u8, _: ?credentials.UserGroup) void {
    record(.ensure_runtime_dir);
}
fn recWritePid(_: []const u8) anyerror!void {
    record(.write_pid);
}
fn recRemovePid(_: []const u8) void {
    record(.remove_pid);
}
fn recSignalReady(_: posix.fd_t) void {
    record(.signal_ready);
}
fn recRaiseFd(_: u64) void {
    record(.raise_fd);
}
fn recDropPrivs(_: []const u8) anyerror!void {
    record(.drop_privs);
}
fn recSetUmask(_: posix.mode_t) void {
    record(.set_umask);
}

const recording_ops = Ops{
    .check_not_running = recCheckRunning,
    .daemonize = recDaemonize,
    .reinit_log = recReinitLog,
    .block_signals = recBlockSignals,
    .signal_ready = recSignalReady,
    .ensure_runtime_dir = recEnsureRuntimeDir,
    .write_pid_file = recWritePid,
    .remove_pid_file = recRemovePid,
    .raise_file_limit = recRaiseFd,
    .drop_privileges = recDropPrivs,
    .set_umask = recSetUmask,
};

fn runRecorded(opts: Options) !Bootstrap {
    recorded_len = 0;
    return runWithOps(opts, recording_ops);
}

fn indexOf(s: Step) ?usize {
    for (recorded[0..recorded_len], 0..) |got, i| {
        if (got == s) return i;
    }
    return null;
}

/// Assert `first` happened, `second` happened, and `first` came first.
fn expectBefore(first: Step, second: Step) !void {
    const a = indexOf(first) orelse {
        std.debug.print("step {s} never ran\n", .{@tagName(first)});
        return error.StepMissing;
    };
    const b = indexOf(second) orelse {
        std.debug.print("step {s} never ran\n", .{@tagName(second)});
        return error.StepMissing;
    };
    if (a >= b) {
        std.debug.print("{s} must precede {s}, got order:", .{ @tagName(first), @tagName(second) });
        for (recorded[0..recorded_len]) |s| std.debug.print(" {s}", .{@tagName(s)});
        std.debug.print("\n", .{});
        return error.WrongOrder;
    }
}

const test_opts = Options{
    .foreground = false,
    .pid_file = "/tmp/securemilter-bootstrap-test.pid",
    .user = "nobody",
    .worker_threads = 2,
    .max_connections = 100,
    .num_listeners = 1,
    .spawn_threads = recSpawnThreads,
};

test "the managed signals are blocked before any thread is spawned" {
    // sigprocmask affects only the calling thread; a new thread inherits
    // whatever mask is in force when it is created. A thread spawned before
    // this point would receive SIGHUP/SIGTERM/SIGINT/SIGPIPE via the
    // default handler instead of leaving them queued for sigwait.
    _ = try runRecorded(test_opts);
    try expectBefore(.block_signals, .spawn_threads);
}

test "threads are spawned after daemonize, because fork keeps only the caller" {
    _ = try runRecorded(test_opts);
    try expectBefore(.daemonize, .spawn_threads);
}

test "the already-running check runs before daemonize" {
    // After the fork, a PID file may name our own ancestor (`daemon -p`) or
    // an orphaned child of init, so a live holder can no longer be told
    // apart from a rival instance. The check must run while that
    // distinction is still answerable.
    _ = try runRecorded(test_opts);
    try expectBefore(.check_running, .daemonize);
    try expectBefore(.check_running, .write_pid);
}

test "the log is re-initialised after daemonize, because the PID changed" {
    _ = try runRecorded(test_opts);
    try expectBefore(.daemonize, .reinit_log);
}

test "the PID file is written while still privileged" {
    // /var/run is not writable by the unprivileged user, so a drop first means no PID
    // file, which means nothing can signal the daemon a reload.
    _ = try runRecorded(test_opts);
    try expectBefore(.write_pid, .drop_privs);
}

test "the fd limit is raised while still privileged" {
    // setrlimit above the soft limit requires root. Dropping first silently caps the
    // daemon at the default, which surfaces later as refused connections under load
    // rather than as an error here.
    _ = try runRecorded(test_opts);
    try expectBefore(.raise_fd, .drop_privs);
}

test "runtime directories are prepared while root, one per directory that gets written" {
    // ensure_runtime_dir must run before write_pid, which writes into the PID
    // directory, and before drop_privs, after which mkdir/chown under
    // /var/run is no longer possible.
    var opts = test_opts;
    const addrs = [_]listener_mod.ListenAddress{
        .{ .unix = .{ .path = "/tmp/securemilter-bootstrap-test/milter.sock" } },
        .{ .tcp = .{ .host = "127.0.0.1", .port = 8891 } },
    };
    opts.listen_addresses = &addrs;
    _ = try runRecorded(opts);

    try expectBefore(.ensure_runtime_dir, .write_pid);
    try expectBefore(.ensure_runtime_dir, .drop_privs);

    // One call for the PID file's directory, one for the unix listener's.
    // The TCP listener has no filesystem path and must not produce a call.
    var n: usize = 0;
    for (recorded[0..recorded_len]) |s| {
        if (s == .ensure_runtime_dir) n += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), n);
}

test "the umask is set before anything is created" {
    // A mask is not applied to a file, it filters the mode the file is created with.
    // Set it after `write_pid` and the PID file keeps the supervisor's mask; the more
    // expensive version of the same mistake is the caller's unix socket, bound after
    // `run` returns, which is the file the option exists for.
    var opts = test_opts;
    opts.umask = 0o117;
    _ = try runRecorded(opts);

    try expectBefore(.set_umask, .write_pid);
    try std.testing.expectEqual(@as(usize, 0), indexOf(.set_umask).?);
}

test "no umask configured leaves the inherited one alone" {
    // Distinct from configuring 0: the daemon must not narrow -- or widen -- a mask
    // nobody asked it to touch.
    _ = try runRecorded(test_opts);
    try std.testing.expect(indexOf(.set_umask) == null);
}

test "foreground skips daemonize and its log re-init, but still blocks before spawning" {
    var opts = test_opts;
    opts.foreground = true;
    _ = try runRecorded(opts);

    try std.testing.expect(indexOf(.daemonize) == null);
    try std.testing.expect(indexOf(.reinit_log) == null);
    // The signal-blocking-before-threads constraint is independent of
    // daemonizing, and must hold either way.
    try expectBefore(.block_signals, .spawn_threads);
}

test "no user configured means privileges are left alone" {
    var opts = test_opts;
    opts.user = null;
    _ = try runRecorded(opts);

    try std.testing.expect(indexOf(.drop_privs) == null);
    try std.testing.expect(indexOf(.write_pid) != null);
}

test "worker_threads 0 resolves to the CPU count" {
    var opts = test_opts;
    opts.worker_threads = 0;
    const boot = try runRecorded(opts);

    try std.testing.expect(boot.workers >= 1);
    try std.testing.expectEqual(@as(u32, @intCast(std.Thread.getCpuCount() catch 4)), boot.workers);
}

test "a failed PID file write is survivable, but a failed privilege drop is not" {
    // A daemon with no PID file still serves mail, only harder to signal.
    // A daemon that failed to drop privileges is running as root without
    // having been asked to, so `runWithOps` must return the error.
    var ops = recording_ops;
    ops.write_pid_file = struct {
        fn f(_: []const u8) anyerror!void {
            return error.AccessDenied;
        }
    }.f;
    recorded_len = 0;
    _ = try runWithOps(test_opts, ops);
    try expectBefore(.raise_fd, .drop_privs);

    ops = recording_ops;
    ops.drop_privileges = struct {
        fn f(_: []const u8) anyerror!void {
            return error.SetuidFailed;
        }
    }.f;
    recorded_len = 0;
    try std.testing.expectError(error.SetuidFailed, runWithOps(test_opts, ops));
}

// --- readiness: signalled by the caller, not by bootstrap --------------------

test "run does not signal readiness, because nothing is listening yet" {
    // `run` returns before the listeners are bound and the worker pool
    // exists, so it must not signal readiness itself.
    const boot = try runRecorded(test_opts);
    try std.testing.expect(indexOf(.signal_ready) == null);
    try std.testing.expectEqual(fake_ready_fd, boot.ready_fd.?);
}

test "a bootstrap that fails never signals readiness" {
    // The fd closes with the process on this path, so the parent reads EOF
    // rather than the ready byte.
    var ops = recording_ops;
    ops.drop_privileges = struct {
        fn f(_: []const u8) anyerror!void {
            return error.SetuidFailed;
        }
    }.f;
    recorded_len = 0;

    try std.testing.expectError(error.SetuidFailed, runWithOps(test_opts, ops));
    try std.testing.expect(indexOf(.signal_ready) == null);
}

test "notifyReady signals once and only once" {
    // The second call must be a no-op: `ready_fd` is cleared and closed by
    // the first call, and writing to a closed (and possibly reused) fd
    // number would send a stray byte to whatever now owns it.
    var boot = try runRecorded(test_opts);
    recorded_len = 0;

    boot.notifyReady();
    try std.testing.expectEqual(@as(usize, 1), recorded_len);
    try std.testing.expect(indexOf(.signal_ready) != null);

    boot.notifyReady();
    try std.testing.expectEqual(@as(usize, 1), recorded_len);
}

test "in the foreground, notifyReady is a no-op" {
    // No fork means no pipe and no `ready_fd`; `notifyReady` must not
    // invent one to write to (fd 0 is stdin).
    var opts = test_opts;
    opts.foreground = true;
    var boot = try runRecorded(opts);
    try std.testing.expect(boot.ready_fd == null);

    recorded_len = 0;
    boot.notifyReady();
    try std.testing.expectEqual(@as(usize, 0), recorded_len);
}

// --- the PID file is removed only when it names a live process ---------------

test "a fatal privilege drop removes the PID file it wrote" {
    // The caller's `defer boot.deinit()` cannot cover this: it is only
    // registered once `run` has returned, and `run` returns an error here
    // instead. Without the `errdefer` in `runWithOps`, the PID file would
    // be left naming a process that no longer exists — the value `rc.d`
    // reads to decide whether the service is running.
    var ops = recording_ops;
    ops.drop_privileges = struct {
        fn f(_: []const u8) anyerror!void {
            return error.SetgroupsFailed;
        }
    }.f;
    recorded_len = 0;

    try std.testing.expectError(error.SetgroupsFailed, runWithOps(test_opts, ops));
    try expectBefore(.write_pid, .remove_pid);
}

test "a successful bootstrap keeps its PID file" {
    // Removal only happens on the error path above; removing it after a
    // successful start would leave a running daemon nothing could signal.
    _ = try runRecorded(test_opts);
    try std.testing.expect(indexOf(.remove_pid) == null);
}

test "a PID file we failed to write is not removed on the way out" {
    // If the write failed, the path may belong to another instance;
    // deleting it here would turn this daemon's failure into that one's.
    var ops = recording_ops;
    ops.write_pid_file = struct {
        fn f(_: []const u8) anyerror!void {
            return error.AccessDenied;
        }
    }.f;
    ops.drop_privileges = struct {
        fn f(_: []const u8) anyerror!void {
            return error.SetgroupsFailed;
        }
    }.f;
    recorded_len = 0;

    try std.testing.expectError(error.SetgroupsFailed, runWithOps(test_opts, ops));
    try std.testing.expect(indexOf(.remove_pid) == null);
}

// --- fatal() names the error that stopped the daemon --------------------------

test "the disposition line names the error that stopped the daemon" {
    var buf: [256]u8 = undefined;
    const msg = fatalMessage(&buf, error.AddressNotAvailable);

    try std.testing.expect(std.mem.indexOf(u8, msg, "AddressNotAvailable") != null);
    // "fatal:" is the prefix an operator greps for, distinguishing this
    // line from other err-level diagnostics logged above it.
    try std.testing.expect(std.mem.startsWith(u8, msg, "fatal:"));
}

test "a buffer too small for the error name still reports a fatal exit" {
    // Losing the error's name to a small buffer is survivable; losing the
    // fact that the daemon died is not, so the fallback message must still
    // contain "fatal".
    var tiny: [8]u8 = undefined;
    const msg = fatalMessage(&tiny, error.SomeVeryLongErrorNameIndeed);

    try std.testing.expect(std.mem.indexOf(u8, msg, "fatal") != null);
}

test "fatal returns the error unchanged, so the exit status stays non-zero" {
    // `main` propagates whatever this returns; swallowing the error here
    // would make the process exit 0 despite the failure.
    try std.testing.expectEqual(anyerror.AddressInUse, fatal(error.AddressInUse));
}
