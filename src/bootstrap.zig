//! Bringing a daemon up, in the one order that works.
//!
//! Split from `daemon.zig` along the seam the two things already had: that module holds
//! the individual privileged operations — fork, write a PID file, raise a limit, drop
//! privileges — and this one holds the single correct sequence for performing them.
//! They are different kinds of knowledge. A reader fixing a `setrlimit` call wants the
//! former; a reader wondering why the health monitor starts where it does wants this.

const std = @import("std");
const daemon = @import("daemon.zig");
const log_mod = @import("log.zig");

/// What a daemon needs to come up, in one place.
pub const Options = struct {
    /// Skip `daemonize`, staying attached to the terminal.
    foreground: bool,
    pid_file: []const u8,
    /// Unprivileged user to become. Null leaves privileges alone.
    user: ?[]const u8,
    /// 0 means "one per CPU", resolved by `run` and reported back.
    worker_threads: u32,
    max_connections: u32,
    num_listeners: u32,

    /// Spawn any long-lived threads the daemon needs — in practice the DNS health
    /// monitor.
    ///
    /// A callback rather than a step, for two reasons. It keeps this module from
    /// importing `dns`, which imports `daemon` and would make a cycle. And it puts the
    /// daemon's thread creation at THE ONE POINT IN THE SEQUENCE WHERE IT IS SAFE,
    /// chosen here rather than by each caller: after `daemonize`, because fork keeps
    /// only the calling thread, and after the managed signals are blocked, because a
    /// thread created before that inherits a mask which does not block them (X-7).
    spawn_threads: ?*const fn () void = null,
};

/// What the caller needs back afterwards.
pub const Bootstrap = struct {
    pid_file: []const u8,
    /// `worker_threads` with 0 resolved to the CPU count.
    workers: u32,

    /// Remove the PID file. `defer` this in `main`.
    ///
    /// Not done by `run` itself because the file must outlive it by the whole life of
    /// the process, and Zig's `defer` is scoped to the function that writes it.
    pub fn deinit(self: Bootstrap) void {
        daemon.removePidFile(self.pid_file);
    }
};

/// The syscall-level steps, injectable.
///
/// THE INDIRECTION EXISTS SO THE ORDER CAN BE TESTED. Five of the ordering relations
/// below were each a filed defect, and not one of them can be exercised directly in a
/// unit test: a test process cannot fork, setuid, or mask its own signals without
/// wrecking the test runner. Substituting recording stubs makes the sequence
/// observable, which is the difference between the constraints being *documented* —
/// they were, in four separate files — and being *enforced*.
pub const Ops = struct {
    daemonize: *const fn () anyerror!void = daemon.daemonize,
    reinit_log: *const fn () void = log_mod.initThread,
    block_signals: *const fn () void = daemon.ManagedSignals.blockForKqueue,
    write_pid_file: *const fn ([]const u8) anyerror!void = daemon.writePidFile,
    raise_file_limit: *const fn (u64) void = daemon.raiseFileLimit,
    drop_privileges: *const fn ([]const u8) anyerror!void = daemon.dropPrivileges,
};

/// Bring the daemon up: daemonize, block signals, spawn threads, claim the PID file,
/// raise the fd budget, drop privileges.
///
/// THE ORDER IS THE POINT OF THIS FUNCTION. It was written out four times, once per
/// daemon, with each constraint restated as a comment — which is how X-7 came to be
/// fixed in one copy while the others waited. The constraints, and what breaks:
///
///   1. `daemonize` before any thread. `fork` carries over only the calling thread, so
///      a thread started earlier simply does not exist in the daemon.
///   2. Signals blocked before any thread. `sigprocmask` affects one thread and a new
///      thread inherits the mask in force when it is created. Miss this and, while the
///      main thread is away from `sigwait` running a reload, SIGHUP goes to the first
///      thread that does not block it and the default action kills the process — no
///      core, no log line, because SIGHUP does not dump core. That is X-7, and it
///      survived six runs of the probe written to catch it.
///   3. Log re-initialised after `daemonize`, because the PID changed and the log lines
///      carry it.
///   4. PID file written before privileges are dropped: /var/run is not writable by the
///      unprivileged user.
///   5. fd limit raised before privileges are dropped: `setrlimit` above the soft limit
///      needs root.
///
/// A failed PID file write is logged and survived — the daemon still works, it is
/// merely harder to signal. A failed `daemonize` or privilege drop is fatal, because
/// continuing would mean running attached, or as root, without being asked to.
pub fn run(opts: Options) !Bootstrap {
    return runWithOps(opts, .{});
}

/// `run` with the steps substituted. For tests; production calls `run`.
pub fn runWithOps(opts: Options, ops: Ops) !Bootstrap {
    if (!opts.foreground) {
        ops.daemonize() catch |err| {
            log_mod.err("daemonize failed: {}", .{err});
            return err;
        };
        // (3) after the fork, because the PID in every subsequent line changed.
        ops.reinit_log();
    }

    // (2) before `spawn_threads` below, and before the worker pool the caller starts
    // after this returns. X-7.
    ops.block_signals();

    // (1) and (2) are both satisfied at this point, and nowhere earlier.
    if (opts.spawn_threads) |spawn| spawn();

    // (4) still privileged here.
    ops.write_pid_file(opts.pid_file) catch |err| {
        log_mod.err("pid file write failed: {}", .{err});
    };

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

    return .{ .pid_file = opts.pid_file, .workers = workers };
}

// --- ordering ----------------------------------------------------------------
//
// Each test below names the defect it exists to catch. They assert RELATIONS rather
// than one exact sequence: "signals before threads" is the constraint, whereas whether
// the PID file is claimed before or after the fd limit is free, and a test that pinned
// the whole order would fail on a change that breaks nothing.

const Step = enum { daemonize, reinit_log, block_signals, spawn_threads, write_pid, raise_fd, drop_privs };

var recorded: [16]Step = undefined;
var recorded_len: usize = 0;

fn record(s: Step) void {
    if (recorded_len < recorded.len) {
        recorded[recorded_len] = s;
        recorded_len += 1;
    }
}

fn recDaemonize() anyerror!void {
    record(.daemonize);
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
fn recWritePid(_: []const u8) anyerror!void {
    record(.write_pid);
}
fn recRaiseFd(_: u64) void {
    record(.raise_fd);
}
fn recDropPrivs(_: []const u8) anyerror!void {
    record(.drop_privs);
}

const recording_ops = Ops{
    .daemonize = recDaemonize,
    .reinit_log = recReinitLog,
    .block_signals = recBlockSignals,
    .write_pid_file = recWritePid,
    .raise_file_limit = recRaiseFd,
    .drop_privileges = recDropPrivs,
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

test "X-7: the managed signals are blocked before any thread is spawned" {
    // The defect this guards: sigprocmask affects the calling thread only, and a new
    // thread inherits whatever mask is in force when it is created. With the block
    // after the health monitor started, a SIGHUP arriving while the main thread was
    // inside reloadConfig -- and so not parked in sigwait -- was delivered to the
    // monitor thread, whose default action terminated the daemon with no core and no
    // log line.
    _ = try runRecorded(test_opts);
    try expectBefore(.block_signals, .spawn_threads);
}

test "threads are spawned after daemonize, because fork keeps only the caller" {
    _ = try runRecorded(test_opts);
    try expectBefore(.daemonize, .spawn_threads);
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

test "foreground skips daemonize and its log re-init, but still blocks before spawning" {
    var opts = test_opts;
    opts.foreground = true;
    _ = try runRecorded(opts);

    try std.testing.expect(indexOf(.daemonize) == null);
    try std.testing.expect(indexOf(.reinit_log) == null);
    // The X-7 constraint has nothing to do with daemonizing, and must hold either way.
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
    // The asymmetry is deliberate: a daemon with no PID file works and is merely
    // awkward to signal, whereas one that meant to drop privileges and did not is
    // running as root without having been asked to.
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
