//! Bringing a daemon up, in the one order that works.
//!
//! Split from `daemon.zig` along the seam the two things already had: that module holds
//! the individual privileged operations — fork, write a PID file, raise a limit, drop
//! privileges — and this one holds the single correct sequence for performing them.
//! They are different kinds of knowledge. A reader fixing a `setrlimit` call wants the
//! former; a reader wondering why the health monitor starts where it does wants this.

const std = @import("std");
const posix = std.posix;
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

    /// Write end of the readiness pipe, or null in the foreground where nobody is
    /// waiting. Held rather than signalled here on purpose — see `notifyReady`.
    ready_fd: ?posix.fd_t = null,
    signal_ready: *const fn (posix.fd_t) void = daemon.signalReady,

    /// Tell the waiting parent this daemon is serving. Call it once listeners are
    /// bound and the worker pool is running, and not before.
    ///
    /// `run` deliberately does not do this itself. Everything that actually makes the
    /// daemon useful — binding, the worker pool — happens after `run` returns, which
    /// is the whole reason the parent's exit status was meaningless (X-16). Signalling
    /// from inside `run` would move the lie rather than remove it.
    ///
    /// Idempotent, and a no-op in the foreground.
    pub fn notifyReady(self: *Bootstrap) void {
        if (self.ready_fd) |fd| {
            self.ready_fd = null;
            self.signal_ready(fd);
        }
    }

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
    daemonize: *const fn () anyerror!posix.fd_t = daemon.daemonize,
    reinit_log: *const fn () void = log_mod.initThread,
    block_signals: *const fn () void = daemon.ManagedSignals.blockForKqueue,
    signal_ready: *const fn (posix.fd_t) void = daemon.signalReady,
    write_pid_file: *const fn ([]const u8) anyerror!void = daemon.writePidFile,
    remove_pid_file: *const fn ([]const u8) void = daemon.removePidFile,
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
    var ready_fd: ?posix.fd_t = null;
    if (!opts.foreground) {
        ready_fd = ops.daemonize() catch |err| {
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
    //
    // Whether the file is ours is tracked, rather than inferred later from the file
    // existing: if the write failed, some other instance may own that path and
    // removing it on the way out would be worse than leaving it.
    var pid_file_is_ours = false;
    if (ops.write_pid_file(opts.pid_file)) {
        pid_file_is_ours = true;
    } else |err| {
        log_mod.err("pid file write failed: {}", .{err});
    }

    // Claiming the file and surviving the rest of this function are separate events,
    // and only the caller's `defer boot.deinit()` covered the gap between them -- which
    // it cannot, because it is only registered once `run` has already returned. A
    // privilege drop that fails here therefore left a PID file naming a process that
    // no longer exists: verified as /tmp/x16pid.pid holding 70682 after
    // "privilege drop to 'nobody' failed: error.SetgroupsFailed". Ownership now begins
    // where the file does (X-16).
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

    // The readiness fd travels out UNSIGNALLED. Nothing this function does proves the
    // daemon can serve -- the listeners are not bound yet. Any error path above returns
    // without writing, the fd closes with the process, and the parent reads EOF.
    return .{
        .pid_file = opts.pid_file,
        .workers = workers,
        .ready_fd = ready_fd,
        .signal_ready = ops.signal_ready,
    };
}

/// The disposition line: why this process is about to stop existing.
///
/// Pure, and separate from the emission, BECAUSE THE LOG OFFERS NOTHING TO OBSERVE --
/// it writes to a datagram socket or to stderr and returns void. A test can assert on
/// this; it cannot assert on `log_mod.err`. The thing worth pinning is that the error
/// is NAMED, since the whole defect was an operator with no way to tell which of a
/// dozen failures had happened.
pub fn fatalMessage(buf: []u8, e: anyerror) []const u8 {
    return std.fmt.bufPrint(buf, "fatal: exiting on {s}", .{@errorName(e)}) catch
        // Only reachable if `buf` cannot hold even the error name. Still says the one
        // thing that must never be lost: this process is stopping on an error.
        "fatal: exiting on an error whose name did not fit";
}

/// Announce a fatal failure through the log, then hand the error back to propagate.
///
/// Used as the whole body of `main`:
///
///     pub fn main() !void {
///         run() catch |e| return bootstrap.fatal(e);
///     }
///
/// THE SHAPE IS THE POINT, not the function. `daemonize` is the first thing `run`
/// does, and it points stderr at /dev/null -- so from that instant the error Zig's
/// start code prints for an error returned by `main` goes nowhere, and syslog is the
/// only channel left. Every fallible step after it (the shutdown pipe, the worker
/// pool, and whatever is added later) therefore had exactly one way to report: a
/// `try` whose error was written to a closed descriptor. Measured on a daemon told to
/// bind an unusable address: parent exit status 0, nothing listening, no process, and
/// a last log line reading "starting" (X-16).
///
/// Reporting at the single point where every error converges is what makes this
/// robust to a `try` added later. Per-site `catch` blocks were the alternative and
/// are how X-7 came to be fixed in one of four copies.
///
/// The error is returned rather than swallowed so the exit status stays non-zero.
/// That is necessary but NOT sufficient, and deliberately not the whole fix: the
/// parent has already exited 0 by the time this runs, so `rc.d` still reports a
/// started service. Closing that needs a readiness handshake across the fork, which
/// is X-16(a) and a change of protocol rather than of reporting.
///
/// A failure that already logged its own diagnostic gets a second line here. That is
/// intended: the diagnostic says what was wrong with the input, this says what became
/// of the process, and only one of the two is guaranteed to exist.
pub fn fatal(e: anyerror) anyerror {
    var buf: [256]u8 = undefined;
    log_mod.err("{s}", .{fatalMessage(&buf, e)});
    return e;
}

// --- ordering ----------------------------------------------------------------
//
// Each test below names the defect it exists to catch. They assert RELATIONS rather
// than one exact sequence: "signals before threads" is the constraint, whereas whether
// the PID file is claimed before or after the fd limit is free, and a test that pinned
// the whole order would fail on a change that breaks nothing.

const Step = enum { daemonize, reinit_log, block_signals, spawn_threads, write_pid, remove_pid, raise_fd, drop_privs, signal_ready };

var recorded: [16]Step = undefined;
var recorded_len: usize = 0;

fn record(s: Step) void {
    if (recorded_len < recorded.len) {
        recorded[recorded_len] = s;
        recorded_len += 1;
    }
}

/// The sentinel stands in for the readiness write end. It is never written to --
/// `signal_ready` is recorded, not performed -- so it only has to be distinguishable.
const fake_ready_fd: posix.fd_t = 4242;

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

const recording_ops = Ops{
    .daemonize = recDaemonize,
    .reinit_log = recReinitLog,
    .block_signals = recBlockSignals,
    .signal_ready = recSignalReady,
    .write_pid_file = recWritePid,
    .remove_pid_file = recRemovePid,
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

// --- X-16(a): readiness is claimed by the daemon, not by bootstrap -----------

test "X-16: run does not report readiness, because nothing is listening yet" {
    // The defect restated as a constraint. `run` finishes long before the listeners
    // are bound and the worker pool exists, so a readiness signal from inside it
    // would be the same false claim the parent used to make on its own.
    const boot = try runRecorded(test_opts);
    try std.testing.expect(indexOf(.signal_ready) == null);
    try std.testing.expectEqual(fake_ready_fd, boot.ready_fd.?);
}

test "X-16: a bootstrap that fails never reports readiness" {
    // The parent must see EOF, not a byte. Nothing writes on this path -- the fd goes
    // out with the process -- and the assertion is that no signal is attempted.
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

test "X-16: notifyReady signals once and only once" {
    // Called from `main` after the pool is up. The second call must be inert: the fd
    // is closed by the first, and writing to a closed descriptor that has since been
    // reused would send a stray byte to whatever now owns that number.
    var boot = try runRecorded(test_opts);
    recorded_len = 0;

    boot.notifyReady();
    try std.testing.expectEqual(@as(usize, 1), recorded_len);
    try std.testing.expect(indexOf(.signal_ready) != null);

    boot.notifyReady();
    try std.testing.expectEqual(@as(usize, 1), recorded_len);
}

test "X-16: in the foreground there is no parent to answer" {
    // No fork, so no pipe and nobody waiting. `notifyReady` must not invent an fd to
    // write to -- 0 is stdin.
    var opts = test_opts;
    opts.foreground = true;
    var boot = try runRecorded(opts);
    try std.testing.expect(boot.ready_fd == null);

    recorded_len = 0;
    boot.notifyReady();
    try std.testing.expectEqual(@as(usize, 0), recorded_len);
}

// --- X-16: the PID file belongs to a process that exists ---------------------

test "X-16: a fatal privilege drop takes the PID file with it" {
    // Measured before the fix: /tmp/x16pid.pid left holding 70682 after
    // "privilege drop to 'nobody' failed", naming a process that had already exited.
    // The caller's `defer boot.deinit()` cannot cover this -- it is only registered
    // once `run` has returned, and `run` did not.
    //
    // A stale PID file is not cosmetic. It is what `rc.d` reads to decide whether the
    // service is running, and what an operator signals.
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

test "X-16: a successful bootstrap keeps its PID file" {
    // The removal is an error path only. Removing on the way out of a good start would
    // leave a running daemon nothing could signal -- the same end state as the defect,
    // reached from the opposite direction.
    _ = try runRecorded(test_opts);
    try std.testing.expect(indexOf(.remove_pid) == null);
}

test "X-16: a PID file we failed to write is not removed on the way out" {
    // If the write failed, the path may belong to another instance. Deleting it
    // because we are exiting would make this daemon's failure into that one's.
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

// --- X-16(b): a fatal failure says so ----------------------------------------

test "X-16: the disposition line names the error that stopped the daemon" {
    // The measured defect: a daemon told to bind an unusable address exited 0 with a
    // last log line of "starting". The operator's evidence of a failed start was an
    // affirmative claim of success. Whatever else is lost, the error's name must not
    // be -- it is the difference between "the address was taken" and "the key was
    // unreadable", and there is no second channel to ask on.
    var buf: [256]u8 = undefined;
    const msg = fatalMessage(&buf, error.AddressNotAvailable);

    try std.testing.expect(std.mem.indexOf(u8, msg, "AddressNotAvailable") != null);
    // "fatal" is what a human greps for, and what distinguishes this line from the
    // diagnostics above it, which are also logged at err level.
    try std.testing.expect(std.mem.startsWith(u8, msg, "fatal:"));
}

test "X-16: a buffer too small for the error name still reports a fatal exit" {
    // The formatter is the last thing to run before the process disappears, so it may
    // not be the thing that breaks. Losing the name is survivable; losing the fact
    // that the daemon died is the defect all over again.
    var tiny: [8]u8 = undefined;
    const msg = fatalMessage(&tiny, error.SomeVeryLongErrorNameIndeed);

    try std.testing.expect(std.mem.indexOf(u8, msg, "fatal") != null);
}

test "X-16: fatal returns the error unchanged, so the exit status stays non-zero" {
    // `main` propagates what this hands back. Swallowing the error here would make the
    // process exit 0 -- which is the half of X-16 that survives until the readiness
    // handshake lands, and would be made permanent by returning void.
    try std.testing.expectEqual(anyerror.AddressInUse, fatal(error.AddressInUse));
}
