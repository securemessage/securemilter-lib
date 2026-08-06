//! Building the worker pool, and owning the pieces until threads take them.
//!
//! Split from `worker.zig` along the seam those two things already had, and the same
//! seam `bootstrap.zig` has against `daemon.zig`: that module is one worker's event
//! loop, and this one is how many of them there are, in what order they are built, and
//! who frees what when construction stops halfway.
//!
//! The split was owed. X-15 moved worker construction out of the spawned threads and
//! onto the calling thread, which is what made the errors reportable — and took
//! `worker.zig` from 657 lines to 722 in the process. The ceiling was raised
//! deliberately, with a note saying it was expected to fall again. This is that.
//!
//! Nothing here changed in the move. The ownership rules below are load-bearing and
//! were written against a measured leak, so they are transcribed rather than rewritten.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const listener_mod = @import("listener.zig");
const reload_mod = @import("reload.zig");
const log_mod = @import("log.zig");
const worker_mod = @import("worker.zig");

const Worker = worker_mod.Worker;
const Callbacks = worker_mod.Callbacks;

/// What a pool needs. Only the three without defaults must be supplied.
pub const Options = struct {
    /// 0 means one thread per CPU.
    num_workers: u32 = 0,
    addresses: []const listener_mod.ListenAddress,
    callbacks: Callbacks,
    /// Read end of a pipe shared by every worker. Writing to the write end
    /// wakes them all out of kevent() to begin the drain.
    shutdown_pipe_rd: posix.fd_t,
    /// The global ConfigGeneration counter. Workers announce quiescence
    /// against it each iteration and call `callbacks.on_reload` when it
    /// advances. Null in a daemon that never reloads.
    config_gen: ?*reload_mod.ConfigGeneration = null,
    /// Per-worker connection limit, for backpressure.
    max_connections: u32 = worker_mod.DEFAULT_MAX_CONNECTIONS,
};

/// Spawn a pool of worker threads.
///
/// This is also where the quiescent-state slots are allocated, because this is
/// the first point at which the real worker count is known (`num_workers` of 0
/// means "one per CPU"). Allocating here rather than in each daemon keeps the
/// slot count and the thread count impossible to disagree about — a worker
/// without a slot would silently never be waited for, and configuration could
/// be freed while it was reading.
///
/// This was `spawnPool` and `spawnPoolWithReload`, the second taking seven
/// positional arguments and the first existing only to pass two defaults to
/// it. Every one of the four daemons called the long form, so the short one
/// had no callers at all and the pair bought nothing.
pub fn spawnPool(allocator: Allocator, opts: Options) !std.ArrayList(std.Thread) {
    const num_workers = opts.num_workers;
    const addresses = opts.addresses;
    const callbacks = opts.callbacks;
    const shutdown_pipe_rd = opts.shutdown_pipe_rd;
    const config_gen = opts.config_gen;
    const max_connections = opts.max_connections;

    var threads: std.ArrayList(std.Thread) = .{};
    errdefer threads.deinit(allocator);

    const count = if (num_workers == 0) @as(u32, @intCast(std.Thread.getCpuCount() catch 4)) else num_workers;

    // If anything below fails there are no workers, so there must be no slots
    // either. A slot with no thread behind it is never written again, and
    // because the safe generation is the *minimum* across slots, one such slot
    // pins reclamation for the whole process: every reload would then retire a
    // configuration that can never be freed (X-15, and see rcu.zig's test
    // "a worker that never quiesces pins reclamation permanently").
    errdefer if (config_gen) |cg| cg.deinit(allocator);

    var wakeup_rd: []posix.fd_t = &.{};
    defer if (wakeup_rd.len != 0) allocator.free(wakeup_rd);
    if (config_gen) |cg| {
        try cg.initSlots(allocator, count);
        wakeup_rd = try cg.initWakeup(allocator, count);
    }

    // Phase 1: build every worker here, on the calling thread, where a failure
    // can still be reported to the caller.
    //
    // This is the fix for X-15 and it is deliberately a relocation rather than
    // a barrier. Each worker binds its own socket (SO_REUSEPORT), so this is
    // where EADDRINUSE from a foreign process, an unwritable unix socket path
    // or fd exhaustion surfaces. Performed inside the spawned thread the only
    // available response was to log and return, leaving a daemon that had
    // reported a successful start with fewer workers than it claimed -- or
    // none at all -- and a quiescent-state slot frozen forever.
    const workers = try allocator.alloc(?*Worker, count);
    defer allocator.free(workers);
    @memset(workers, null);

    // Only workers still owned by us are torn down. `null` means a thread has
    // taken ownership and will free it on exit.
    errdefer for (workers) |slot| {
        if (slot) |w| {
            w.deinit();
            allocator.destroy(w);
        }
    };

    // A constructed worker owns its wakeup read end and closes it in deinit().
    // The ones no worker ever received are still ours, including the read end
    // belonging to the worker that failed.
    var built: usize = 0;
    errdefer for (wakeup_rd[@min(built, wakeup_rd.len)..]) |fd| posix.close(fd);

    while (built < count) : (built += 1) {
        const wake_fd: posix.fd_t = if (built < wakeup_rd.len) wakeup_rd[built] else -1;
        const w = try allocator.create(Worker);
        errdefer allocator.destroy(w);
        w.* = try Worker.init(allocator, .{
            .addresses = addresses,
            .callbacks = callbacks,
            .shutdown_pipe = shutdown_pipe_rd,
            .config_gen = config_gen,
            .max_connections = max_connections,
            .worker_index = built,
            .wakeup_fd = wake_fd,
        });
        workers[built] = w;
    }

    // Phase 2: hand each ready worker to a thread. Capacity is reserved up
    // front so that the only fallible step in the loop is the spawn itself --
    // an append failing after a successful spawn would drop the handle while
    // the thread owned the worker, which is unjoinable and undiagnosable.
    try threads.ensureTotalCapacityPrecise(allocator, count);

    for (workers) |*slot| {
        const t = try std.Thread.spawn(.{}, workerEntryReload, .{ allocator, slot.*.? });
        threads.appendAssumeCapacity(t);
        slot.* = null; // ownership transferred to the thread
    }

    return threads;
}

/// Run one worker until shutdown, then free it.
///
/// The worker arrives fully constructed: everything that can fail happened in
/// `spawnPool`, on a thread that could still report it. That is why there is
/// no error path here to swallow (X-15).
fn workerEntryReload(allocator: Allocator, worker: *Worker) void {
    log_mod.initThread();
    defer log_mod.deinitThread();
    defer allocator.destroy(worker);
    defer worker.deinit();
    worker.run();
}

// X-15: a worker that cannot start must fail the whole pool.
//
// The address here passes configuration validation and fails at bind, which is
// the gap X-14 deliberately left open. X-14 made `parse` agree with `bind` about
// the *form* of an address -- for a unix socket that is only `sun_path` length,
// because whether a directory exists is not a property of the string. So
// `unix:/nonexistent-.../sock` is a well-formed listen address that cannot be
// bound, and it is the case X-15 was filed for.
//
// Before the fix this returned a populated thread list: the failure happened
// inside the spawned thread, where `return` is the only option, so the pool
// reported success with nothing serving.
test "X-15: a worker that cannot bind fails the spawn instead of the thread" {
    const pipe = try posix.pipe();
    defer posix.close(pipe[0]);
    defer posix.close(pipe[1]);

    const unbindable = listener_mod.ListenAddress{
        .unix = .{ .path = "/nonexistent-x15-directory/securemilter.sock" },
    };

    const result = spawnPool(std.testing.allocator, .{
        .num_workers = 2,
        .addresses = &.{unbindable},
        .callbacks = .{},
        .shutdown_pipe_rd = pipe[0],
    });

    try std.testing.expectError(error.FileNotFound, result);
}

// X-15: and the same when a generation counter is in play, because that is the
// path that leaks. Asserted separately so a regression cannot be hidden by the
// `config_gen == null` shortcut, and it also pins the cleanup: `initSlots` and
// `initWakeup` run before any worker is built, so a failed spawn must leave the
// counter as it found it or the caller cannot retry and the test allocator
// reports the leak.
test "X-15: a failed spawn leaves the generation counter clean" {
    const pipe = try posix.pipe();
    defer posix.close(pipe[0]);
    defer posix.close(pipe[1]);

    var gen = reload_mod.ConfigGeneration.init();
    defer gen.deinit(std.testing.allocator);

    const unbindable = listener_mod.ListenAddress{
        .unix = .{ .path = "/nonexistent-x15-directory/securemilter.sock" },
    };

    const result = spawnPool(std.testing.allocator, .{
        .num_workers = 3,
        .addresses = &.{unbindable},
        .callbacks = .{},
        .shutdown_pipe_rd = pipe[0],
        .config_gen = &gen,
    });

    try std.testing.expectError(error.FileNotFound, result);

    // No workers exist, so no slot may claim to be a reader. A slot left behind
    // here is the leak this finding is about: it would pin `minObserved` at the
    // spawn-time generation for the life of the process.
    try std.testing.expectEqual(@as(usize, 0), gen.workerCount());
}
