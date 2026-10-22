//! Build the worker pool and own workers until their threads take them.
//!
//! Construction stays on the calling thread so startup failures remain reportable.
//! The ownership rules below preserve cleanup on partial construction.

const std = @import("std");
const posix = std.posix;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const listener_mod = @import("listener.zig");
const reload_mod = @import("reload.zig");
const log_mod = @import("log.zig");
const worker_mod = @import("worker.zig");
const connection_mod = @import("connection.zig");
const commands = @import("milter/commands.zig");
const responses = @import("milter/responses.zig");

const Worker = worker_mod.Worker;
const Callbacks = worker_mod.Callbacks;

/// What a pool needs. Only the three without defaults must be supplied.
pub const Options = struct {
    /// 0 means one thread per CPU, at most `listener.balanced_listeners_max`.
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
pub fn spawnPool(allocator: Allocator, opts: Options) !std.ArrayList(std.Thread) {
    const num_workers = opts.num_workers;
    const addresses = opts.addresses;
    const callbacks = opts.callbacks;
    const shutdown_pipe_rd = opts.shutdown_pipe_rd;
    const config_gen = opts.config_gen;
    const max_connections = opts.max_connections;

    var threads: std.ArrayList(std.Thread) = .{};
    errdefer threads.deinit(allocator);

    const count = try workerCount(num_workers, addresses);

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

    // Bind each Unix path once, here, so its failures are reported like every
    // other bind failure below. The pool's hold on each shared listener is
    // released on every return path; after a successful spawn the workers
    // hold the only references, and the last one to drain closes the socket
    // and unlinks the path.
    const shared = try allocator.alloc(?*listener_mod.SharedListener, addresses.len);
    defer allocator.free(shared);
    @memset(shared, null);
    defer for (shared) |slot| {
        if (slot) |s| s.release();
    };
    for (addresses, shared) |addr, *slot| switch (addr) {
        .unix => slot.* = try listener_mod.SharedListener.create(allocator, addr, count),
        .tcp => {},
    };

    // Phase 1: build every worker here, on the calling thread, where a failure
    // can still be reported to the caller.
    //
    // This is the fix for X-15 and it is deliberately a relocation rather than
    // a barrier. Each worker binds its own TCP sockets (see listener.bind), so
    // this is where EADDRINUSE from a foreign process or fd exhaustion
    // surfaces. Performed inside the spawned thread the only available
    // response was to log and return, leaving a daemon that had reported a
    // successful start with fewer workers than it claimed -- or none at all --
    // and a quiescent-state slot frozen forever.
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
            .shared_listeners = shared,
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

/// Resolve the configured worker count (0 means one per CPU).
///
/// Every worker binds each TCP address into one kernel balancing group, which
/// holds at most `listener.balanced_listeners_max` sockets; a worker past that
/// would bind but never be handed a TCP connection. The per-CPU default is
/// capped there, and an explicit count above it is refused.
fn workerCount(num_workers: u32, addresses: []const listener_mod.ListenAddress) !u32 {
    const max = listener_mod.balanced_listeners_max;
    if (num_workers == 0) {
        const cpus: u32 = @intCast(std.Thread.getCpuCount() catch 4);
        return @min(cpus, max);
    }
    if (num_workers <= max) return num_workers;

    for (addresses) |addr| switch (addr) {
        .tcp => {
            log_mod.err(
                "{d} workers exceed the {d} listeners one TCP port can balance across",
                .{ num_workers, max },
            );
            return error.TooManyWorkers;
        },
        .unix => {},
    };
    return num_workers;
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
// bound, and it is the case X-15 was filed for: binding inside the spawned
// thread would leave `return` as the only option there, reporting a
// successful pool with nothing serving.
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

// Goal: a pool larger than one balancing group refuses to start on TCP instead
// of running workers that never receive a connection. Method: ask for one
// worker past the limit and expect the refusal before anything is bound.
test "a TCP pool larger than one balancing group is refused" {
    const pipe = try posix.pipe();
    defer posix.close(pipe[0]);
    defer posix.close(pipe[1]);

    const tcp = listener_mod.ListenAddress{ .tcp = .{ .host = "127.0.0.1", .port = 0 } };
    const result = spawnPool(std.testing.allocator, .{
        .num_workers = listener_mod.balanced_listeners_max + 1,
        .addresses = &.{tcp},
        .callbacks = .{},
        .shutdown_pipe_rd = pipe[0],
    });
    try std.testing.expectError(error.TooManyWorkers, result);

    // The per-CPU default is capped rather than refused.
    const auto = try workerCount(0, &.{tcp});
    try std.testing.expect(auto >= 1);
    try std.testing.expect(auto <= listener_mod.balanced_listeners_max);
}

// Goal: connections to one Unix path reach every worker of a pool, and the
// last worker to drain unlinks the path. Method: a four-worker pool on one
// Unix address; `on_connect` holds each worker until four distinct worker
// threads have entered it. Each client connects only after the previous one's
// `on_connect` has run, so every earlier worker is blocked and only a free
// worker can accept. With the path rebound per worker, every connection
// reaches the last worker bound, the second client is never served, and the
// wait times out with one thread counted.
test "connections to a unix address reach every worker of the pool" {
    const worker_count = 4;
    const path = "/tmp/securemilter-test-pool-unix.sock";

    const Probe = struct {
        var mutex: std.Thread.Mutex = .{};
        var cond: std.Thread.Condition = .{};
        var threads: [worker_count]std.Thread.Id = undefined;
        var entered: usize = 0;

        fn onConnect(_: *connection_mod.Connection, _: commands.ConnectInfo) u8 {
            mutex.lock();
            defer mutex.unlock();
            if (entered < worker_count) threads[entered] = std.Thread.getCurrentId();
            entered += 1;
            cond.broadcast();
            waitLocked(worker_count);
            return @intFromEnum(responses.Code.@"continue");
        }

        /// Wait with `mutex` held until `count` workers have entered.
        /// Bounded, so a regression fails the assertions instead of hanging
        /// the gate.
        fn waitLocked(count: usize) void {
            const deadline_ms = std.time.milliTimestamp() + 5_000;
            while (entered < count) {
                const now_ms = std.time.milliTimestamp();
                if (now_ms >= deadline_ms) return;
                const wait_ns: u64 = @intCast((deadline_ms - now_ms) * std.time.ns_per_ms);
                cond.timedWait(&mutex, wait_ns) catch |err| switch (err) {
                    error.Timeout => {},
                };
            }
        }

        fn waitEntered(count: usize) usize {
            mutex.lock();
            defer mutex.unlock();
            waitLocked(count);
            return entered;
        }
    };
    Probe.entered = 0;

    const pipe = try posix.pipe();
    defer posix.close(pipe[0]);
    var pipe_wr: posix.fd_t = pipe[1];

    var threads = spawnPool(std.testing.allocator, .{
        .num_workers = worker_count,
        .addresses = &.{.{ .unix = .{ .path = path } }},
        .callbacks = .{ .on_connect = Probe.onConnect },
        .shutdown_pipe_rd = pipe[0],
    }) catch |err| {
        posix.close(pipe_wr);
        return err;
    };
    defer threads.deinit(std.testing.allocator);

    // Clients close first (the drain waits for them), then EOF on the
    // shutdown pipe begins the drain, then the workers are joined.
    defer if (pipe_wr >= 0) {
        posix.close(pipe_wr);
        for (threads.items) |thread| thread.join();
    };

    var clients: [worker_count]std.net.Stream = undefined;
    var connected: usize = 0;
    defer for (clients[0..connected]) |client| client.close();

    // SMFIC_CONNECT: host "h", family unknown, port 0, empty address.
    const packet = [_]u8{ 0, 0, 0, 7, 'C', 'h', 0, 'U', 0, 0, 0 };
    comptime assert(std.mem.readInt(u32, packet[0..4], .big) == packet.len - 4);

    const receive_timeout = posix.timeval{ .sec = 10, .usec = 0 };
    while (connected < worker_count) : (connected += 1) {
        const client = try std.net.connectUnixSocket(path);
        clients[connected] = client;
        try posix.setsockopt(
            client.handle,
            posix.SOL.SOCKET,
            posix.SO.RCVTIMEO,
            std.mem.asBytes(&receive_timeout),
        );
        try client.writeAll(&packet);
        try std.testing.expectEqual(connected + 1, Probe.waitEntered(connected + 1));
    }

    // Each reply follows its on_connect, so every count is final once all
    // four replies have arrived.
    for (clients[0..connected]) |client| {
        var reply: [5]u8 = undefined;
        var got: usize = 0;
        while (got < reply.len) {
            const n = try posix.read(client.handle, reply[got..]);
            if (n == 0) return error.EndOfStream;
            got += n;
        }
        try std.testing.expectEqual(@intFromEnum(responses.Code.@"continue"), reply[4]);
    }

    Probe.mutex.lock();
    const entered = Probe.entered;
    const served_by = Probe.threads;
    Probe.mutex.unlock();
    try std.testing.expectEqual(@as(usize, worker_count), entered);
    for (served_by, 0..) |id, index| {
        for (served_by[0..index]) |earlier| try std.testing.expect(id != earlier);
    }

    for (clients[0..connected]) |client| client.close();
    connected = 0;
    posix.close(pipe_wr);
    pipe_wr = -1;
    for (threads.items) |thread| thread.join();

    // The last worker to drain released the final hold.
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(path, .{}));
}
