const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

/// Configuration generation counter, and the per-worker quiescent state that
/// lets retired configuration be freed safely.
///
/// The counter tells workers *that* something changed, so they can drop
/// thread-local caches. On its own that is not enough to replace shared
/// configuration: this type previously carried a comment asserting that
/// "no deferred freeing is needed since config data is static lifetime
/// (backed by the original parsed INI allocation or a replace-in-place swap)".
/// The replace-in-place swap was the bug — it frees or tears memory a worker
/// is reading (audit X-2). The slots below supply the missing half.
///
/// Each worker owns one slot and writes the current generation into it at the
/// top of its event loop, which is the one point where it provably holds no
/// reference to shared configuration. `minObserved` is therefore a generation
/// that every worker has passed while holding nothing, which is exactly the
/// condition for reclaiming anything retired at or before it. See `rcu.zig`.
pub const ConfigGeneration = struct {
    global: std.atomic.Value(u64),
    /// One per worker. Empty until `initSlots`, which means "no readers" and
    /// makes everything immediately reclaimable — correct for tests and for
    /// the window before workers spawn.
    slots: []std.atomic.Value(u64) = &.{},
    /// Write ends of the per-worker wakeup pipes, owned by the main thread.
    /// Empty when no workers are registered.
    wakeup_w: []posix.fd_t = &.{},

    pub fn init() ConfigGeneration {
        return .{ .global = std.atomic.Value(u64).init(0) };
    }

    /// Construct with the slots already allocated, for callers that know the
    /// worker count up front (tests, mainly — daemons let `spawnPoolWithReload`
    /// do it so the count cannot disagree with the threads actually spawned).
    pub fn initWithWorkers(allocator: Allocator, worker_count: usize) Allocator.Error!ConfigGeneration {
        var self = ConfigGeneration.init();
        try self.initSlots(allocator, worker_count);
        return self;
    }

    /// Allocate one quiescent-state slot per worker. Call before spawning
    /// them, from the main thread.
    pub fn initSlots(self: *ConfigGeneration, allocator: Allocator, worker_count: usize) Allocator.Error!void {
        if (self.slots.len != 0) return;
        const slots = try allocator.alloc(std.atomic.Value(u64), worker_count);
        // Start at the current generation: a worker that has not run yet also
        // cannot be holding anything older than what is published now.
        const now = self.load();
        for (slots) |*s| s.* = std.atomic.Value(u64).init(now);
        self.slots = slots;
    }

    /// Create one wakeup pipe per worker and keep the write ends. Returns the
    /// read ends for the caller to hand to the workers, which own them.
    ///
    /// Without this, reclamation stalls indefinitely on a quiet daemon: a
    /// worker blocked in kevent() never reaches its quiescent point, and
    /// because the safe generation is the *minimum* across workers, a single
    /// idle worker pins it for all of them. Observed on the lab as 500
    /// whitelists and 20 MB held after a reload storm.
    pub fn initWakeup(self: *ConfigGeneration, allocator: Allocator, worker_count: usize) ![]posix.fd_t {
        const write_ends = try allocator.alloc(posix.fd_t, worker_count);
        errdefer allocator.free(write_ends);
        const read_ends = try allocator.alloc(posix.fd_t, worker_count);
        errdefer allocator.free(read_ends);

        var created: usize = 0;
        errdefer for (0..created) |i| {
            posix.close(write_ends[i]);
            posix.close(read_ends[i]);
        };

        while (created < worker_count) : (created += 1) {
            const fds = try posix.pipe();
            // The reader drains opportunistically and must never block on an
            // empty pipe.
            const flags = try posix.fcntl(fds[0], posix.F.GETFL, 0);
            _ = try posix.fcntl(fds[0], posix.F.SETFL, flags | @as(u32, @bitCast(posix.O{ .NONBLOCK = true })));
            read_ends[created] = fds[0];
            write_ends[created] = fds[1];
        }

        self.wakeup_w = write_ends;
        return read_ends;
    }

    /// Nudge every worker out of kevent() so it reaches its quiescent point.
    /// Called by the writer after publishing new configuration.
    ///
    /// A byte on a pipe rather than a signal: EVFILT_SIGNAL is unreliable in a
    /// multi-threaded process, and a periodic timeout would trade a stall for
    /// a permanent tick.
    pub fn wake(self: *const ConfigGeneration) void {
        const byte = [_]u8{1};
        for (self.wakeup_w) |fd| {
            // A full pipe means a wakeup is already pending, which is just as
            // good; nothing here is worth failing a reload over.
            _ = posix.write(fd, &byte) catch {};
        }
    }

    pub fn deinit(self: *ConfigGeneration, allocator: Allocator) void {
        if (self.wakeup_w.len != 0) {
            for (self.wakeup_w) |fd| posix.close(fd);
            allocator.free(self.wakeup_w);
            self.wakeup_w = &.{};
        }
        if (self.slots.len == 0) return;
        allocator.free(self.slots);
        self.slots = &.{};
    }

    pub fn workerCount(self: *const ConfigGeneration) usize {
        return self.slots.len;
    }

    /// Advance the generation. Called by the writer after a config swap.
    /// Returns the new generation, which is what retired values are stamped
    /// with.
    pub fn increment(self: *ConfigGeneration) u64 {
        return self.global.fetchAdd(1, .release) + 1;
    }

    /// Read the current generation. Called by workers each loop iteration.
    pub fn load(self: *const ConfigGeneration) u64 {
        return self.global.load(.acquire);
    }

    /// Announce that this worker holds no reference to shared configuration.
    /// Called at the top of the event loop and nowhere else — calling it while
    /// a reference is live would licence freeing memory still in use.
    /// Takes a const pointer deliberately: workers only ever hold a read-only
    /// view of the generation counter, and the slot itself is atomic.
    pub fn quiesce(self: *const ConfigGeneration, worker_index: usize) void {
        if (worker_index >= self.slots.len) return;
        self.slots[worker_index].store(self.load(), .release);
    }

    /// The lowest generation any worker has been observed at while quiescent.
    /// Anything retired at or before this can no longer be reached.
    ///
    /// With no slots registered there are no readers, so everything is
    /// reclaimable.
    pub fn minObserved(self: *const ConfigGeneration) u64 {
        if (self.slots.len == 0) return std.math.maxInt(u64);
        var min: u64 = std.math.maxInt(u64);
        for (self.slots) |*s| {
            const v = s.load(.acquire);
            if (v < min) min = v;
        }
        return min;
    }
};

test "config generation increment and load" {
    var gen = ConfigGeneration.init();
    try std.testing.expectEqual(@as(u64, 0), gen.load());

    try std.testing.expectEqual(@as(u64, 1), gen.increment());
    try std.testing.expectEqual(@as(u64, 1), gen.load());

    _ = gen.increment();
    try std.testing.expectEqual(@as(u64, 3), gen.increment());
    try std.testing.expectEqual(@as(u64, 3), gen.load());
}

test "without slots everything is reclaimable" {
    var gen = ConfigGeneration.init();
    try std.testing.expectEqual(@as(usize, 0), gen.workerCount());
    try std.testing.expectEqual(std.math.maxInt(u64), gen.minObserved());

    // quiesce on an unregistered index must not write out of bounds.
    gen.quiesce(0);
    gen.quiesce(99);
}

test "minObserved tracks the slowest worker" {
    const allocator = std.testing.allocator;
    var gen = ConfigGeneration.init();
    try gen.initSlots(allocator, 3);
    defer gen.deinit(allocator);

    // Slots start at the generation current when they were allocated.
    try std.testing.expectEqual(@as(u64, 0), gen.minObserved());

    _ = gen.increment();
    _ = gen.increment();

    gen.quiesce(0);
    gen.quiesce(1);
    // Worker 2 has not been seen since generation 0, so that is the bound.
    try std.testing.expectEqual(@as(u64, 0), gen.minObserved());

    gen.quiesce(2);
    try std.testing.expectEqual(@as(u64, 2), gen.minObserved());
}

test "slots are allocated once" {
    const allocator = std.testing.allocator;
    var gen = ConfigGeneration.init();
    try gen.initSlots(allocator, 4);
    defer gen.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), gen.workerCount());

    // A second call must not leak the first allocation.
    try gen.initSlots(allocator, 8);
    try std.testing.expectEqual(@as(usize, 4), gen.workerCount());
}
