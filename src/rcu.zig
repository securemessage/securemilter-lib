const std = @import("std");
const Allocator = std.mem.Allocator;

const reload = @import("reload.zig");

/// Read-copy-update container for configuration shared between the main
/// thread and worker threads.
///
/// The problem it solves: a daemon holds parsed configuration in a module
/// global, workers read it while handling messages, and SIGHUP replaces it.
/// Assigning the new value over the old one frees memory a worker may be
/// reading, or tears a struct mid-read. Doing it without freeing leaks a
/// whole config per reload instead.
///
/// The reader holds a pointer to an immutable value and the writer never
/// mutates a published value. A reload builds a *new* value, publishes the
/// pointer atomically, and defers freeing the old one until no worker can
/// still be looking at it.
///
/// # The invariant that makes this safe
///
/// **A reference returned by `get` is valid until the worker next reaches the
/// top of its event loop.** Workers announce quiescence there and nowhere
/// else, so a reference acquired while handling a message stays valid for the
/// whole of that message — including pointers that escape a lookup helper
/// into the code that signs with them. Never stash a reference somewhere that
/// outlives one event-loop iteration; re-acquire it instead.
///
/// # Reclamation
///
/// Freeing is deferred rather than waited for. Workers block in `kevent` with
/// no timeout, so an idle worker may not reach a quiescent point for an
/// arbitrarily long time; a writer that waited for every worker to acknowledge
/// would hang the signal loop on an idle daemon. Instead the old value goes on
/// a retire list stamped with the generation at which it was replaced, and is
/// freed once every worker has been observed at or past that generation. In
/// practice a busy daemon reclaims on the next reload; an idle one holds the
/// memory until it sees traffic, which is exactly when it stops mattering.
///
/// # Concurrency contract
///
/// One writer. `publish`, `sweep` and `deinit` are for the main thread only
/// and are not safe to call concurrently with each other. `get` is safe from
/// any number of readers.
pub fn Rcu(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Frees a retired value. Called only once no reader can reach it.
        pub const DeinitFn = *const fn (Allocator, *T) void;

        current: std.atomic.Value(?*T) = std.atomic.Value(?*T).init(null),
        retired: std.ArrayListUnmanaged(Retired) = .{},
        allocator: Allocator,
        deinit_fn: DeinitFn,

        const Retired = struct {
            ptr: *T,
            /// Generation at which this value stopped being reachable.
            generation: u64,
        };

        pub fn init(allocator: Allocator, deinit_fn: DeinitFn) Self {
            return .{ .allocator = allocator, .deinit_fn = deinit_fn };
        }

        /// Read the current value. Null until something is published.
        ///
        /// The result is valid for the remainder of this event-loop iteration
        /// (see the invariant above).
        pub fn get(self: *const Self) ?*const T {
            return self.current.load(.acquire);
        }

        /// Install `value`, retiring whatever was there before.
        ///
        /// Ownership of `value` passes to the container. The release ordering
        /// pairs with the acquire in `get`, so a reader that sees the new
        /// pointer also sees everything written into it beforehand.
        ///
        /// Called by the writer only.
        pub fn publish(self: *Self, gen: *reload.ConfigGeneration, value: *T) Allocator.Error!void {
            // Reserve the retire slot *before* the swap. Once the new pointer
            // is visible a worker may already have acquired it, so there is no
            // way to undo the swap: putting the old value back and freeing the
            // new one would free memory a reader is holding. Failing here
            // instead leaves the previous configuration installed, which is
            // the right outcome for a reload that could not be completed.
            try self.retired.ensureUnusedCapacity(self.allocator, 1);

            const old = self.current.swap(value, .release);

            // Bump after the swap so the new generation implies the swap has
            // happened. A worker seen at or past this generation has therefore
            // already published a quiescent state in which it held nothing
            // older, and can only acquire this value or a later one.
            const generation = gen.increment();

            if (old) |o| {
                self.retired.appendAssumeCapacity(.{ .ptr = o, .generation = generation });
            }

            // Sweep last, not first: the value just retired is reclaimable
            // right now if every worker is already past this generation, which
            // is always true when nothing is running yet. Sweeping beforehand
            // would hold each superseded config for an extra reload.
            self.sweep(gen);
        }

        /// Free every retired value that no worker can still reach.
        ///
        /// Called by the writer only.
        pub fn sweep(self: *Self, gen: *const reload.ConfigGeneration) void {
            const safe_below = gen.minObserved();

            var i: usize = 0;
            while (i < self.retired.items.len) {
                const entry = self.retired.items[i];
                if (entry.generation <= safe_below) {
                    self.deinit_fn(self.allocator, entry.ptr);
                    _ = self.retired.swapRemove(i);
                    // swapRemove moved a different entry into i; re-test it.
                } else {
                    i += 1;
                }
            }
        }

        /// Number of values awaiting reclamation. For tests and observability.
        pub fn retiredCount(self: *const Self) usize {
            return self.retired.items.len;
        }

        /// Free the current value and everything retired, unconditionally.
        ///
        /// Only valid once the workers have been joined: it does not check
        /// whether anyone still holds a reference.
        pub fn deinit(self: *Self) void {
            for (self.retired.items) |entry| self.deinit_fn(self.allocator, entry.ptr);
            self.retired.deinit(self.allocator);
            if (self.current.load(.acquire)) |cur| self.deinit_fn(self.allocator, cur);
            self.current.store(null, .release);
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

const MAGIC: u64 = 0x5EC12E_A11_600D;

const TestValue = struct {
    id: u32,
    /// Set on free. A reader still holding the pointer sees the change, which
    /// turns a use-after-free from undefined behaviour into a caught failure.
    magic: u64 = MAGIC,
    /// Incremented when this value is freed, so tests can assert reclamation
    /// happened exactly once and at the right moment.
    freed: *u32,
};

fn freeTestValue(allocator: Allocator, v: *TestValue) void {
    v.freed.* += 1;
    v.magic = 0;
    allocator.destroy(v);
}

fn makeValue(allocator: Allocator, id: u32, counter: *u32) !*TestValue {
    const v = try allocator.create(TestValue);
    v.* = .{ .id = id, .freed = counter };
    return v;
}

test "get returns null before anything is published" {
    var rcu = Rcu(TestValue).init(std.testing.allocator, freeTestValue);
    defer rcu.deinit();
    try std.testing.expect(rcu.get() == null);
}

test "publish makes the new value visible" {
    const allocator = std.testing.allocator;
    var gen = try reload.ConfigGeneration.initWithWorkers(allocator, 1);
    defer gen.deinit(allocator);

    var freed: u32 = 0;
    var rcu = Rcu(TestValue).init(allocator, freeTestValue);
    defer rcu.deinit();

    try rcu.publish(&gen, try makeValue(allocator, 1, &freed));
    try std.testing.expectEqual(@as(u32, 1), rcu.get().?.id);

    try rcu.publish(&gen, try makeValue(allocator, 2, &freed));
    try std.testing.expectEqual(@as(u32, 2), rcu.get().?.id);
}

test "a retired value is not freed until every worker has quiesced past it" {
    const allocator = std.testing.allocator;
    var gen = try reload.ConfigGeneration.initWithWorkers(allocator, 2);
    defer gen.deinit(allocator);

    var freed: u32 = 0;
    var rcu = Rcu(TestValue).init(allocator, freeTestValue);
    defer rcu.deinit();

    try rcu.publish(&gen, try makeValue(allocator, 1, &freed));

    // Both workers have seen generation 1 and hold nothing.
    gen.quiesce(0);
    gen.quiesce(1);

    // Replacing it retires the first value, which is still unreclaimable:
    // neither worker has been observed at the new generation yet, so either
    // could be mid-message holding the old pointer.
    try rcu.publish(&gen, try makeValue(allocator, 2, &freed));
    try std.testing.expectEqual(@as(usize, 1), rcu.retiredCount());
    try std.testing.expectEqual(@as(u32, 0), freed);

    // One worker reaching the loop top is not enough — the other may still
    // be inside a message that started before the swap.
    gen.quiesce(0);
    rcu.sweep(&gen);
    try std.testing.expectEqual(@as(usize, 1), rcu.retiredCount());
    try std.testing.expectEqual(@as(u32, 0), freed);

    // Once the straggler quiesces, nobody can reach the old value.
    gen.quiesce(1);
    rcu.sweep(&gen);
    try std.testing.expectEqual(@as(usize, 0), rcu.retiredCount());
    try std.testing.expectEqual(@as(u32, 1), freed);
}

test "an idle worker defers reclamation without blocking or losing memory" {
    const allocator = std.testing.allocator;
    var gen = try reload.ConfigGeneration.initWithWorkers(allocator, 2);
    defer gen.deinit(allocator);

    var freed: u32 = 0;
    var rcu = Rcu(TestValue).init(allocator, freeTestValue);
    defer rcu.deinit();

    try rcu.publish(&gen, try makeValue(allocator, 0, &freed));

    // Worker 1 is blocked in kevent with no traffic and never quiesces.
    // Reloads must keep working regardless.
    var i: u32 = 1;
    while (i <= 5) : (i += 1) {
        gen.quiesce(0);
        try rcu.publish(&gen, try makeValue(allocator, i, &freed));
    }

    // Nothing was freed early and nothing was lost: every superseded value is
    // still accounted for on the retire list.
    try std.testing.expectEqual(@as(u32, 0), freed);
    try std.testing.expectEqual(@as(usize, 5), rcu.retiredCount());
    try std.testing.expectEqual(@as(u32, 5), rcu.get().?.id);

    // When the idle worker finally sees traffic the backlog drains at once.
    gen.quiesce(0);
    gen.quiesce(1);
    rcu.sweep(&gen);
    try std.testing.expectEqual(@as(usize, 0), rcu.retiredCount());
    try std.testing.expectEqual(@as(u32, 5), freed);
}

test "deinit frees the live value and any backlog" {
    const allocator = std.testing.allocator;
    var gen = try reload.ConfigGeneration.initWithWorkers(allocator, 1);
    defer gen.deinit(allocator);

    var freed: u32 = 0;
    var rcu = Rcu(TestValue).init(allocator, freeTestValue);

    try rcu.publish(&gen, try makeValue(allocator, 1, &freed));
    try rcu.publish(&gen, try makeValue(allocator, 2, &freed));
    try rcu.publish(&gen, try makeValue(allocator, 3, &freed));

    // Two retired plus one live, none reclaimed yet.
    try std.testing.expectEqual(@as(usize, 2), rcu.retiredCount());
    try std.testing.expectEqual(@as(u32, 0), freed);

    rcu.deinit();
    try std.testing.expectEqual(@as(u32, 3), freed);
}

/// A worker: quiesce at the loop top, then hold a reference across a "message"
/// exactly as the real callbacks do. Any value it can still see must be intact.
fn stressReader(
    rcu: *Rcu(TestValue),
    gen: *reload.ConfigGeneration,
    index: usize,
    stop: *std.atomic.Value(bool),
    reads: *std.atomic.Value(u64),
) void {
    while (!stop.load(.acquire)) {
        // Loop top: nothing held, announce it.
        gen.quiesce(index);

        if (rcu.get()) |v| {
            // Everything below stands in for handling one message while
            // holding the reference — the window the old code freed into.
            const id = v.id;
            std.Thread.yield() catch {};
            if (v.magic != MAGIC) @panic("read a value that had been freed");
            if (v.id != id) @panic("value changed underneath a reader");
            _ = reads.fetchAdd(1, .monotonic);
        }
    }
}

test "concurrent readers never observe a freed value while the writer reloads" {
    const allocator = std.testing.allocator;

    const reader_count = 4;
    var gen = try reload.ConfigGeneration.initWithWorkers(allocator, reader_count);
    defer gen.deinit(allocator);

    var freed: u32 = 0;
    var rcu = Rcu(TestValue).init(allocator, freeTestValue);
    defer rcu.deinit();

    try rcu.publish(&gen, try makeValue(allocator, 0, &freed));

    var stop = std.atomic.Value(bool).init(false);
    var reads = std.atomic.Value(u64).init(0);

    var threads: [reader_count]std.Thread = undefined;
    for (&threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(.{}, stressReader, .{ &rcu, &gen, i, &stop, &reads });
    }

    // Reload underneath them. Against the pre-fix code — which freed the old
    // value in place — this is the loop that corrupted a live reader.
    var i: u32 = 1;
    while (i <= 2000) : (i += 1) {
        try rcu.publish(&gen, try makeValue(allocator, i, &freed));
    }

    stop.store(true, .release);
    for (threads) |t| t.join();

    // Readers really did run, or the test proved nothing.
    try std.testing.expect(reads.load(.monotonic) > 0);

    // Drain whatever the last publish could not yet reclaim. The readers have
    // exited, so a final quiesce from each is what a joined worker implies.
    for (0..reader_count) |idx| gen.quiesce(idx);
    rcu.sweep(&gen);

    // Every superseded value was freed exactly once, and only the live one
    // remains for deinit.
    try std.testing.expectEqual(@as(u32, 2000), freed);
    try std.testing.expectEqual(@as(usize, 0), rcu.retiredCount());
    try std.testing.expectEqual(@as(u32, 2000), rcu.get().?.id);
}

test "with no workers registered everything is immediately reclaimable" {
    const allocator = std.testing.allocator;
    var gen = reload.ConfigGeneration.init();
    defer gen.deinit(allocator);

    var freed: u32 = 0;
    var rcu = Rcu(TestValue).init(allocator, freeTestValue);
    defer rcu.deinit();

    try rcu.publish(&gen, try makeValue(allocator, 1, &freed));
    try rcu.publish(&gen, try makeValue(allocator, 2, &freed));

    // No worker can hold a reference, so the first value goes on the next
    // sweep rather than accumulating for the lifetime of the process.
    try std.testing.expectEqual(@as(u32, 1), freed);
    try std.testing.expectEqual(@as(usize, 0), rcu.retiredCount());
}
