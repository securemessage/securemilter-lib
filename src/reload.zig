const std = @import("std");

/// Atomic configuration generation counter for lock-free reload signaling.
///
/// The main thread increments this after swapping in new configuration.
/// Worker threads compare their local generation snapshot against this
/// global value on each event loop iteration — if stale, they execute
/// their product-specific reload action (e.g., flush LRU key cache).
///
/// This is a single atomic counter (not a full RCU/epoch scheme) because:
/// - Config swaps are module-level global pointer assignments (instantaneous)
/// - Workers only need to know "something changed" — not what generation
///   they missed (they always reload to current state)
/// - No deferred freeing is needed since config data is static lifetime
///   (backed by the original parsed INI allocation or a replace-in-place swap)
pub const ConfigGeneration = struct {
    global: std.atomic.Value(u64),

    pub fn init() ConfigGeneration {
        return .{ .global = std.atomic.Value(u64).init(0) };
    }

    /// Called by main thread after config swap completes.
    pub fn increment(self: *ConfigGeneration) void {
        _ = self.global.fetchAdd(1, .release);
    }

    /// Called by workers to read the current generation.
    pub fn load(self: *const ConfigGeneration) u64 {
        return self.global.load(.acquire);
    }
};

test "config generation increment and load" {
    var gen = ConfigGeneration.init();
    try std.testing.expectEqual(@as(u64, 0), gen.load());

    gen.increment();
    try std.testing.expectEqual(@as(u64, 1), gen.load());

    gen.increment();
    gen.increment();
    try std.testing.expectEqual(@as(u64, 3), gen.load());
}
