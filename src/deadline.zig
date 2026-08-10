//! Shared wall-clock deadline for one evaluation.
//!
//! Callers map expiry to an indeterminate result, never a sender failure.

const std = @import("std");

/// The shared default, in milliseconds: 20 s. `securespf` has shipped this
/// default as `max_duration_ms`; the other daemons now share both the number
/// and (via `OPTION_NAME`) the spelling.
pub const DEFAULT_MS: i64 = 20_000;

/// The config key, one spelling for every daemon: an operator tuning one must
/// not discover another daemon counts differently (the A-24 rule).
pub const OPTION_NAME = "MaxEvaluationMs";

pub const Deadline = struct {
    at_ms: i64,

    /// A deadline `max_duration_ms` from now. 0 disables the limit (never
    /// expires), matching the `Max*` convention the rest of the suite uses.
    pub fn fromNow(max_duration_ms: i64) Deadline {
        return .{ .at_ms = if (max_duration_ms == 0)
            std.math.maxInt(i64)
        else
            std.time.milliTimestamp() + max_duration_ms };
    }

    /// Test seam: an absolute expiry with no sleep and no clock control.
    /// `initAbsolute(0)` is already expired, which is what lets a deadline
    /// test be deterministic.
    pub fn initAbsolute(at_ms: i64) Deadline {
        return .{ .at_ms = at_ms };
    }

    pub fn expired(self: *const Deadline) bool {
        return std.time.milliTimestamp() >= self.at_ms;
    }
};

test "a deadline expires, zero disables, absolute zero is already expired" {
    var soon = Deadline.fromNow(1);
    std.Thread.sleep(5 * std.time.ns_per_ms);
    try std.testing.expect(soon.expired());

    const off = Deadline.fromNow(0);
    try std.testing.expect(!off.expired());

    const past = Deadline.initAbsolute(0);
    try std.testing.expect(past.expired());
}
