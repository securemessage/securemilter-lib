//! A wall-clock deadline for one evaluation.
//!
//! X-21: `securespf` was the only daemon that bounded its own work in time
//! (`max_duration_ms`); the other three measured elapsed time only to log it,
//! so a slow-but-working resolver could hold a worker for unbounded seconds
//! past the MTA's own timeout. This is the shared form of that bound, used by
//! every daemon's evaluation loop, so the four cannot drift on what "give up"
//! means.
//!
//! Expiry must never become a verdict against the sender: every caller maps it
//! to the daemon's "could not evaluate" answer (temperror / unknown), never
//! fail -- the message was not judged, merely not judged in time.

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
