const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const net = std.net;
const Allocator = mem.Allocator;
const packet = @import("packet.zig");
const daemon_mod = @import("../daemon.zig");

const log_mod = @import("../log.zig");

/// Maximum number of nameservers supported.
pub const MAX_SERVERS = 8;

/// Probe defaults, previously written as bare 53/5/2000 at four call sites.
const PROBE_PORT = 53;
const PROBE_INTERVAL_S = 5;
const PROBE_TIMEOUT_MS = 2000;

/// Start the proactive monitor, or return null having said why.
///
/// Null is a SUPPORTED MODE, not a failure: `Resolver.initWithMonitor(.., null)` falls
/// back to trying every server with timeout-based failover, which is slower but correct.
/// So neither branch here is fatal, and both are warnings.
///
/// Note the asymmetry, which is deliberate and was in all four copies of this: if
/// `init` fails there is no monitor and null is the only answer, but if only `start`
/// fails the monitor object is still returned. It holds the health flags, every
/// resolver reads them, and they default to healthy — so a monitor whose thread never
/// came up behaves exactly like no monitor, whereas dropping it here would lose the
/// pointer that the rest of the daemon expects to hand to each resolver.
///
/// Call from `Options.spawn_threads`, which is the point in the bootstrap where
/// creating a thread is safe: after the fork, and after the managed signals are blocked.
pub fn startMonitor(allocator: Allocator, nameservers: []const []const u8) ?*HealthMonitor {
    const monitor = HealthMonitor.init(
        allocator,
        nameservers,
        PROBE_PORT,
        PROBE_INTERVAL_S,
        PROBE_TIMEOUT_MS,
    ) catch |err| {
        log_mod.warn("DNS health monitor init failed: {}, falling back to reactive", .{err});
        return null;
    };

    monitor.start() catch |err| {
        log_mod.warn("DNS health monitor thread failed: {}", .{err});
    };
    return monitor;
}

/// Shared DNS server health state, probed by a background thread.
///
/// The monitor thread sends lightweight probe queries ("." NS) to each
/// nameserver at a configurable interval. Workers read health state
/// atomically — zero-delay skip of unhealthy servers on the hot path.
///
/// Lifecycle: create in main thread before spawning workers, pass pointer
/// to each Resolver, stop before process exit.
pub const HealthMonitor = struct {
    /// Atomic health flags: 1 = healthy, 0 = unhealthy. Workers read, monitor writes.
    server_healthy: [MAX_SERVERS]std.atomic.Value(u8),
    addrs: []net.Address,
    num_servers: usize,
    probe_interval_s: u32,
    probe_timeout_ms: u32,
    port: u16,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(u8),
    allocator: Allocator,

    /// Create a health monitor for the given nameserver addresses.
    /// Does NOT start the probe thread — call `start()` after creation.
    pub fn init(allocator: Allocator, nameservers: []const []const u8, port: u16, probe_interval_s: u32, probe_timeout_ms: u32) !*HealthMonitor {
        if (nameservers.len == 0 or nameservers.len > MAX_SERVERS) return error.InvalidServerCount;

        const monitor = try allocator.create(HealthMonitor);
        errdefer allocator.destroy(monitor);

        const addrs = try allocator.alloc(net.Address, nameservers.len);
        errdefer allocator.free(addrs);

        for (nameservers, 0..) |ns, i| {
            addrs[i] = parseNameserver(ns, port) catch return error.InvalidNameserver;
        }

        monitor.* = .{
            .server_healthy = undefined,
            .addrs = addrs,
            .num_servers = nameservers.len,
            .probe_interval_s = probe_interval_s,
            .probe_timeout_ms = probe_timeout_ms,
            .port = port,
            .thread = null,
            .stop_flag = std.atomic.Value(u8).init(0),
            .allocator = allocator,
        };

        // All servers start as healthy (optimistic — avoid blocking on first query)
        for (0..MAX_SERVERS) |i| {
            monitor.server_healthy[i] = std.atomic.Value(u8).init(if (i < nameservers.len) 1 else 0);
        }

        return monitor;
    }

    /// Start the background probe thread.
    pub fn start(self: *HealthMonitor) !void {
        self.thread = try std.Thread.spawn(.{}, probeLoop, .{self});
    }

    /// Signal the probe thread to stop and wait for it to exit.
    pub fn stop(self: *HealthMonitor) void {
        self.stop_flag.store(1, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    pub fn deinit(self: *HealthMonitor) void {
        self.stop();
        self.allocator.free(self.addrs);
        self.allocator.destroy(self);
    }

    /// Check if server at index is healthy (atomic read, safe from any thread).
    pub fn isHealthy(self: *const HealthMonitor, idx: usize) bool {
        if (idx >= self.num_servers) return false;
        return self.server_healthy[idx].load(.acquire) != 0;
    }

    /// Count how many servers are currently healthy.
    pub fn healthyCount(self: *const HealthMonitor) usize {
        var count: usize = 0;
        for (0..self.num_servers) |i| {
            if (self.server_healthy[i].load(.acquire) != 0) count += 1;
        }
        return count;
    }

    fn probeLoop(self: *HealthMonitor) void {
        // Block the daemon-managed signals in this thread before doing anything
        // else.
        //
        // A thread inherits its signal mask from whoever spawned it, and the
        // daemons all block these signals in main() only just before spawning
        // their worker pool — which is *after* this monitor starts. That left
        // this thread as the only one in the process with SIGHUP unblocked
        // (audit X-7). The main thread normally wins a SIGHUP because it is
        // parked in sigwait(), but while it is away running the reload callback
        // it is not a candidate, and the kernel then delivers to the first
        // thread that does not block the signal — this one — where the default
        // action for SIGHUP is to terminate the process. SIGHUP does not dump
        // core, so the daemon vanished with no core and no kernel log line.
        //
        // Fixing the call order in the daemons is the real fix and is done, but
        // that correctness then depends on four separate main() functions
        // keeping two statements in the right order forever. Blocking here as
        // well makes the invariant belong to the thread that needs it.
        daemon_mod.ManagedSignals.blockForKqueue();

        // Initial probe immediately on startup
        self.probeAll();

        while (self.stop_flag.load(.acquire) == 0) {
            // Sleep in small increments so we can respond to stop_flag quickly
            var slept: u32 = 0;
            while (slept < self.probe_interval_s and self.stop_flag.load(.acquire) == 0) {
                std.Thread.sleep(std.time.ns_per_s);
                slept += 1;
            }
            if (self.stop_flag.load(.acquire) != 0) break;

            self.probeAll();
        }
    }

    fn probeAll(self: *HealthMonitor) void {
        for (0..self.num_servers) |i| {
            const healthy = self.probeServer(self.addrs[i]);
            self.server_healthy[i].store(if (healthy) 1 else 0, .release);
        }
    }

    /// Send a "." NS probe query to a single server and wait for response.
    fn probeServer(self: *HealthMonitor, addr: net.Address) bool {
        // Build a minimal "." NS query (root nameservers — every resolver answers this)
        var query_buf: [32]u8 = undefined;
        const query_len = buildProbeQuery(&query_buf) catch return false;

        const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0) catch return false;
        defer posix.close(sock);

        const timeout_sec = self.probe_timeout_ms / 1000;
        const timeout_usec = (self.probe_timeout_ms % 1000) * 1000;
        const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = @intCast(timeout_usec) };
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&tv)) catch return false;

        _ = posix.sendto(sock, query_buf[0..query_len], 0, &addr.any, addr.getOsSockLen()) catch return false;

        var buf: [512]u8 = undefined;
        const n = posix.recvfrom(sock, &buf, 0, null, null) catch return false;

        // Any valid DNS response (≥12 bytes header) = server is alive
        return n >= 12;
    }
};

/// Build a minimal DNS query for "." NS (17 bytes).
fn buildProbeQuery(buf: []u8) !usize {
    if (buf.len < 17) return error.BufferTooSmall;

    // Header: ID=0x0001, flags=0x0100 (RD=1), QDCOUNT=1
    buf[0] = 0x00;
    buf[1] = 0x01; // ID
    buf[2] = 0x01;
    buf[3] = 0x00; // Flags: RD=1
    buf[4] = 0x00;
    buf[5] = 0x01; // QDCOUNT=1
    buf[6] = 0x00;
    buf[7] = 0x00; // ANCOUNT=0
    buf[8] = 0x00;
    buf[9] = 0x00; // NSCOUNT=0
    buf[10] = 0x00;
    buf[11] = 0x00; // ARCOUNT=0

    // Question: "." (root, encoded as single 0x00 label terminator)
    buf[12] = 0x00; // root label

    // Type: NS (0x0002)
    buf[13] = 0x00;
    buf[14] = 0x02;

    // Class: IN (0x0001)
    buf[15] = 0x00;
    buf[16] = 0x01;

    return 17;
}

fn parseNameserver(host: []const u8, port: u16) !net.Address {
    if (net.Ip4Address.parse(host, port)) |ip4| {
        return .{ .in = ip4 };
    } else |_| {}
    if (net.Ip6Address.parse(host, port)) |ip6| {
        return .{ .in6 = ip6 };
    } else |_| {}
    return error.InvalidNameserver;
}

test "health monitor init and deinit" {
    const servers: []const []const u8 = &.{ "8.8.8.8", "1.1.1.1" };
    const monitor = try HealthMonitor.init(std.testing.allocator, servers, 53, 5, 2000);
    defer monitor.deinit();
    try std.testing.expectEqual(@as(usize, 2), monitor.num_servers);
    // All servers start healthy
    try std.testing.expect(monitor.isHealthy(0));
    try std.testing.expect(monitor.isHealthy(1));
    try std.testing.expect(!monitor.isHealthy(2));
    try std.testing.expectEqual(@as(usize, 2), monitor.healthyCount());
}

test "build probe query" {
    var buf: [32]u8 = undefined;
    const len = try buildProbeQuery(&buf);
    try std.testing.expectEqual(@as(usize, 17), len);
    // Check it's a valid DNS query header
    try std.testing.expectEqual(@as(u8, 0x01), buf[2]); // Flags byte 1: RD=1
    try std.testing.expectEqual(@as(u8, 0x01), buf[5]); // QDCOUNT=1
    try std.testing.expectEqual(@as(u8, 0x00), buf[12]); // root label
    try std.testing.expectEqual(@as(u8, 0x02), buf[14]); // Type NS
}
