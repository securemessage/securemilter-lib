pub const packet = @import("dns/packet.zig");
pub const resolver = @import("dns/resolver.zig");
pub const health = @import("dns/health.zig");
const packet_test = @import("dns/packet_test.zig");

pub const RecordType = packet.RecordType;
pub const Resolver = resolver.Resolver;
pub const ResolverConfig = resolver.ResolverConfig;
pub const HealthMonitor = resolver.HealthMonitor;
pub const Cache = resolver.Cache;

test {
    _ = packet;
    _ = resolver;
    _ = health;
    _ = packet_test;
}
