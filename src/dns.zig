pub const packet = @import("dns/packet.zig");
pub const resolver = @import("dns/resolver.zig");
pub const cache = @import("dns/cache.zig");
pub const health = @import("dns/health.zig");

pub const RecordType = packet.RecordType;
pub const ResponseCode = packet.ResponseCode;
pub const Resolver = resolver.Resolver;
pub const ResolverConfig = resolver.ResolverConfig;
pub const HealthMonitor = resolver.HealthMonitor;
pub const Cache = resolver.Cache;
pub const NegativeKind = resolver.NegativeKind;
pub const isTransientError = resolver.isTransientError;
pub const startMonitor = health.startMonitor;

test {
    _ = packet;
    _ = resolver;
    _ = cache;
    _ = health;
}
