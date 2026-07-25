const std = @import("std");
const net = std.net;
const posix = std.posix;
const mem = std.mem;

/// Parsed listener address from config.
///
/// Supports two formats:
///   inet:port@host  — TCP socket (e.g., "inet:8891@0.0.0.0")
///   unix:/path      — Unix domain socket (e.g., "unix:/var/run/milter.sock")
pub const ListenAddress = union(enum) {
    tcp: struct {
        host: []const u8,
        port: u16,
    },
    unix: struct {
        path: []const u8,
    },

    /// Parse a listener address string from config.
    pub fn parse(spec: []const u8) !ListenAddress {
        if (mem.startsWith(u8, spec, "inet:")) {
            return parseTcp(spec[5..]);
        } else if (mem.startsWith(u8, spec, "unix:")) {
            return .{ .unix = .{ .path = spec[5..] } };
        } else if (mem.startsWith(u8, spec, "/")) {
            return .{ .unix = .{ .path = spec } };
        } else {
            return parseTcp(spec);
        }
    }

    fn parseTcp(spec: []const u8) !ListenAddress {
        const at_pos = mem.indexOfScalar(u8, spec, '@');
        if (at_pos) |pos| {
            const port_str = spec[0..pos];
            const host = spec[pos + 1 ..];
            const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;
            return .{ .tcp = .{ .host = host, .port = port } };
        }

        const port = std.fmt.parseInt(u16, spec, 10) catch return error.InvalidPort;
        return .{ .tcp = .{ .host = "0.0.0.0", .port = port } };
    }
};

/// A bound, listening socket ready for accept().
pub const BoundListener = struct {
    server: net.Server,
    address: ListenAddress,
    fd: posix.fd_t,

    /// Get the file descriptor for kqueue registration.
    pub fn getFd(self: *const BoundListener) posix.fd_t {
        return self.fd;
    }

    pub fn close(self: *BoundListener) void {
        self.server.stream.close();
    }

    /// Accept a connection (non-blocking).
    pub fn accept(self: *BoundListener) !net.Server.Connection {
        return self.server.accept();
    }
};

/// Bind and listen on a parsed address.
///
/// Uses SO_REUSEADDR + SO_REUSEPORT (for TCP), O_NONBLOCK.
/// Each worker thread calls this independently for SO_REUSEPORT.
pub fn bind(addr: ListenAddress) !BoundListener {
    switch (addr) {
        .tcp => |tcp| {
            const net_addr = try parseIpAddress(tcp.host, tcp.port);
            const server = try net_addr.listen(.{
                .reuse_address = true,
                .force_nonblocking = true,
                .kernel_backlog = 256,
            });
            return .{
                .server = server,
                .address = addr,
                .fd = server.stream.handle,
            };
        },
        .unix => |ux| {
            std.fs.cwd().deleteFile(ux.path) catch {};

            const un_addr = try net.Address.initUnix(ux.path);
            const server = try un_addr.listen(.{
                .reuse_address = true,
                .force_nonblocking = true,
                .kernel_backlog = 256,
            });
            return .{
                .server = server,
                .address = addr,
                .fd = server.stream.handle,
            };
        },
    }
}

/// Parse an IP address string into a net.Address without using resolveIp
/// (which requires if_nametoindex, not available on all platforms in Zig 0.15).
fn parseIpAddress(host: []const u8, port: u16) !net.Address {
    if (net.Ip4Address.parse(host, port)) |ip4| {
        return .{ .in = ip4 };
    } else |_| {}

    if (net.Ip6Address.parse(host, port)) |ip6| {
        return .{ .in6 = ip6 };
    } else |_| {}

    return error.InvalidAddress;
}

test "parse inet address with host" {
    const addr = try ListenAddress.parse("inet:8891@0.0.0.0");
    switch (addr) {
        .tcp => |tcp| {
            try std.testing.expectEqualStrings("0.0.0.0", tcp.host);
            try std.testing.expectEqual(@as(u16, 8891), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse inet address port only" {
    const addr = try ListenAddress.parse("inet:8891");
    switch (addr) {
        .tcp => |tcp| {
            try std.testing.expectEqualStrings("0.0.0.0", tcp.host);
            try std.testing.expectEqual(@as(u16, 8891), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse bare port" {
    const addr = try ListenAddress.parse("8891");
    switch (addr) {
        .tcp => |tcp| {
            try std.testing.expectEqual(@as(u16, 8891), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse unix path" {
    const addr = try ListenAddress.parse("unix:/var/run/milter.sock");
    switch (addr) {
        .unix => |ux| {
            try std.testing.expectEqualStrings("/var/run/milter.sock", ux.path);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse bare absolute path" {
    const addr = try ListenAddress.parse("/var/run/milter.sock");
    switch (addr) {
        .unix => |ux| {
            try std.testing.expectEqualStrings("/var/run/milter.sock", ux.path);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse inet with IPv6" {
    const addr = try ListenAddress.parse("inet:8891@::1");
    switch (addr) {
        .tcp => |tcp| {
            try std.testing.expectEqualStrings("::1", tcp.host);
            try std.testing.expectEqual(@as(u16, 8891), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "bind and close tcp" {
    var listener = try bind(.{ .tcp = .{ .host = "127.0.0.1", .port = 0 } });
    defer listener.close();
    try std.testing.expect(listener.fd >= 0);
}

test "bind and close unix" {
    const path = "/tmp/securemilter-test.sock";
    var listener = try bind(.{ .unix = .{ .path = path } });
    defer listener.close();
    defer std.fs.cwd().deleteFile(path) catch {};
    try std.testing.expect(listener.fd >= 0);
}
