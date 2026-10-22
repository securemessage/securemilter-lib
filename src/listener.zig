const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const posix = std.posix;
const mem = std.mem;
const log_mod = @import("log.zig");
const escape = @import("escape.zig");
const ip = @import("ip.zig");

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
    ///
    /// Every value this accepts must be one `bind` can bind. That is not a
    /// nicety: a value accepted here and refused there escapes the config
    /// parser, and the refusal then surfaces inside a worker thread during
    /// startup where the only response available is to log and die. So the
    /// checks below are performed with the *same functions* `bind` calls,
    /// rather than with an independent reimplementation that can drift
    /// (X-14 was precisely this pair disagreeing: `inet:8891@localhost`
    /// parsed cleanly, failed at bind, and left a live daemon listening on
    /// nothing while its startup log said `listeners=1`).
    pub fn parse(spec: []const u8) !ListenAddress {
        if (mem.startsWith(u8, spec, "inet:")) {
            return parseTcp(spec[5..]);
        } else if (mem.startsWith(u8, spec, "unix:")) {
            return parseUnix(spec[5..]);
        } else if (mem.startsWith(u8, spec, "/")) {
            return parseUnix(spec);
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

            // `bind` resolves the host with parseIpAddress and nothing else --
            // no DNS, deliberately. A name would therefore always fail there,
            // so reject it here where the operator can be told which line of
            // which config file is wrong.
            _ = parseIpAddress(host, port) catch return error.InvalidHost;

            return .{ .tcp = .{ .host = host, .port = port } };
        }

        // No host given: the default is a literal, so there is nothing to validate.
        const port = std.fmt.parseInt(u16, spec, 10) catch return error.InvalidPort;
        return .{ .tcp = .{ .host = "0.0.0.0", .port = port } };
    }

    fn parseUnix(path: []const u8) !ListenAddress {
        // Same reasoning as the host check: sun_path is a fixed-size field, so
        // an over-long path fails in initUnix at bind time. Checked with
        // initUnix itself so the limit cannot be duplicated wrongly here.
        _ = net.Address.initUnix(path) catch return error.InvalidPath;

        return .{ .unix = .{ .path = path } };
    }
};

/// Resolve one `[listener:*]` section's `Socket` value, or fail loudly (audit
/// X-14).
///
/// A missing or malformed `Socket` must never be silently discarded: if it was
/// the only listener, the caller's "no listener sections" fallback would bind
/// the loopback default instead -- so the daemon would not fail to listen, it
/// would listen somewhere else, having been told plainly where to listen. In
/// the two daemons that carry a per-listener `Mode`, that fallback also
/// supplies the *global* mode, so a mistyped `verify` listener could come up in
/// whatever mode `[global] Mode` names. If it was one of several listeners,
/// that listener simply would not exist, and under Postfix's
/// `milter_default_action = accept` an unreachable milter means mail is
/// delivered unfiltered -- indistinguishable from success.
///
/// So this refuses instead, and names the section and the value. There is no
/// deployment that depends on a typo being ignored, and no man page promises a
/// fallback for a malformed value -- the documented default covers an *absent*
/// listener section, which the caller still honours.
pub fn parseListenerSocket(section_name: []const u8, spec: ?[]const u8) !ListenAddress {
    const value = spec orelse {
        log_mod.err("config: [{f}] has no Socket setting -- a listener section must name an address", .{escape.logField(section_name)});
        return error.MissingListenerSocket;
    };

    return ListenAddress.parse(value) catch |err| {
        log_mod.err(
            "config: [{f}] Socket={f} is not a valid listen address ({}) -- expected inet:port@ip or unix:/path",
            .{ escape.logField(section_name), escape.logField(value), err },
        );
        return error.InvalidListenerSocket;
    };
}

/// A bound, listening socket ready for accept().
pub const BoundListener = struct {
    server: net.Server,
    address: ListenAddress,
    fd: posix.fd_t,

    /// Get the file descriptor for kqueue registration.
    pub fn getFd(self: *const BoundListener) posix.fd_t {
        return self.fd;
    }

    /// Close the listening socket. Idempotent: the drain path closes
    /// listeners before Worker.deinit() runs, and a second close would
    /// hit EBADF in posix.close (unreachable → abort).
    pub fn close(self: *BoundListener) void {
        if (self.fd < 0) return;
        switch (self.address) {
            .unix => |ux| std.fs.cwd().deleteFile(ux.path) catch {},
            .tcp => {},
        }
        self.server.stream.close();
        self.fd = -1;
    }

    /// Accept a connection (non-blocking).
    pub fn accept(self: *BoundListener) !net.Server.Connection {
        return self.server.accept();
    }
};

/// `TCP_NODELAY` from <netinet/tcp.h>. Zig 0.15 exposes `std.c.TCP` for linux
/// and macos but leaves it `void` on FreeBSD, so the value is written out here
/// the same way `dns/resolver.zig` writes `TCP_KEEPINIT`.
const TCP_NODELAY: u32 = 1;

/// Set O_NONBLOCK on a descriptor.
pub fn setNonBlocking(fd: posix.fd_t) !void {
    const flags = try posix.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    // O_NONBLOCK = 0x0004 on FreeBSD
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | 0x0004);
}

/// Prepare a freshly accepted connection: non-blocking, and for TCP, no Nagle.
///
/// NAGLE IS WRONG FOR THIS PROTOCOL. Milter is strictly request/response -- the
/// MTA sends a command and waits -- so coalescing small writes buys nothing and
/// costs a delayed-ACK round trip wherever the daemon writes twice in a row. It
/// writes twice at end-of-message: one packet per header modification, then the
/// final action.
///
/// Measured with real Postfix on the production-emulating jails, capturing port
/// 8891: the daemon wrote the 65-byte Authentication-Results modification, then
/// sat 52.4 ms until Postfix's delayed ACK arrived before it could send the
/// 5-byte accept, while its own log recorded elapsed=1-3ms. Postfix lists four
/// milters and each stamps a header, so a message paid that four times.
///
/// Sendmail's libmilter does not set this (it sets only SO_REUSEADDR on the
/// listener and SO_KEEPALIVE on the connection) and writes one packet per call
/// exactly as this does, so OpenDKIM over TCP stalls the same way. That is not a
/// reason to keep it: it is why the stall is rarely reported, because most
/// deployments reach their milters over a unix socket, where Nagle never applies.
///
/// SO_KEEPALIVE matches libmilter's one connection-side option: the milters
/// hold long-lived TCP connections from the MTA, and a silently dead peer
/// (jail restart, NAT state drop) would otherwise occupy a connection slot
/// until the next message write fails. Keepalive probes surface that in the
/// background instead.
///
/// A failed setsockopt is ignored: the option cannot meaningfully fail on a TCP
/// socket, and a lost optimisation must not cost a connection that works.
pub fn prepareAccepted(addr: ListenAddress, fd: posix.fd_t) !void {
    try setNonBlocking(fd);
    switch (addr) {
        // Neither option is defined for a unix socket.
        .unix => {},
        .tcp => {
            const one: u32 = 1;
            posix.setsockopt(fd, posix.IPPROTO.TCP, TCP_NODELAY, mem.asBytes(&one)) catch {};
            posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, mem.asBytes(&one)) catch {};
        },
    }
}

/// The socket option under which the kernel spreads incoming TCP connections
/// across every listener bound to the same address and port.
///
/// On FreeBSD plain SO_REUSEPORT only lets the sockets share the port, and
/// every connection goes to one of them; balancing is SO_REUSEPORT_LB
/// (FreeBSD 12+). Linux balances under SO_REUSEPORT. Other kernels share
/// without balancing, so the build refuses them rather than run N workers of
/// which one does all the work.
const balanced_reuse_port: u32 = switch (builtin.os.tag) {
    .freebsd => posix.SO.REUSEPORT_LB,
    .linux => posix.SO.REUSEPORT,
    else => @compileError("no kernel-balanced TCP listener option on this OS"),
};

/// Most listeners one balancing group holds. On FreeBSD this is
/// INPCBLBGROUP_SIZMAX (sys/netinet/in_pcb.c): a socket bound past it binds
/// successfully but never joins the group, so it is never handed a connection.
/// Linux counts group members in a u16.
pub const balanced_listeners_max: u32 = switch (builtin.os.tag) {
    .freebsd => 256,
    .linux => std.math.maxInt(u16),
    else => @compileError("no kernel-balanced TCP listener option on this OS"),
};

const listen_backlog: u31 = 256;

/// Bind and listen on a parsed address. The socket is non-blocking.
///
/// Each worker calls this for every configured address, so a TCP address gets
/// one listening socket per worker. Those sockets set SO_REUSEADDR and
/// `balanced_reuse_port`, and the kernel spreads connections across them by
/// connection hash.
///
/// A Unix path is unlinked and rebound by each worker in turn, so only the
/// socket bound last stays reachable and it receives every connection.
pub fn bind(addr: ListenAddress) !BoundListener {
    switch (addr) {
        .tcp => |tcp| {
            const net_addr = try parseIpAddress(tcp.host, tcp.port);
            const server = try listenBalanced(net_addr);
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
                .kernel_backlog = listen_backlog,
            });
            return .{
                .server = server,
                .address = addr,
                .fd = server.stream.handle,
            };
        },
    }
}

/// Open a non-blocking TCP listener on `address` that joins the kernel's
/// balancing group for that address and port. Built by hand because
/// `std.net.Address.listen` sets SO_REUSEPORT, never SO_REUSEPORT_LB.
fn listenBalanced(address: net.Address) !net.Server {
    const sock_flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const fd = try posix.socket(address.any.family, sock_flags, posix.IPPROTO.TCP);
    errdefer posix.close(fd);

    const one: c_int = 1;
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, mem.asBytes(&one));
    try posix.setsockopt(fd, posix.SOL.SOCKET, balanced_reuse_port, mem.asBytes(&one));

    var server: net.Server = .{ .listen_address = undefined, .stream = .{ .handle = fd } };
    var socklen = address.getOsSockLen();
    try posix.bind(fd, &address.any, socklen);
    try posix.listen(fd, listen_backlog);
    try posix.getsockname(fd, &server.listen_address.any, &socklen);
    return server;
}

/// Parse an IP address string into a net.Address without using resolveIp
/// (which requires if_nametoindex, not available on all platforms in Zig 0.15).
///
/// The v6 half goes through the STRICT parser (L-7): `std.net.Ip6Address.parse`
/// repairs what it cannot read, and on this path a repair becomes a bind to an
/// address the operator did not write -- `Socket=inet:8890@:CAFE::` was measured
/// landing on [::]:8890, every interface, on the protocol with no
/// authentication. The v4 half of std.net has no repair behaviour to avoid.
fn parseIpAddress(host: []const u8, port: u16) !net.Address {
    if (net.Ip4Address.parse(host, port)) |ip4| {
        return .{ .in = ip4 };
    } else |_| {}

    if (ip.parseIp6Address(host, port)) |addr| {
        return addr;
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

// X-14. `bind` accepts only a literal IP, so `parse` must reject a hostname
// too: accepting one here and failing at bind turns a config error into a dead
// worker thread. These pin the two halves to the same contract: if `parse`
// accepts it, `bind` must be able to bind it.
test "parse rejects a hostname, because bind cannot resolve one" {
    // The obvious thing an operator writes, and the exact value that produced
    // a live daemon with no listener.
    try std.testing.expectError(error.InvalidHost, ListenAddress.parse("inet:8891@localhost"));
    try std.testing.expectError(error.InvalidHost, ListenAddress.parse("inet:8891@mail.example.com"));
}

test "parse rejects a repaired IPv6 literal (L-7)" {
    // The measured L-7 case: one illegal leading colon. The stdlib parser
    // repairs this to "::cafe::" and the daemon then binds the WILDCARD --
    // told to listen on one address, it listened on all of them, on the
    // protocol that has no authentication. Now a parse error instead.
    // parseTcp reports host failures as InvalidHost -- the same variant the
    // X-14 tests assert for a bad host.
    try std.testing.expectError(error.InvalidHost, ListenAddress.parse("inet:8890@:CAFE::"));
    // And the honest form still parses.
    _ = try ListenAddress.parse("inet:8890@fd10:99::254");
}

test "parse rejects a misspelled scheme rather than reinterpreting it" {
    // Each of these falls through to parseTcp as a whole and fails on the
    // port -- the right answer, since none is a recognised scheme. `inet6:`
    // is the one an operator actually reaches for.
    try std.testing.expectError(error.InvalidPort, ListenAddress.parse("inet6:8891@::1"));
    try std.testing.expectError(error.InvalidPort, ListenAddress.parse("tcp:8891"));
    try std.testing.expectError(error.InvalidPort, ListenAddress.parse("unxi:/var/run/m.sock"));
    try std.testing.expectError(error.InvalidPort, ListenAddress.parse(""));
}

test "parse still accepts every form bind supports" {
    // The other direction. A stricter parser that rejected a legitimate
    // address would break deployments, so pin the accepted set too.
    _ = try ListenAddress.parse("inet:8891@0.0.0.0");
    _ = try ListenAddress.parse("inet:8891@127.0.0.1");
    _ = try ListenAddress.parse("inet:8891@::1");
    _ = try ListenAddress.parse("inet:8891@::");
    _ = try ListenAddress.parse("8891");
    _ = try ListenAddress.parse("unix:/var/run/m.sock");
    _ = try ListenAddress.parse("/var/run/m.sock");
}

test "every address parse accepts, bind accepts" {
    // The contract itself, checked end to end on port 0 so it is
    // hermetic. This is the assertion that would have caught X-14.
    for ([_][]const u8{ "inet:0@127.0.0.1", "inet:0@::1", "0" }) |spec| {
        const addr = try ListenAddress.parse(spec);
        var listener = bind(addr) catch |err| {
            std.debug.print("parse accepted '{s}' but bind rejected it: {}\n", .{ spec, err });
            return error.ParseBindContractBroken;
        };
        listener.close();
    }
}

test "bind and close tcp" {
    var listener = try bind(.{ .tcp = .{ .host = "127.0.0.1", .port = 0 } });
    defer listener.close();
    try std.testing.expect(listener.fd >= 0);
}

// Goal: a TCP address bound once per worker spreads connections across every
// worker's listener. Method: bind four listeners on one port, open 128
// connections, then count what each listener's accept queue received. With
// plain SO_REUSEPORT on FreeBSD all 128 land on one listener. Under hashing,
// the chance that any of the four receives none is about 4 * 0.75^128.
test "connections to a shared TCP address reach every listener" {
    const listener_count = 4;
    const connection_count = 128;

    var listeners: [listener_count]BoundListener = undefined;
    var bound: usize = 0;
    defer for (listeners[0..bound]) |*lst| lst.close();

    listeners[0] = try bind(.{ .tcp = .{ .host = "127.0.0.1", .port = 0 } });
    bound = 1;
    const port = listeners[0].server.listen_address.getPort();
    while (bound < listener_count) : (bound += 1) {
        listeners[bound] = try bind(.{ .tcp = .{ .host = "127.0.0.1", .port = port } });
    }

    var clients: [connection_count]net.Stream = undefined;
    var connected: usize = 0;
    defer for (clients[0..connected]) |client| client.close();

    const target = try net.Address.parseIp4("127.0.0.1", port);
    while (connected < connection_count) : (connected += 1) {
        clients[connected] = try net.tcpConnectToAddress(target);
    }

    // A connect can return before the server side of the handshake reaches an
    // accept queue, so sweep the listeners until every connection is counted.
    var accepted: [listener_count]usize = @splat(0);
    var total: usize = 0;
    var sweeps: usize = 0;
    while (total < connection_count and sweeps < 10_000) : (sweeps += 1) {
        for (&listeners, &accepted) |*lst, *count| {
            while (lst.accept()) |conn| {
                conn.stream.close();
                count.* += 1;
                total += 1;
            } else |err| switch (err) {
                error.WouldBlock => {},
                else => return err,
            }
        }
    }

    try std.testing.expectEqual(@as(usize, connection_count), total);
    for (accepted) |count| {
        if (count == 0) std.debug.print("per-listener accepts: {any}\n", .{accepted});
        try std.testing.expect(count > 0);
    }
}

test "bind and close unix" {
    const path = "/tmp/securemilter-test.sock";
    var listener = try bind(.{ .unix = .{ .path = path } });
    defer listener.close();
    defer std.fs.cwd().deleteFile(path) catch {};
    try std.testing.expect(listener.fd >= 0);
}
