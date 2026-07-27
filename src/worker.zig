const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;
const c = std.c;
const Kevent = posix.Kevent;

const listener_mod = @import("listener.zig");
const connection_mod = @import("connection.zig");
const codec = @import("milter/codec.zig");
const commands = @import("milter/commands.zig");
const negotiate = @import("milter/negotiate.zig");
const responses = @import("milter/responses.zig");
const reload_mod = @import("reload.zig");
const log_mod = @import("log.zig");

/// Callback interface that product milters implement.
///
/// Each callback receives the connection and returns a milter response
/// code (continue, accept, reject, tempfail, etc.). The worker calls
/// these at the appropriate milter protocol stage.
pub const Callbacks = struct {
    on_connect: ?*const fn (*connection_mod.Connection, commands.ConnectInfo) u8 = null,
    on_helo: ?*const fn (*connection_mod.Connection, []const u8) u8 = null,
    on_mail_from: ?*const fn (*connection_mod.Connection, []const u8) u8 = null,
    on_rcpt_to: ?*const fn (*connection_mod.Connection, []const u8) u8 = null,
    on_header: ?*const fn (*connection_mod.Connection, []const u8, []const u8) u8 = null,
    on_eoh: ?*const fn (*connection_mod.Connection) u8 = null,
    on_body: ?*const fn (*connection_mod.Connection, []const u8) u8 = null,
    on_eom: ?*const fn (*connection_mod.Connection) u8 = null,
    on_abort: ?*const fn (*connection_mod.Connection) void = null,

    /// Called per-worker when config_generation advances (SIGHUP reload).
    /// Product milters use this to flush LRU caches or re-read thread-local state.
    on_reload: ?*const fn () void = null,

    required_actions: negotiate.ActionFlags = .{ .add_headers = true },
    skip_flags: negotiate.ProtocolFlags = .{},
};

/// Configuration for the worker pool.
pub const WorkerPoolConfig = struct {
    num_workers: u32,
    listen_addresses: []const listener_mod.ListenAddress,
    callbacks: Callbacks,
    allocator: Allocator,
};

/// Default drain timeout: 30 seconds.
const DRAIN_TIMEOUT_MS: u64 = 30_000;

/// Default max connections per worker if not configured.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 256;

/// A single worker thread's state.
///
/// Each worker owns its own kqueue, its own set of SO_REUSEPORT
/// listener sockets, and its own connection pool. Workers share
/// nothing with each other — no locks, no contention.
/// Maximum staged changelist entries. Flushed on next kevent() call.
const MAX_PENDING: usize = 128;

pub const Worker = struct {
    allocator: Allocator,
    kq: i32,
    listeners: std.ArrayList(listener_mod.BoundListener),
    connections: std.AutoHashMap(posix.fd_t, *connection_mod.Connection),
    callbacks: Callbacks,
    running: bool,
    shutdown_pipe: posix.fd_t,
    draining: bool,
    pending: [MAX_PENDING]Kevent,
    pending_len: usize,
    config_gen: ?*const reload_mod.ConfigGeneration,
    local_generation: u64,
    max_connections: u32,

    pub fn init(allocator: Allocator, addresses: []const listener_mod.ListenAddress, callbacks: Callbacks, shutdown_pipe: posix.fd_t) !Worker {
        return initWithReload(allocator, addresses, callbacks, shutdown_pipe, null, DEFAULT_MAX_CONNECTIONS);
    }

    pub fn initWithReload(allocator: Allocator, addresses: []const listener_mod.ListenAddress, callbacks: Callbacks, shutdown_pipe: posix.fd_t, config_gen: ?*const reload_mod.ConfigGeneration, max_conn: u32) !Worker {
        const kq = try posix.kqueue();

        var self = Worker{
            .allocator = allocator,
            .kq = kq,
            .listeners = .{},
            .connections = std.AutoHashMap(posix.fd_t, *connection_mod.Connection).init(allocator),
            .callbacks = callbacks,
            .running = true,
            .shutdown_pipe = shutdown_pipe,
            .draining = false,
            .pending = undefined,
            .pending_len = 0,
            .config_gen = config_gen,
            .local_generation = if (config_gen) |cg| cg.load() else 0,
            .max_connections = max_conn,
        };

        // Stage initial registrations — flushed on first kevent() call
        self.stageRead(shutdown_pipe);

        for (addresses) |addr| {
            const bound = try listener_mod.bind(addr);
            self.stageRead(bound.fd);
            try self.listeners.append(allocator, bound);
        }

        return self;
    }

    pub fn deinit(self: *Worker) void {
        var conn_iter = self.connections.iterator();
        while (conn_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.connections.deinit();

        for (self.listeners.items) |*lst| {
            lst.close();
        }
        self.listeners.deinit(self.allocator);

        posix.close(self.kq);
    }

    /// Run the kqueue event loop. Blocks until shutdown completes.
    ///
    /// Uses kqueue's combined changelist+eventlist pattern: pending fd
    /// registrations are batched and submitted alongside the wait call
    /// in a single syscall (no separate registration calls).
    pub fn run(self: *Worker) void {
        var events: [64]Kevent = undefined;
        var drain_deadline: i64 = 0;

        while (self.running) {
            // In drain mode: exit when all connections are done or timeout
            if (self.draining) {
                if (self.connections.count() == 0) break;
                if (std.time.milliTimestamp() >= drain_deadline) {
                    log_mod.warn("drain timeout, closing {d} remaining connections", .{self.connections.count()});
                    break;
                }
            }

            // Check for config reload (SIGHUP): compare local generation
            // to global. If stale, notify the product via on_reload callback
            // (e.g., flush LRU key cache) and advance local snapshot.
            if (self.config_gen) |cg| {
                const current = cg.load();
                if (current != self.local_generation) {
                    self.local_generation = current;
                    if (self.callbacks.on_reload) |cb| cb();
                }
            }

            // Single kevent() call: flush staged changes AND wait for events
            const drain_ts = posix.timespec{ .sec = 1, .nsec = 0 };
            const timeout: ?*const posix.timespec = if (self.draining) &drain_ts else null;
            const changelist = self.pending[0..self.pending_len];
            const n = posix.kevent(self.kq, changelist, &events, timeout) catch |err| {
                log_mod.err("kevent error: {}", .{err});
                self.pending_len = 0;
                continue;
            };
            self.pending_len = 0; // changes applied

            for (events[0..n]) |ev| {
                const fd: posix.fd_t = @intCast(ev.ident);

                // Shutdown pipe EOF (write-end closed) = begin drain
                if (fd == self.shutdown_pipe) {
                    if (!self.draining) {
                        self.beginDrain();
                        drain_deadline = std.time.milliTimestamp() + @as(i64, @intCast(DRAIN_TIMEOUT_MS));
                    }
                } else if (self.isListenFd(fd)) {
                    if (!self.draining) self.handleAccept(fd);
                } else if (ev.flags & 0x8000 != 0) { // EV_EOF = 0x8000 on FreeBSD
                    self.removeConnection(fd);
                } else {
                    self.handleConnectionData(fd);
                }
            }
        }
    }

    /// Stage a READ registration for the next kevent() call.
    /// If the buffer is full, flush immediately (rare — only under
    /// extreme accept bursts exceeding 128 simultaneous new connections).
    fn stageRead(self: *Worker, fd: posix.fd_t) void {
        if (self.pending_len >= MAX_PENDING) self.flushPending();
        self.pending[self.pending_len] = .{
            .ident = @intCast(fd),
            .filter = c.EVFILT.READ,
            .flags = c.EV.ADD | c.EV.CLEAR, // edge-triggered
            .fflags = 0,
            .data = 0,
            .udata = 0,
            ._ext = .{ 0, 0, 0, 0 },
        };
        self.pending_len += 1;
    }

    /// Emergency flush when pending buffer is full (standalone syscall).
    fn flushPending(self: *Worker) void {
        _ = posix.kevent(self.kq, self.pending[0..self.pending_len], &.{}, null) catch {};
        self.pending_len = 0;
    }

    /// Begin graceful drain: close all listener sockets so no new
    /// connections are accepted, then let in-flight messages complete.
    fn beginDrain(self: *Worker) void {
        self.draining = true;
        for (self.listeners.items) |*lst| {
            lst.close();
        }
    }

    fn isListenFd(self: *const Worker, fd: posix.fd_t) bool {
        for (self.listeners.items) |lst| {
            if (lst.fd == fd) return true;
        }
        return false;
    }

    fn listenerIndexForFd(self: *const Worker, fd: posix.fd_t) usize {
        for (self.listeners.items, 0..) |lst, i| {
            if (lst.fd == fd) return i;
        }
        return 0;
    }

    fn handleAccept(self: *Worker, listen_fd: posix.fd_t) void {
        const listener_index = self.listenerIndexForFd(listen_fd);

        while (true) {
            const conn_result = self.listeners.items[listener_index].accept() catch |err| {
                if (err == error.WouldBlock) break;
                log_mod.err("accept error: {}", .{err});
                break;
            };

            const conn_fd = conn_result.stream.handle;

            // Backpressure: reject connection if at capacity
            if (self.connections.count() >= self.max_connections) {
                posix.close(conn_fd);
                continue;
            }

            setNonBlocking(conn_fd) catch {
                posix.close(conn_fd);
                continue;
            };

            const conn = self.allocator.create(connection_mod.Connection) catch {
                posix.close(conn_fd);
                continue;
            };
            conn.* = connection_mod.Connection.init(self.allocator, conn_fd, listener_index);

            self.connections.put(conn_fd, conn) catch {
                conn.deinit();
                self.allocator.destroy(conn);
                continue;
            };

            self.stageRead(conn_fd);
        }
    }

    fn handleConnectionData(self: *Worker, fd: posix.fd_t) void {
        const conn = self.connections.get(fd) orelse return;

        const result = conn.reader.feed(fd);
        switch (result) {
            .packet => |pkt| {
                self.dispatchPacket(conn, pkt);
                // Connection may have been removed by dispatchPacket
                // (e.g., sendResponse write failure → removeConnection)
                if (self.connections.get(fd) == null) return;
                conn.reader.consume();
            },
            .incomplete => return,
            .closed => {
                self.removeConnection(fd);
                return;
            },
            .err => {
                self.removeConnection(fd);
                return;
            },
        }

        // Process any additional complete packets already buffered
        // (Postfix often sends multiple commands in one TCP segment)
        while (true) {
            if (self.connections.get(fd) == null) return; // connection was removed
            const next = conn.reader.tryDecode();
            switch (next) {
                .packet => |pkt| {
                    self.dispatchPacket(conn, pkt);
                    if (self.connections.get(fd) == null) return;
                    conn.reader.consume();
                },
                .incomplete => return,
                .closed => {
                    self.removeConnection(fd);
                    return;
                },
                .err => {
                    self.removeConnection(fd);
                    return;
                },
            }
        }
    }

    fn dispatchPacket(self: *Worker, conn: *connection_mod.Connection, pkt: codec.Packet) void {
        const cmd_byte = pkt.cmd;
        const data = pkt.data;

        switch (cmd_byte) {
            @intFromEnum(commands.Code.optneg) => self.handleOptneg(conn, data),
            @intFromEnum(commands.Code.macro) => self.handleMacro(conn, data),
            @intFromEnum(commands.Code.connect) => self.handleConnect(conn, data),
            @intFromEnum(commands.Code.helo) => self.handleHelo(conn, data),
            @intFromEnum(commands.Code.mail) => self.handleMailFrom(conn, data),
            @intFromEnum(commands.Code.rcpt) => self.handleRcptTo(conn, data),
            @intFromEnum(commands.Code.header) => self.handleHeader(conn, data),
            @intFromEnum(commands.Code.eoh) => self.handleEoh(conn),
            @intFromEnum(commands.Code.body) => self.handleBody(conn, data),
            @intFromEnum(commands.Code.body_eob) => self.handleEom(conn),
            @intFromEnum(commands.Code.abort) => self.handleAbort(conn),
            @intFromEnum(commands.Code.quit) => self.removeConnection(conn.fd),
            @intFromEnum(commands.Code.quit_new_conn) => {
                conn.resetMessage();
                conn.state = .new;
            },
            else => self.sendResponse(conn, @intFromEnum(responses.Code.@"continue")),
        }
    }

    fn handleOptneg(self: *Worker, conn: *connection_mod.Connection, data: []const u8) void {
        const offer = negotiate.parseOffer(data) catch {
            self.removeConnection(conn.fd);
            return;
        };
        const resp = negotiate.buildResponse(self.callbacks.required_actions, self.callbacks.skip_flags, offer);
        codec.writePacket(conn.fd, &resp) catch {
            self.removeConnection(conn.fd);
            return;
        };
        conn.state = .connected;
    }

    fn handleMacro(self: *Worker, conn: *connection_mod.Connection, data: []const u8) void {
        var macros = commands.parseMacros(self.allocator, data) catch return;
        defer macros.macros.deinit(self.allocator);
        conn.macros.update(self.allocator, &macros) catch {};
    }

    fn handleConnect(self: *Worker, conn: *connection_mod.Connection, data: []const u8) void {
        const info = commands.parseConnect(data) catch {
            self.sendResponse(conn, @intFromEnum(responses.Code.@"continue"));
            return;
        };
        conn.state = .connected;
        const resp = if (self.callbacks.on_connect) |cb| cb(conn, info) else @intFromEnum(responses.Code.@"continue");
        self.sendResponse(conn, resp);
    }

    fn handleHelo(self: *Worker, conn: *connection_mod.Connection, data: []const u8) void {
        const helo = stripNull(data);
        conn.setHelo(helo) catch {};
        conn.state = .helo;
        const resp = if (self.callbacks.on_helo) |cb| cb(conn, helo) else @intFromEnum(responses.Code.@"continue");
        self.sendResponse(conn, resp);
    }

    fn handleMailFrom(self: *Worker, conn: *connection_mod.Connection, data: []const u8) void {
        var iter = commands.parseNullTermArray(data);
        const sender = iter.next() orelse "";
        conn.setMailFrom(sender) catch {};
        conn.state = .mail_from;
        const resp = if (self.callbacks.on_mail_from) |cb| cb(conn, sender) else @intFromEnum(responses.Code.@"continue");
        self.sendResponse(conn, resp);
    }

    fn handleRcptTo(self: *Worker, conn: *connection_mod.Connection, data: []const u8) void {
        var iter = commands.parseNullTermArray(data);
        const rcpt = iter.next() orelse "";
        conn.addRecipient(rcpt) catch {};
        conn.state = .rcpt_to;
        const resp = if (self.callbacks.on_rcpt_to) |cb| cb(conn, rcpt) else @intFromEnum(responses.Code.@"continue");
        self.sendResponse(conn, resp);
    }

    fn handleHeader(self: *Worker, conn: *connection_mod.Connection, data: []const u8) void {
        const hdr = commands.parseHeader(data) catch {
            self.sendResponse(conn, @intFromEnum(responses.Code.@"continue"));
            return;
        };
        conn.addHeader(hdr.name, hdr.value) catch {};
        conn.state = .headers;
        const resp = if (self.callbacks.on_header) |cb| cb(conn, hdr.name, hdr.value) else @intFromEnum(responses.Code.@"continue");
        self.sendResponse(conn, resp);
    }

    fn handleEoh(self: *Worker, conn: *connection_mod.Connection) void {
        conn.state = .end_of_headers;
        const resp = if (self.callbacks.on_eoh) |cb| cb(conn) else @intFromEnum(responses.Code.@"continue");
        self.sendResponse(conn, resp);
    }

    fn handleBody(self: *Worker, conn: *connection_mod.Connection, data: []const u8) void {
        conn.state = .body;
        const resp = if (self.callbacks.on_body) |cb| cb(conn, data) else @intFromEnum(responses.Code.@"continue");
        self.sendResponse(conn, resp);
    }

    fn handleEom(self: *Worker, conn: *connection_mod.Connection) void {
        conn.state = .end_of_message;
        const resp = if (self.callbacks.on_eom) |cb| cb(conn) else @intFromEnum(responses.Code.accept);
        self.sendResponse(conn, resp);
        conn.resetMessage();
    }

    fn handleAbort(self: *Worker, conn: *connection_mod.Connection) void {
        if (self.callbacks.on_abort) |cb| cb(conn);
        conn.resetMessage();
    }

    fn sendResponse(self: *Worker, conn: *connection_mod.Connection, resp_code: u8) void {
        codec.writeSimpleResponse(conn.fd, resp_code) catch {
            self.removeConnection(conn.fd);
        };
    }

    fn removeConnection(self: *Worker, fd: posix.fd_t) void {
        if (self.connections.fetchRemove(fd)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        }
    }
};

fn setNonBlocking(fd: posix.fd_t) !void {
    const flags = try posix.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    // O_NONBLOCK = 0x0004 on FreeBSD
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | 0x0004);
}

fn stripNull(data: []const u8) []const u8 {
    if (data.len > 0 and data[data.len - 1] == 0) {
        return data[0 .. data.len - 1];
    }
    return data;
}

/// Spawn a pool of worker threads.
///
/// `shutdown_pipe_rd` is the read end of a pipe shared across all workers.
/// Writing to the write end wakes all workers from kevent() to begin drain.
pub fn spawnPool(
    allocator: Allocator,
    num_workers: u32,
    addresses: []const listener_mod.ListenAddress,
    callbacks: Callbacks,
    shutdown_pipe_rd: posix.fd_t,
) !std.ArrayList(std.Thread) {
    return spawnPoolWithReload(allocator, num_workers, addresses, callbacks, shutdown_pipe_rd, null, DEFAULT_MAX_CONNECTIONS);
}

/// Spawn a pool of worker threads with config reload support.
///
/// `config_gen` is a pointer to the global ConfigGeneration counter.
/// Workers poll it each event loop iteration and call callbacks.on_reload
/// when the generation advances.
/// `max_connections` is the per-worker connection limit for backpressure.
pub fn spawnPoolWithReload(
    allocator: Allocator,
    num_workers: u32,
    addresses: []const listener_mod.ListenAddress,
    callbacks: Callbacks,
    shutdown_pipe_rd: posix.fd_t,
    config_gen: ?*const reload_mod.ConfigGeneration,
    max_connections: u32,
) !std.ArrayList(std.Thread) {
    var threads: std.ArrayList(std.Thread) = .{};

    const count = if (num_workers == 0) @as(u32, @intCast(std.Thread.getCpuCount() catch 4)) else num_workers;

    for (0..count) |_| {
        const t = try std.Thread.spawn(.{}, workerEntryReload, .{ allocator, addresses, callbacks, shutdown_pipe_rd, config_gen, max_connections });
        try threads.append(allocator, t);
    }

    return threads;
}

fn workerEntryReload(allocator: Allocator, addresses: []const listener_mod.ListenAddress, callbacks: Callbacks, shutdown_pipe_rd: posix.fd_t, config_gen: ?*const reload_mod.ConfigGeneration, max_connections: u32) void {
    log_mod.initThread();
    defer log_mod.deinitThread();

    var worker = Worker.initWithReload(allocator, addresses, callbacks, shutdown_pipe_rd, config_gen, max_connections) catch |err| {
        log_mod.err("worker init failed: {}", .{err});
        return;
    };
    defer worker.deinit();
    worker.run();
}

test "worker init and deinit" {
    const pipe = try posix.pipe();
    defer posix.close(pipe[0]);
    defer posix.close(pipe[1]);
    var worker = try Worker.init(
        std.testing.allocator,
        &.{listener_mod.ListenAddress{ .tcp = .{ .host = "127.0.0.1", .port = 0 } }},
        .{},
        pipe[0],
    );
    defer worker.deinit();

    try std.testing.expect(worker.kq >= 0);
    try std.testing.expectEqual(@as(usize, 1), worker.listeners.items.len);
}
