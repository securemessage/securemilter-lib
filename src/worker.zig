const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;
const c = std.c;
const Kevent = posix.Kevent;

const listener_mod = @import("listener.zig");
const connection_mod = @import("connection.zig");
const escape = @import("escape.zig");
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

    /// Protocol flags to request in OPTNEG. Named `skip_flags` until D-23, when
    /// `header_leading_space` became the first that asks the MTA for *more* data
    /// rather than less, and the old name said the opposite of what it did.
    protocol_flags: negotiate.ProtocolFlags = .{},

    /// Caps applied to every connection this pool accepts. Carried here beside
    /// `required_actions` and `protocol_flags` — the worker behaviour a product
    /// milter chooses — so the daemons already building this struct need no new
    /// plumbing to set them.
    limits: connection_mod.Limits = .{},
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

/// Maximum staged changelist entries. Flushed on next kevent() call.
const MAX_PENDING: usize = 128;

/// Minimum gap between one worker's "refused connections" reports.
///
/// The refusal path is reachable by anyone who can open a socket to the milter
/// port, so a line per refused connection would let a caller choose how much
/// this daemon writes to syslog. Reporting is therefore collapsed: the first
/// refusal is logged at once, and subsequent ones are counted and summarised no
/// more often than this.
const REFUSED_LOG_INTERVAL_MS: i64 = 1000;

/// A single worker thread's state.
///
/// Each worker owns its own kqueue, its own set of SO_REUSEPORT
/// listener sockets, and its own connection pool. Workers share
/// nothing with each other — no locks, no contention.
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
    /// Connections refused for being at `max_connections` and not yet reported,
    /// with the time of the last report. See `reportRefusedConnections`.
    refused_pending: u64,
    refused_log_at: ?i64,
    /// Index of this worker's quiescent-state slot in `config_gen`.
    worker_index: usize,
    /// Read end of this worker's wakeup pipe, or -1. A byte here means only
    /// "wake up": it exists so a reload can pull an otherwise idle worker to
    /// the top of its loop, where it announces quiescence.
    wakeup_fd: posix.fd_t,

    pub fn init(allocator: Allocator, addresses: []const listener_mod.ListenAddress, callbacks: Callbacks, shutdown_pipe: posix.fd_t) !Worker {
        return initWithReload(allocator, addresses, callbacks, shutdown_pipe, null, DEFAULT_MAX_CONNECTIONS, 0, -1);
    }

    /// On failure nothing is retained: the kqueue descriptor and any listeners
    /// already bound are released before the error propagates. That matters now
    /// that the error is reportable -- while this ran inside a spawned thread the
    /// only response was to log and return, so the descriptors were simply
    /// abandoned and the leak was unobservable (X-15).
    pub fn initWithReload(allocator: Allocator, addresses: []const listener_mod.ListenAddress, callbacks: Callbacks, shutdown_pipe: posix.fd_t, config_gen: ?*const reload_mod.ConfigGeneration, max_conn: u32, worker_index: usize, wakeup_fd: posix.fd_t) !Worker {
        const kq = try posix.kqueue();
        errdefer posix.close(kq);

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
            .refused_pending = 0,
            .refused_log_at = null,
            .worker_index = worker_index,
            .wakeup_fd = wakeup_fd,
        };

        errdefer self.connections.deinit();
        errdefer {
            for (self.listeners.items) |*lst| lst.close();
            self.listeners.deinit(allocator);
        }

        // Stage initial registrations — flushed on first kevent() call
        self.stageRead(shutdown_pipe);
        if (wakeup_fd >= 0) self.stageRead(wakeup_fd);

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

        if (self.wakeup_fd >= 0) posix.close(self.wakeup_fd);
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

            // Top of the loop is the quiescent point: every reference this
            // worker took to shared configuration while handling the previous
            // batch of events has been dropped, and it has not yet acquired
            // one for the next. Announcing it here — and only here — is what
            // lets the main thread free retired configuration without racing
            // us (audit X-2; see reload.zig and rcu.zig).
            //
            // This must stay above the kevent() call. Announcing after the
            // wait would leave the slot stale for as long as the worker sits
            // idle, which delays reclamation; announcing mid-batch would be
            // worse than useless, since it would licence freeing memory a
            // half-finished message is still reading.
            if (self.config_gen) |cg| {
                cg.quiesce(self.worker_index);

                // Then the reload notification: compare local generation to
                // global and, if stale, let the product drop thread-local
                // caches (e.g. its DNS resolver).
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
                } else if (self.wakeup_fd >= 0 and fd == self.wakeup_fd) {
                    // Waking was the whole point; the quiescent announcement
                    // happens at the top of the next iteration. Just drain the
                    // byte so the pipe does not stay readable.
                    var sink: [64]u8 = undefined;
                    while (posix.read(self.wakeup_fd, &sink)) |got| {
                        if (got < sink.len) break;
                    } else |_| {}
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

    /// Count a connection closed for arriving while this worker was full.
    ///
    /// Counted here and reported by `reportRefusedConnections` once the accept
    /// batch is drained, so that one burst produces one line naming how many it
    /// refused. Reporting from inside the loop instead described a burst of four
    /// as "refused 1", because the first refusal logged immediately and the rest
    /// arrived inside the suppression window and were never flushed.
    fn noteRefusedConnection(self: *Worker) void {
        self.refused_pending += 1;
    }

    /// Report connections closed for arriving while this worker was full.
    ///
    /// The refusal itself is correct and is what L-2 asked for, but it used to be
    /// SILENT: the fd was closed and the loop moved on. From the MTA's side that
    /// is a milter that accepted a TCP connection and hung up without speaking,
    /// which with `milter_default_action = tempfail` defers the mail. So an
    /// operator who set `MaxConnections` too low, or who was simply pushed past
    /// it, saw deferrals in the Postfix log and NOTHING here to attribute them
    /// to -- while this daemon was working exactly as configured.
    ///
    /// Called once per accept batch rather than per connection. `handleAccept`
    /// drains until EWOULDBLOCK, so a flood of connections costs a handful of
    /// lines rather than one per connection; the time floor then bounds a caller
    /// who trickles connections slowly enough to earn a batch each. Refusals
    /// arriving inside that floor stay pending and are added to the next report,
    /// so a count may lag by up to `REFUSED_LOG_INTERVAL_MS` but is never lost
    /// except at the very end of an episode.
    ///
    /// The cap is named as the setting an operator would change, and
    /// `max_connections` is PER WORKER, so the worker index is included: the
    /// process-wide ceiling is this number times the worker count, and a reader
    /// who assumed otherwise would go looking for a limit several times lower
    /// than the one they actually hit.
    fn reportRefusedConnections(self: *Worker) void {
        if (self.refused_pending == 0) return;

        const now = std.time.milliTimestamp();
        if (self.refused_log_at) |last| {
            if (now - last < REFUSED_LOG_INTERVAL_MS) return;
        }

        log_mod.warn("refused {d} connection(s): worker {d} is at MaxConnections={d}", .{
            self.refused_pending,
            self.worker_index,
            self.max_connections,
        });
        self.refused_log_at = now;
        self.refused_pending = 0;
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
                self.noteRefusedConnection();
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
            conn.* = connection_mod.Connection.init(self.allocator, conn_fd, listener_index, self.callbacks.limits);
            conn.setPeerAddr(conn_result.address);

            self.connections.put(conn_fd, conn) catch {
                conn.deinit();
                self.allocator.destroy(conn);
                continue;
            };

            self.stageRead(conn_fd);
        }

        self.reportRefusedConnections();
    }

    /// Whether the connection is still in the map after a dispatch.
    ///
    /// A handler can close the connection -- `sendResponse` removes it on a write
    /// failure -- so `conn` may be freed memory the moment `dispatchPacket` returns.
    /// This check appeared five times in `handleConnectionData` with no name on it.
    fn alive(self: *Worker, fd: posix.fd_t) bool {
        return self.connections.get(fd) != null;
    }

    /// Dispatch every packet already sitting in the reader's buffer.
    ///
    /// Postfix pipelines commands, so one read can carry several packets. `tryDecode`
    /// is deliberately used rather than `feed`: this pass must not issue another
    /// `read(2)`, only drain what the last one already delivered.
    ///
    /// Returns false if the connection went away, in which case `fd` is closed and
    /// `conn` is freed.
    fn drainBuffered(self: *Worker, conn: *connection_mod.Connection, fd: posix.fd_t) bool {
        while (self.alive(fd)) {
            switch (conn.reader.tryDecode()) {
                .packet => |pkt| {
                    self.dispatchPacket(conn, pkt);
                    if (!self.alive(fd)) return false;
                    conn.reader.consume();
                },
                // Both mean "nothing more decodable without another read".
                .incomplete, .would_block => return true,
                .closed, .err => {
                    self.removeConnection(fd);
                    return false;
                },
            }
        }
        return false;
    }

    fn handleConnectionData(self: *Worker, fd: posix.fd_t) void {
        const conn = self.connections.get(fd) orelse return;

        // Drain the socket and every buffered packet.
        //
        // X-6: a partial packet (.incomplete) means the rest may already sit in the
        // kernel buffer, so keep feeding. `feed` reports .would_block only once the
        // socket is actually drained, and yielding to the event loop on a partial
        // packet would wait for a kqueue edge that never arrives once the peer's send
        // window fills. Covered by the test at the foot of this file, which sends one
        // packet larger than the 8192-byte read chunk and calls this once.
        while (self.alive(fd)) {
            switch (conn.reader.feed(fd)) {
                .packet => |pkt| {
                    self.dispatchPacket(conn, pkt);
                    if (!self.alive(fd)) return;
                    conn.reader.consume();
                    if (!self.drainBuffered(conn, fd)) return;
                },
                // The rest of this packet may already be buffered; read again.
                .incomplete => continue,
                // Socket drained: this is the only path that returns to the loop.
                .would_block => return,
                .closed, .err => {
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
        conn.negotiated_actions = negotiate.grantedActions(self.callbacks.required_actions, offer);
        // What the MTA agreed to, by the same mask `buildResponse` applies: a
        // milter that assumed it got what it asked for would misparse every header
        // against an MTA that declined `header_leading_space`.
        conn.negotiated_protocol = @bitCast(
            @as(u32, @bitCast(offer.protocol)) & @as(u32, @bitCast(self.callbacks.protocol_flags)),
        );
        const resp = negotiate.buildResponse(self.callbacks.required_actions, self.callbacks.protocol_flags, offer);
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
        // Persist before dispatching, exactly as handleHelo and handleMailFrom
        // do with their values. This was previously handed to the callback and
        // dropped, and since no daemon registers on_connect it was dropped every
        // time -- leaving the client address readable only from the optional
        // {client_addr} macro, which a default Postfix does not send.
        conn.setConnectInfo(info) catch {};
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
        // Report the first rejection only: a flood would otherwise turn one
        // abusive message into thousands of log lines, which is its own denial
        // of service. `addHeader` latches the flag, so end-of-message still
        // knows the list is incomplete however many headers followed.
        const first_overflow = !conn.headers_overflow;
        // With SMFIP_HDR_LEADSPC the value still carries the whitespace after the
        // colon; recover the bit and hand consumers the value they always saw.
        // See `Header.had_space` for why (audit D-23).
        const split = if (conn.negotiated_protocol.header_leading_space)
            connection_mod.splitLeadingSpace(hdr.value)
        else
            connection_mod.HeaderSplit{ .value = hdr.value, .had_space = true };
        conn.addHeaderSpaced(hdr.name, split.value, split.had_space) catch |e| {
            if (first_overflow and conn.headers_overflow) {
                const peer = conn.getPeerDisplay();
                log_mod.warn(
                    "header limit reached ({d} headers, {d} bytes) from {f}[{f}]: message will not be authenticated",
                    .{
                        conn.headers.items.len,
                        conn.header_bytes,
                        escape.logField(peer.name),
                        escape.logField(peer.ip),
                    },
                );
            } else if (e != error.TooManyHeaders) {
                // Allocation failure rather than a cap. The list is short by at
                // least one header, so the same rule applies.
                conn.headers_overflow = true;
                log_mod.err("header accumulation failed: {}", .{e});
            }
        };
        conn.state = .headers;
        // `split.value`, not `hdr.value`: a callback must see what was stored, or
        // the two disagree about the same header once the flag is in force.
        const resp = if (self.callbacks.on_header) |cb| cb(conn, hdr.name, split.value) else @intFromEnum(responses.Code.@"continue");
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

        // A header block we did not see in full must not be delivered.
        //
        // Enforced here rather than left to each product callback because
        // getting it wrong is silent. Every daemon in this suite strips
        // Authentication-Results headers that forge its own authserv-id (audit
        // X-1), and it can only strip headers it accumulated: with the cap in
        // place, a sender who pads past `max_headers` and then appends a forged
        // `spf=pass` would have it pass through uninspected. Tempfail is the only
        // response that cannot leak it — the MTA holds the message and the
        // sender may retry within the limits.
        //
        // Body overflow is deliberately not treated this way. There the header
        // block was seen in full and scrubbed; only the hash is unavailable, so
        // the callback can still return a truthful temperror result and the
        // message can be delivered.
        if (conn.headers_overflow) {
            const peer = conn.getPeerDisplay();
            // The peer name comes from rDNS the sender may control, so it is
            // rendered as a single bare token (audit X-5).
            log_mod.warn(
                "tempfail: header block from {f}[{f}] exceeded MaxHeaders={d}/MaxHeaderBytes={d} and could not be inspected in full",
                .{
                    escape.logField(peer.name),
                    escape.logField(peer.ip),
                    conn.limits.max_headers,
                    conn.limits.max_header_bytes,
                },
            );
            self.sendResponse(conn, @intFromEnum(responses.Code.tempfail));
            conn.resetMessage();
            return;
        }

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

/// Records what `on_body` was handed, so a test can assert the whole payload arrived.
var test_body_len: usize = 0;

fn recordBodyLen(conn: *connection_mod.Connection, data: []const u8) u8 {
    _ = conn;
    test_body_len = data.len;
    return @intFromEnum(responses.Code.@"continue");
}

test "X-6: a packet larger than the read chunk is assembled without yielding to the event loop" {
    // THE PROPERTY: `feed` reads at most 8192 bytes per call, so a larger packet
    // necessarily returns `.incomplete` several times before it completes.
    // `handleConnectionData` must keep feeding on `.incomplete` rather than returning
    // to the event loop, because the rest of the packet may already be in the kernel
    // buffer -- in which case no new data arrives, no new kqueue edge fires, and the
    // connection hangs. That was X-6.
    //
    // Until now this was documented only in a comment inside the function. The
    // refactor plan lists this function as the riskiest in the codebase, so the test
    // is written FIRST, against the unmodified implementation.
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(
        @intCast(posix.AF.UNIX),
        @intCast(posix.SOCK.STREAM),
        0,
        &fds,
    );
    try std.testing.expectEqual(@as(c_int, 0), rc);
    const worker_end = fds[0];
    const peer_end = fds[1];
    defer posix.close(peer_end);

    // FreeBSD's default net.local.stream.sendspace is 8192, which is smaller than the
    // packet under test, so an unbuffered write would block with nothing reading yet.
    const bufsize: c_int = 262144;
    _ = std.c.setsockopt(peer_end, posix.SOL.SOCKET, posix.SO.SNDBUF, &bufsize, @sizeOf(c_int));
    _ = std.c.setsockopt(worker_end, posix.SOL.SOCKET, posix.SO.RCVBUF, &bufsize, @sizeOf(c_int));

    try setNonBlocking(worker_end);

    const pipe = try posix.pipe();
    defer posix.close(pipe[0]);
    defer posix.close(pipe[1]);

    test_body_len = 0;
    var worker = try Worker.init(
        std.testing.allocator,
        &.{listener_mod.ListenAddress{ .tcp = .{ .host = "127.0.0.1", .port = 0 } }},
        .{ .on_body = recordBodyLen },
        pipe[0],
    );
    // Closes `worker_end` and frees the connection below.
    defer worker.deinit();

    const conn = try std.testing.allocator.create(connection_mod.Connection);
    conn.* = connection_mod.Connection.init(std.testing.allocator, worker_end, 0, .{});
    try worker.connections.put(worker_end, conn);

    // One SMFIC_BODY packet, deliberately more than three read chunks.
    const payload_len: usize = 8192 * 3 + 17;
    const packet = try std.testing.allocator.alloc(u8, 4 + 1 + payload_len);
    defer std.testing.allocator.free(packet);
    std.mem.writeInt(u32, packet[0..4], @intCast(1 + payload_len), .big);
    packet[4] = @intFromEnum(commands.Code.body);
    @memset(packet[5..], 'x');

    var written: usize = 0;
    while (written < packet.len) {
        written += try posix.write(peer_end, packet[written..]);
    }

    // Exactly one call, as one kqueue readability edge would produce.
    worker.handleConnectionData(worker_end);

    try std.testing.expectEqual(payload_len, test_body_len);
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
