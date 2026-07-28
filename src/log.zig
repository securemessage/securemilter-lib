const std = @import("std");
const posix = std.posix;
const c = std.c;
const mem = std.mem;
const escape = @import("escape.zig");

/// Syslog severity levels (RFC 5424 §6.2.1).
pub const Level = enum(u3) {
    err = 3,
    warn = 4,
    info = 6,
    debug = 7,

    pub fn fromString(s: []const u8) Level {
        if (std.ascii.eqlIgnoreCase(s, "err") or std.ascii.eqlIgnoreCase(s, "error")) return .err;
        if (std.ascii.eqlIgnoreCase(s, "warn") or std.ascii.eqlIgnoreCase(s, "warning")) return .warn;
        if (std.ascii.eqlIgnoreCase(s, "debug")) return .debug;
        return .info;
    }
};

/// Syslog facility codes (RFC 5424 §6.2.1).
pub const Facility = enum(u5) {
    kern = 0,
    user = 1,
    mail = 2,
    daemon = 3,
    auth = 4,
    syslog = 5,
    lpr = 6,
    news = 7,
    local0 = 16,
    local1 = 17,
    local2 = 18,
    local3 = 19,
    local4 = 20,
    local5 = 21,
    local6 = 22,
    local7 = 23,

    pub fn fromString(s: []const u8) Facility {
        if (std.ascii.eqlIgnoreCase(s, "mail")) return .mail;
        if (std.ascii.eqlIgnoreCase(s, "daemon")) return .daemon;
        if (std.ascii.eqlIgnoreCase(s, "auth")) return .auth;
        if (std.ascii.eqlIgnoreCase(s, "local0")) return .local0;
        if (std.ascii.eqlIgnoreCase(s, "local1")) return .local1;
        if (std.ascii.eqlIgnoreCase(s, "local2")) return .local2;
        if (std.ascii.eqlIgnoreCase(s, "local3")) return .local3;
        if (std.ascii.eqlIgnoreCase(s, "local4")) return .local4;
        if (std.ascii.eqlIgnoreCase(s, "local5")) return .local5;
        if (std.ascii.eqlIgnoreCase(s, "local6")) return .local6;
        if (std.ascii.eqlIgnoreCase(s, "local7")) return .local7;
        return .mail;
    }
};

/// Logger configuration, shared immutable after init.
pub const LogConfig = struct {
    use_syslog: bool = true,
    facility: Facility = .mail,
    level: Level = .info,
    ident: [64]u8 = undefined,
    ident_len: u8 = 0,

    pub fn init(use_syslog: bool, facility: Facility, level: Level, ident: []const u8) LogConfig {
        var cfg = LogConfig{
            .use_syslog = use_syslog,
            .facility = facility,
            .level = level,
        };
        const len: u8 = @intCast(@min(ident.len, 64));
        @memcpy(cfg.ident[0..len], ident[0..len]);
        cfg.ident_len = len;
        return cfg;
    }

    /// Parse config from a Config.Section (the [global] section).
    pub fn fromSection(section: anytype, program_name: []const u8) LogConfig {
        const use_syslog = section.getBool("Syslog", true);
        const facility_str = section.getOrDefault("SyslogFacility", "mail");
        const level_str = section.getOrDefault("LogLevel", "info");
        return LogConfig.init(
            use_syslog,
            Facility.fromString(facility_str),
            Level.fromString(level_str),
            program_name,
        );
    }
};

/// Per-thread logger instance.
///
/// Each worker thread owns one of these. It holds its own SOCK_DGRAM fd
/// connected to /var/run/log (FreeBSD syslog socket). Non-blocking sendto()
/// means a full syslog socket buffer silently drops the message rather than
/// blocking the event loop.
///
/// In foreground mode (use_syslog=false), writes to STDERR_FILENO instead.
pub const Logger = struct {
    fd: posix.fd_t,
    config: *const LogConfig,
    pid: c.pid_t,

    /// Sentinel value for "no socket" (foreground/stderr mode).
    const NO_FD: posix.fd_t = -1;

    /// FreeBSD syslog socket path.
    const SYSLOG_PATH = "/var/run/log";

    /// Initialize a logger. Opens a non-blocking SOCK_DGRAM to /var/run/log.
    /// If syslog is disabled (foreground mode), fd is set to NO_FD.
    pub fn init(cfg: *const LogConfig) Logger {
        var self = Logger{
            .fd = NO_FD,
            .config = cfg,
            .pid = c.getpid(),
        };

        if (cfg.use_syslog) {
            self.fd = openSyslogSocket() catch NO_FD;
        }

        return self;
    }

    /// Close the syslog socket.
    pub fn deinit(self: *Logger) void {
        if (self.fd != NO_FD) {
            posix.close(self.fd);
            self.fd = NO_FD;
        }
    }

    /// Log at error level.
    pub fn err(self: *const Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args);
    }

    /// Log at warning level.
    pub fn warn(self: *const Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, fmt, args);
    }

    /// Log at info level.
    pub fn info(self: *const Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args);
    }

    /// Log at debug level.
    pub fn debug(self: *const Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args);
    }

    /// Core log function. Level check is a single integer compare.
    fn log(self: *const Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) > @intFromEnum(self.config.level)) return;

        var buf: [1024]u8 = undefined;
        const msg = self.format(&buf, level, fmt, args);

        // Backstop for audit X-5: one log line per log call, unconditionally.
        //
        // Attacker-derived values are supposed to reach this function already
        // rendered through `escape.logField`, which keeps each one to a single
        // bare token. That has to be applied per value at every call site, and a
        // site added later -- or one missed today -- would silently reopen log
        // forgery, where an embedded newline writes a second, plausible line
        // attributing an action to another host.
        //
        // Scrubbing the assembled message here makes that impossible regardless
        // of the call site. It cannot replace `logField`: by this point the
        // spaces separating fields are indistinguishable from a space inside a
        // value, so this deliberately leaves spaces alone and only guarantees
        // that the line is one line.
        escape.scrubControlBytes(buf[0..msg.len]);

        if (self.config.use_syslog) {
            self.sendSyslog(msg);
        } else {
            self.writeStderr(msg);
        }
    }

    /// Format a syslog message into the stack buffer.
    ///
    /// BSD syslog format: <PRI>IDENT[PID]: MESSAGE
    /// PRI = facility * 8 + severity
    fn format(self: *const Logger, buf: []u8, level: Level, comptime fmt: []const u8, args: anytype) []const u8 {
        const pri: u8 = @as(u8, @intFromEnum(self.config.facility)) * 8 + @intFromEnum(level);
        const ident = self.config.ident[0..self.config.ident_len];

        // Write PRI + ident + PID prefix
        var pos: usize = 0;
        const prefix = std.fmt.bufPrint(buf[pos..], "<{d}>{s}[{d}]: ", .{ pri, ident, self.pid }) catch return buf[0..0];
        pos += prefix.len;

        // Write the actual message
        const msg = std.fmt.bufPrint(buf[pos..], fmt, args) catch blk: {
            // If message is too long, truncate
            break :blk buf[pos..];
        };
        pos += msg.len;

        return buf[0..pos];
    }

    /// Send to syslog socket. Non-blocking, silently drops on EAGAIN.
    fn sendSyslog(self: *const Logger, msg: []const u8) void {
        if (self.fd == NO_FD) return;
        if (msg.len == 0) return;

        // sendto with null addr (connected socket) — fire and forget
        _ = posix.write(self.fd, msg) catch {};
    }

    /// Write to stderr (foreground mode). Appends newline.
    fn writeStderr(self: *const Logger, msg: []const u8) void {
        _ = self;
        if (msg.len == 0) return;
        // Skip the <PRI> prefix for stderr — find the '>' after PRI
        var start: usize = 0;
        if (msg.len > 0 and msg[0] == '<') {
            if (mem.indexOfScalar(u8, msg, '>')) |end| {
                start = end + 1;
            }
        }
        _ = posix.write(posix.STDERR_FILENO, msg[start..]) catch {};
        _ = posix.write(posix.STDERR_FILENO, "\n") catch {};
    }

    /// Open a non-blocking SOCK_DGRAM connected to /var/run/log.
    fn openSyslogSocket() !posix.fd_t {
        const sock_fd = try posix.socket(posix.AF.UNIX, posix.SOCK.DGRAM, 0);
        errdefer posix.close(sock_fd);

        // Set non-blocking (O_NONBLOCK = 0x0004 on FreeBSD)
        const flags = try posix.fcntl(sock_fd, posix.F.GETFL, 0);
        _ = try posix.fcntl(sock_fd, posix.F.SETFL, flags | 0x0004);

        // Connect to /var/run/log via net.Address (handles sockaddr_un portably)
        const addr = try std.net.Address.initUnix(SYSLOG_PATH);
        posix.connect(sock_fd, &addr.any, addr.getOsSockLen()) catch |e| {
            posix.close(sock_fd);
            return e;
        };

        return sock_fd;
    }
};

/// Thread-local logger instance. Each worker thread initializes this once.
pub threadlocal var logger: Logger = Logger{
    .fd = Logger.NO_FD,
    .config = &default_config,
    .pid = 0,
};

/// Default config (stderr, info level) for use before explicit init.
var default_config: LogConfig = LogConfig.init(false, .mail, .info, "securemilter");

/// Global shared config pointer. Set once by initGlobal(), read by all threads.
var global_config: *const LogConfig = &default_config;

/// Initialize the global logging configuration.
///
/// Call once from main() after parsing config, before spawning workers.
/// The config must outlive all logger instances (typically static or arena-allocated).
pub fn initGlobal(cfg: *const LogConfig) void {
    global_config = cfg;
}

/// Initialize the thread-local logger for the current thread.
///
/// Call once at the start of each worker thread entry function.
/// Uses the global config set by initGlobal().
pub fn initThread() void {
    logger = Logger.init(global_config);
}

/// Deinitialize the thread-local logger (close socket).
pub fn deinitThread() void {
    logger.deinit();
}

// Convenience free functions that use the thread-local logger.

pub fn err(comptime fmt: []const u8, args: anytype) void {
    logger.err(fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    logger.warn(fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    logger.info(fmt, args);
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    logger.debug(fmt, args);
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

test "Level.fromString" {
    try std.testing.expectEqual(Level.err, Level.fromString("err"));
    try std.testing.expectEqual(Level.err, Level.fromString("error"));
    try std.testing.expectEqual(Level.warn, Level.fromString("warn"));
    try std.testing.expectEqual(Level.warn, Level.fromString("warning"));
    try std.testing.expectEqual(Level.info, Level.fromString("info"));
    try std.testing.expectEqual(Level.debug, Level.fromString("debug"));
    try std.testing.expectEqual(Level.info, Level.fromString("unknown"));
}

test "Facility.fromString" {
    try std.testing.expectEqual(Facility.mail, Facility.fromString("mail"));
    try std.testing.expectEqual(Facility.daemon, Facility.fromString("daemon"));
    try std.testing.expectEqual(Facility.local0, Facility.fromString("local0"));
    try std.testing.expectEqual(Facility.local7, Facility.fromString("local7"));
    try std.testing.expectEqual(Facility.mail, Facility.fromString("unknown"));
}

test "LogConfig.init" {
    const cfg = LogConfig.init(true, .mail, .info, "securespf");
    try std.testing.expect(cfg.use_syslog);
    try std.testing.expectEqual(Facility.mail, cfg.facility);
    try std.testing.expectEqual(Level.info, cfg.level);
    try std.testing.expectEqualStrings("securespf", cfg.ident[0..cfg.ident_len]);
}

test "Logger format output" {
    var cfg = LogConfig.init(false, .mail, .debug, "test");
    var log_inst = Logger{
        .fd = Logger.NO_FD,
        .config = &cfg,
        .pid = 12345,
    };

    var buf: [1024]u8 = undefined;
    const msg = log_inst.format(&buf, .info, "hello {s} {d}", .{ "world", 42 });

    // PRI for mail(2) + info(6) = 2*8+6 = 22
    try std.testing.expect(mem.startsWith(u8, msg, "<22>test[12345]: hello world 42"));
}

// X-5: a call site that forgets `escape.logField` still cannot forge a log line.
test "the assembled message can never contain a line break" {
    var cfg = LogConfig.init(false, .mail, .debug, "test");
    var log_inst = Logger{
        .fd = Logger.NO_FD,
        .config = &cfg,
        .pid = 1,
    };

    // Deliberately interpolated raw, the way a missed call site would.
    const hostile = "victim.example\nJul 28 18:00:00 host securespf[1]: from=attacker.example result=pass";

    var buf: [1024]u8 = undefined;
    const msg = log_inst.format(&buf, .info, "from={s}", .{hostile});
    escape.scrubControlBytes(buf[0..msg.len]);

    try std.testing.expect(mem.indexOfScalar(u8, msg, '\n') == null);
    try std.testing.expect(mem.indexOfScalar(u8, msg, '\r') == null);

    // Still one syslog line, so the forged second line is inert text within it.
    try std.testing.expectEqual(@as(usize, 1), mem.count(u8, msg, "<22>test[1]:"));
}

test "Logger level check skips disabled levels" {
    var cfg = LogConfig.init(false, .mail, .info, "test");
    var log_inst = Logger{
        .fd = Logger.NO_FD,
        .config = &cfg,
        .pid = 1,
    };

    // debug > info, so this should be a no-op (no crash, no output)
    log_inst.debug("this should not appear", .{});
    log_inst.info("this should appear", .{});
    log_inst.err("this should also appear", .{});
}

test "PRI encoding" {
    // mail(2) * 8 + err(3) = 19
    const pri_mail_err: u8 = @as(u8, @intFromEnum(Facility.mail)) * 8 + @intFromEnum(Level.err);
    try std.testing.expectEqual(@as(u8, 19), pri_mail_err);

    // local0(16) * 8 + debug(7) = 135
    const pri_local0_debug: u8 = @as(u8, @intFromEnum(Facility.local0)) * 8 + @intFromEnum(Level.debug);
    try std.testing.expectEqual(@as(u8, 135), pri_local0_debug);

    // daemon(3) * 8 + warn(4) = 28
    const pri_daemon_warn: u8 = @as(u8, @intFromEnum(Facility.daemon)) * 8 + @intFromEnum(Level.warn);
    try std.testing.expectEqual(@as(u8, 28), pri_daemon_warn);
}
