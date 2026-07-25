const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const Allocator = mem.Allocator;
const codec = @import("milter/codec.zig");
const commands = @import("milter/commands.zig");

/// Milter conversation state — tracks where we are in the SMTP lifecycle.
pub const State = enum {
    new,
    negotiating,
    connected,
    helo,
    mail_from,
    rcpt_to,
    headers,
    end_of_headers,
    body,
    end_of_message,
    dns_pending,
    error_state,
    closed,
};

/// Stored macro values captured during the milter conversation.
///
/// Postfix sends macros at specific protocol stages. We capture
/// the values needed by authentication milters and expose them
/// for the product-specific callback logic.
pub const Macros = struct {
    client_addr: ?[]const u8 = null,
    client_name: ?[]const u8 = null,
    mail_from: ?[]const u8 = null,
    rcpt_to: ?[]const u8 = null,
    queue_id: ?[]const u8 = null,
    helo_name: ?[]const u8 = null,
    daemon_name: ?[]const u8 = null,
    auth_type: ?[]const u8 = null,

    /// Update macros from a parsed SMFIC_MACRO packet.
    pub fn update(self: *Macros, allocator: Allocator, macro_set: *const commands.MacroSet) !void {
        for (macro_set.macros.items) |entry| {
            try self.setByName(allocator, entry.name, entry.value);
        }
    }

    fn setByName(self: *Macros, allocator: Allocator, name: []const u8, value: []const u8) !void {
        const field = self.fieldFor(name) orelse return;
        if (field.*) |old| allocator.free(old);
        field.* = try allocator.dupe(u8, value);
    }

    fn fieldFor(self: *Macros, name: []const u8) ?*?[]const u8 {
        if (eql(name, "{client_addr}") or eql(name, "client_addr")) return &self.client_addr;
        if (eql(name, "{client_name}") or eql(name, "client_name")) return &self.client_name;
        if (eql(name, "{mail_addr}") or eql(name, "mail_addr")) return &self.mail_from;
        if (eql(name, "{rcpt_addr}") or eql(name, "rcpt_addr")) return &self.rcpt_to;
        if (eql(name, "i")) return &self.queue_id;
        if (eql(name, "{daemon_name}") or eql(name, "daemon_name")) return &self.daemon_name;
        if (eql(name, "{auth_type}") or eql(name, "auth_type")) return &self.auth_type;
        return null;
    }

    fn eql(a: []const u8, b: []const u8) bool {
        return mem.eql(u8, a, b);
    }

    pub fn deinit(self: *Macros, allocator: Allocator) void {
        inline for (std.meta.fields(Macros)) |f| {
            if (@field(self, f.name)) |val| {
                allocator.free(val);
            }
        }
        self.* = .{};
    }

    /// Reset per-message macros (keep connection-level ones).
    pub fn resetMessage(self: *Macros, allocator: Allocator) void {
        if (self.mail_from) |v| { allocator.free(v); self.mail_from = null; }
        if (self.rcpt_to) |v| { allocator.free(v); self.rcpt_to = null; }
        if (self.queue_id) |v| { allocator.free(v); self.queue_id = null; }
    }
};

/// Accumulated message headers for product-specific processing.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// A single milter connection's state and buffered data.
///
/// One Connection exists per accepted socket. It holds the protocol
/// reader, conversation state, accumulated macros and headers, and
/// a reference to the listener config it came from.
pub const Connection = struct {
    allocator: Allocator,
    fd: posix.fd_t,
    state: State,
    reader: codec.PacketReader,
    macros: Macros,
    headers: std.ArrayList(Header),
    helo_name: ?[]const u8,
    mail_from_raw: ?[]const u8,
    recipients: std.ArrayList([]const u8),
    listener_index: usize,

    pub fn init(allocator: Allocator, fd: posix.fd_t, listener_index: usize) Connection {
        return .{
            .allocator = allocator,
            .fd = fd,
            .state = .new,
            .reader = codec.PacketReader.init(allocator),
            .macros = .{},
            .headers = .{},
            .helo_name = null,
            .mail_from_raw = null,
            .recipients = .{},
            .listener_index = listener_index,
        };
    }

    pub fn deinit(self: *Connection) void {
        posix.close(self.fd);
        self.reader.deinit();
        self.macros.deinit(self.allocator);
        self.freeHeaders();
        self.headers.deinit(self.allocator);
        if (self.helo_name) |h| self.allocator.free(h);
        if (self.mail_from_raw) |m| self.allocator.free(m);
        self.freeRecipients();
        self.recipients.deinit(self.allocator);
    }

    /// Reset per-message state (called on ABORT or after EOM).
    pub fn resetMessage(self: *Connection) void {
        self.macros.resetMessage(self.allocator);
        self.freeHeaders();
        if (self.mail_from_raw) |m| { self.allocator.free(m); self.mail_from_raw = null; }
        self.freeRecipients();
        self.state = .connected;
    }

    /// Store a header from SMFIC_HEADER.
    pub fn addHeader(self: *Connection, name: []const u8, value: []const u8) !void {
        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);
        const value_dup = try self.allocator.dupe(u8, value);
        try self.headers.append(self.allocator, .{ .name = name_dup, .value = value_dup });
    }

    /// Store envelope sender from SMFIC_MAIL.
    pub fn setMailFrom(self: *Connection, sender: []const u8) !void {
        if (self.mail_from_raw) |old| self.allocator.free(old);
        self.mail_from_raw = try self.allocator.dupe(u8, sender);
    }

    /// Store a recipient from SMFIC_RCPT.
    pub fn addRecipient(self: *Connection, rcpt: []const u8) !void {
        const dup = try self.allocator.dupe(u8, rcpt);
        try self.recipients.append(self.allocator, dup);
    }

    /// Store HELO name from SMFIC_HELO.
    pub fn setHelo(self: *Connection, name: []const u8) !void {
        if (self.helo_name) |old| self.allocator.free(old);
        self.helo_name = try self.allocator.dupe(u8, name);
    }

    fn freeHeaders(self: *Connection) void {
        for (self.headers.items) |hdr| {
            self.allocator.free(hdr.name);
            self.allocator.free(hdr.value);
        }
        self.headers.clearRetainingCapacity();
    }

    fn freeRecipients(self: *Connection) void {
        for (self.recipients.items) |r| {
            self.allocator.free(r);
        }
        self.recipients.clearRetainingCapacity();
    }
};

test "connection lifecycle" {
    const allocator = std.testing.allocator;

    var pipe: [2]posix.fd_t = undefined;
    const result = std.c.pipe(&pipe);
    if (result != 0) return error.PipeFailed;
    defer posix.close(pipe[0]);

    var conn = Connection.init(allocator, pipe[1], 0);
    defer conn.deinit();

    try std.testing.expectEqual(State.new, conn.state);

    try conn.setHelo("mail.example.com");
    try std.testing.expectEqualStrings("mail.example.com", conn.helo_name.?);

    try conn.setMailFrom("sender@example.com");
    try std.testing.expectEqualStrings("sender@example.com", conn.mail_from_raw.?);

    try conn.addRecipient("rcpt1@example.com");
    try conn.addRecipient("rcpt2@example.com");
    try std.testing.expectEqual(@as(usize, 2), conn.recipients.items.len);

    try conn.addHeader("Subject", "Test");
    try conn.addHeader("From", "sender@example.com");
    try std.testing.expectEqual(@as(usize, 2), conn.headers.items.len);

    conn.resetMessage();
    try std.testing.expectEqual(@as(usize, 0), conn.headers.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.recipients.items.len);
    try std.testing.expect(conn.mail_from_raw == null);
    try std.testing.expectEqualStrings("mail.example.com", conn.helo_name.?);
}

test "macros update and reset" {
    const allocator = std.testing.allocator;
    var macros: Macros = .{};
    defer macros.deinit(allocator);

    var macro_list: commands.MacroSet.MacroList = .{};
    defer macro_list.deinit(allocator);
    try macro_list.append(allocator, .{ .name = "{client_addr}", .value = "192.0.2.1" });
    try macro_list.append(allocator, .{ .name = "i", .value = "ABC123" });

    const set = commands.MacroSet{ .cmd_code = 'C', .macros = macro_list };
    try macros.update(allocator, &set);

    try std.testing.expectEqualStrings("192.0.2.1", macros.client_addr.?);
    try std.testing.expectEqualStrings("ABC123", macros.queue_id.?);

    macros.resetMessage(allocator);
    try std.testing.expect(macros.queue_id == null);
    try std.testing.expectEqualStrings("192.0.2.1", macros.client_addr.?);
}
