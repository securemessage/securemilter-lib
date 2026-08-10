const std = @import("std");

/// Milter protocol version for OPTNEG.
pub const MILTER_VERSION: u32 = 6;

/// Action flags — what the milter may do to messages.
///
/// The milter declares these in its OPTNEG response. Any action
/// the milter might perform MUST be declared here or the MTA will
/// reject the milter.
pub const ActionFlags = packed struct(u32) {
    add_headers: bool = false,
    change_body: bool = false,
    add_rcpt: bool = false,
    del_rcpt: bool = false,
    change_headers: bool = false,
    quarantine: bool = false,
    change_from: bool = false,
    add_rcpt_par: bool = false,
    set_symlist: bool = false,
    _padding: u23 = 0,
};

/// Protocol flags controlling MTA event delivery.
///
/// Most flags suppress an event; `header_leading_space` requests the separator
/// after a header colon.
pub const ProtocolFlags = packed struct(u32) {
    no_connect: bool = false,
    no_helo: bool = false,
    no_mail: bool = false,
    no_rcpt: bool = false,
    no_body: bool = false,
    no_headers: bool = false,
    no_eoh: bool = false,
    no_reply_headers: bool = false,
    no_unknown: bool = false,
    no_data: bool = false,
    skip: bool = false,
    rejected_rcpt: bool = false,
    no_reply_connect: bool = false,
    no_reply_helo: bool = false,
    no_reply_mail: bool = false,
    no_reply_rcpt: bool = false,
    no_reply_data: bool = false,
    no_reply_unknown: bool = false,
    no_reply_eoh: bool = false,
    no_reply_body: bool = false,
    header_leading_space: bool = false,
    _padding: u11 = 0,
};

/// SMFIC_OPTNEG payload sent by the MTA.
pub const MtaOffer = struct {
    version: u32,
    actions: ActionFlags,
    protocol: ProtocolFlags,
};

/// Resolve which actions the milter may actually perform: the intersection of
/// what it asked for and what the MTA offered. Sending a modification packet
/// for an action outside this set is a protocol violation.
pub fn grantedActions(requested: ActionFlags, mta_offer: MtaOffer) ActionFlags {
    const offered: u32 = @bitCast(mta_offer.actions);
    const wanted: u32 = @bitCast(requested);
    return @bitCast(offered & wanted);
}

/// Build an OPTNEG response payload for the milter.
///
/// The milter MUST only set flags that the MTA offered.
/// This function masks the requested flags against the MTA's offer.
pub fn buildResponse(
    requested_actions: ActionFlags,
    requested_protocol: ProtocolFlags,
    mta_offer: MtaOffer,
) [13]u8 {
    var buf: [13]u8 = undefined;

    buf[0] = 'O';

    std.mem.writeInt(u32, buf[1..5], MILTER_VERSION, .big);

    const granted: u32 = @bitCast(grantedActions(requested_actions, mta_offer));
    std.mem.writeInt(u32, buf[5..9], granted, .big);

    const offered_protocol: u32 = @bitCast(mta_offer.protocol);
    const wanted_protocol: u32 = @bitCast(requested_protocol);
    std.mem.writeInt(u32, buf[9..13], offered_protocol & wanted_protocol, .big);

    return buf;
}

/// Parse an SMFIC_OPTNEG payload from the MTA.
///
/// Payload format (after cmd byte): version(u32) actions(u32) protocol(u32)
pub fn parseOffer(data: []const u8) !MtaOffer {
    if (data.len < 12) return error.MalformedPacket;

    return .{
        .version = std.mem.readInt(u32, data[0..4], .big),
        .actions = @bitCast(std.mem.readInt(u32, data[4..8], .big)),
        .protocol = @bitCast(std.mem.readInt(u32, data[8..12], .big)),
    };
}

test "build optneg response masks against offer" {
    const offer = MtaOffer{
        .version = 6,
        .actions = .{ .add_headers = true, .change_headers = true },
        .protocol = .{ .no_body = true, .no_connect = true },
    };

    const requested_actions = ActionFlags{ .add_headers = true, .add_rcpt = true };
    const requested_protocol = ProtocolFlags{ .no_body = true, .no_data = true };

    const resp = buildResponse(requested_actions, requested_protocol, offer);

    try std.testing.expectEqual(@as(u8, 'O'), resp[0]);

    const ver = std.mem.readInt(u32, resp[1..5], .big);
    try std.testing.expectEqual(MILTER_VERSION, ver);

    const actions: ActionFlags = @bitCast(std.mem.readInt(u32, resp[5..9], .big));
    try std.testing.expect(actions.add_headers);
    try std.testing.expect(!actions.add_rcpt);

    const protocol: ProtocolFlags = @bitCast(std.mem.readInt(u32, resp[9..13], .big));
    try std.testing.expect(protocol.no_body);
    try std.testing.expect(!protocol.no_data);
}

test "parse offer" {
    var data: [12]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 6, .big);
    std.mem.writeInt(u32, data[4..8], 0x1F, .big);
    std.mem.writeInt(u32, data[8..12], 0x7F, .big);

    const offer = try parseOffer(&data);
    try std.testing.expectEqual(@as(u32, 6), offer.version);
}
