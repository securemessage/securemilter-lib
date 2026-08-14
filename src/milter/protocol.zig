//! Sendmail milter protocol codec, commands, responses, and negotiation.

pub const commands = @import("commands.zig");
pub const responses = @import("responses.zig");
pub const negotiate = @import("negotiate.zig");
pub const codec = @import("codec.zig");
/// The write half: every reply is queued per connection and flushed by the
/// worker, so a full send buffer costs a retry rather than the connection.
pub const outbuf = @import("outbuf.zig");

test {
    _ = commands;
    _ = responses;
    _ = negotiate;
    _ = codec;
    _ = outbuf;
}
