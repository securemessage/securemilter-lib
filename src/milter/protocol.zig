//! Sendmail milter protocol codec, commands, responses, and negotiation.

pub const commands = @import("commands.zig");
pub const responses = @import("responses.zig");
pub const negotiate = @import("negotiate.zig");
pub const codec = @import("codec.zig");

test {
    _ = commands;
    _ = responses;
    _ = negotiate;
    _ = codec;
}
