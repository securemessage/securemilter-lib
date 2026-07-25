pub const config = @import("config.zig");
pub const milter = @import("milter/protocol.zig");

test {
    _ = config;
    _ = milter;
}
