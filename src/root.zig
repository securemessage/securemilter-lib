pub const cli = @import("cli.zig");
pub const config = @import("config.zig");
pub const milter = @import("milter/protocol.zig");
pub const listener = @import("listener.zig");
pub const connection = @import("connection.zig");
pub const header = @import("header.zig");
/// The one definition of how a message *file* becomes the view of a message a
/// milter receives. Public because every conformance checker in the suite has to
/// model it identically to the daemon, and three private copies is how they came
/// to disagree (refactor plan stage 5.2).
pub const msgfile = @import("msgfile.zig");
pub const daemon = @import("daemon.zig");
pub const credentials = @import("credentials.zig");
pub const bootstrap = @import("bootstrap.zig");
pub const worker = @import("worker.zig");
pub const pool = @import("pool.zig");
pub const dns = @import("dns.zig");
pub const auth_results = @import("auth_results.zig");
/// RFC 5322 comment and folding-whitespace scanners. Public because every
/// consumer of a structured header field has to agree on where the tokens are,
/// and a second private copy of that logic is how the four daemons came to
/// disagree about `Authentication-Results` in the first place (audit M-6).
pub const cfws = @import("cfws.zig");
pub const auth_stamp = @import("auth_stamp.zig");
pub const escape = @import("escape.zig");
pub const header_scrub = @import("header_scrub.zig");
pub const zmq = @import("zmq.zig");
pub const reload = @import("reload.zig");
pub const rcu = @import("rcu.zig");
pub const log = @import("log.zig");

test {
    _ = cli;
    _ = config;
    _ = milter;
    _ = listener;
    _ = connection;
    _ = header;
    _ = msgfile;
    _ = daemon;
    _ = credentials;
    _ = bootstrap;
    _ = worker;
    // `pool` was exported above but missing here, so its tests had never run.
    // A module absent from this list still compiles and still looks tested.
    _ = pool;
    _ = dns;
    _ = auth_results;
    _ = auth_stamp;
    _ = escape;
    _ = header_scrub;
    _ = zmq;
    _ = reload;
    _ = rcu;
    _ = log;
}
