//! The one implementation of "does the key in DNS match the key on disk".
//!
//! `securedkim-testkey` and `securearc-testkey` were 244 and 246 lines that
//! differed in 18: a program name, some usage prose, and two sentences of the
//! same warning written twice (refactor plan stage 5.1). Everything that made
//! them a *tool* -- the argument loop, the TXT lookup, the `p=` extraction, the
//! key load, the comparison -- was duplicated, and neither copy had a test or a
//! conformance case pointing at it. Two untested copies of one thing is not twice
//! the coverage of one untested thing; it is two things that can disagree about
//! whether an operator's key is deployed correctly, which is the only question
//! this tool exists to answer.
//!
//! WHY THE CRYPTO PACKAGE ARRIVES AS A PARAMETER. This file needs `cli` and `dns`
//! from this library and key loading from `securemilter_crypto`, and the two
//! packages are both dependency-free roots: neither imports the other. Adding
//! `securemilter_crypto` to this library's dependencies would link OpenSSL into
//! `securespf` and `securedmarc`, which have no keys and no use for it, to give a
//! diagnostic tool a shorter import line. So the caller -- which already has both
//! -- passes the one it has, and the graph stays as it is.
//!
//! NOTHING HERE IS COVERED BY A CONFORMANCE SUITE, unlike everything else stage 5
//! consolidated, and nothing here can be covered by a unit test either: the
//! generic cannot be instantiated in this library's own test build, because that
//! would need the crypto dependency this file exists to avoid. There is also no
//! RFC to be conformant to -- the tool compares two strings.
//!
//! What it has instead is `test/testkey_verify.py`, which drives both binaries
//! against the shared DNS fake and pins 18 behaviours each. `-p` exists so that is
//! possible at all -- see `Options.usage`. Teeth-checked by hardcoding one
//! product's name in place of `opts.daemon`, which fails exactly one check, in the
//! other product only.

const std = @import("std");
const mem = std.mem;
const process = std.process;

const cli_mod = @import("cli.zig");
const dns_mod = @import("dns.zig");

/// What differs between one product's key tool and another's.
pub const Options = struct {
    /// Program name, as it appears in messages: `securedkim-testkey`.
    name: []const u8,

    /// The daemon that would load this key, named in the permissions warning.
    /// An operator running `securearc-testkey` needs to be told that *securearc*
    /// will refuse the key, not that some daemon somewhere will.
    daemon: []const u8,

    /// The `-h` text. Per product because the DKIM and ARC tools describe
    /// different things to different people, and usage prose is documentation
    /// rather than logic -- sharing it would mean one of the two lying.
    ///
    /// It has to document `-p`, which the flag loop below accepts: without a port
    /// this tool can only talk to 53, and a fake resolver on 53 needs root. Both
    /// copies omitted it while their sibling `securedkim-check` had it, so neither
    /// could be run against the suite's own DNS server.
    usage: []const u8,
};

/// A key-comparison tool for one product.
///
/// `xcrypto` is the `securemilter_crypto` package: this uses `.crypto` for key
/// loading and `.sig_header` for the `p=` lookup.
pub fn Tool(comptime xcrypto: type, comptime opts: Options) type {
    const crypto = xcrypto.crypto;
    const sig_header = xcrypto.sig_header;
    const cli = cli_mod.Tool(opts.name);

    return struct {
        pub fn main() !void {
            var gpa = std.heap.GeneralPurposeAllocator(.{}){};
            defer _ = gpa.deinit();
            const allocator = gpa.allocator();

            var args = process.args();
            _ = args.next();

            var selector: ?[]const u8 = null;
            var domain: ?[]const u8 = null;
            var keyfile: ?[]const u8 = null;
            var nameserver: []const u8 = "127.0.0.1";
            var port: u16 = 53;

            while (args.next()) |arg| {
                if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
                    cli.out(opts.usage);
                    return;
                } else if (mem.eql(u8, arg, "-s")) {
                    selector = args.next() orelse return cli.fatal("missing argument for -s");
                } else if (mem.eql(u8, arg, "-d")) {
                    domain = args.next() orelse return cli.fatal("missing argument for -d");
                } else if (mem.eql(u8, arg, "-k")) {
                    keyfile = args.next() orelse return cli.fatal("missing argument for -k");
                } else if (mem.eql(u8, arg, "-n")) {
                    nameserver = args.next() orelse return cli.fatal("missing argument for -n");
                } else if (mem.eql(u8, arg, "-p")) {
                    const raw = args.next() orelse return cli.fatal("missing argument for -p");
                    port = std.fmt.parseInt(u16, raw, 10) catch return cli.fatal("invalid port");
                } else {
                    return cli.fatal("unknown option (use -h for help)");
                }
            }

            const sel = selector orelse return cli.fatal("-s <selector> is required");
            const dom = domain orelse return cli.fatal("-d <domain> is required");
            const kf = keyfile orelse return cli.fatal("-k <keyfile> is required");

            // ARC keys live under `_domainkey` too. RFC 8617 §4.2.1 gives ARC no
            // DNS namespace of its own: "the public key is stored in the DNS as
            // described in Section 3.6.1 of [RFC6376]", which is this name.
            const qname = try std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{ sel, dom });
            defer allocator.free(qname);

            const ns_slice: []const []const u8 = &.{nameserver};
            var resolver = dns_mod.Resolver.init(allocator, .{
                .nameservers = ns_slice,
                .port = port,
                .timeout_ms = 5000,
                .retries = 2,
            });
            defer resolver.deinit();

            var dns_result = resolver.resolve(qname, .TXT) catch {
                const msg = try std.fmt.allocPrint(allocator, "DNS lookup failed for {s}\n", .{qname});
                defer allocator.free(msg);
                cli.err(msg);
                return cli.fatal("cannot resolve DNS TXT record");
            };
            defer dns_result.deinit();

            var pubkey_b64: ?[]const u8 = null;
            var key_type: []const u8 = "rsa";
            var txt_iter = dns_result.txtRecords();
            while (txt_iter.next()) |txt| {
                // A `p=` present but empty is a REVOKED key (RFC 6376 §3.6.1),
                // not a record to keep looking past -- so an empty value ends the
                // search and is reported as revoked below, while a record with no
                // `p=` at all is skipped in case another TXT record at the same
                // name is the key.
                if (sig_header.findTag(txt, "p")) |p| {
                    if (p.len > 0) {
                        pubkey_b64 = p;
                        // Absent `k=` means rsa: §3.6.1 makes `k` optional with
                        // "rsa" as its default.
                        if (sig_header.findTag(txt, "k")) |k| key_type = k;
                        break;
                    }
                }
            }

            const dns_pub = pubkey_b64 orelse {
                const msg = try std.fmt.allocPrint(allocator, "No key record found at {s}\n", .{qname});
                defer allocator.free(msg);
                cli.err(msg);
                return cli.fatal("key record not found or revoked (empty p=)");
            };

            const local_pub_b64 = extractPublicKey(allocator, kf, key_type) catch {
                return cli.fatal("failed to load or parse private key file");
            };
            defer allocator.free(local_pub_b64);

            const out_header = try std.fmt.allocPrint(allocator,
                \\{s}: checking key {s}._domainkey.{s}
                \\  algorithm: {s}
                \\
            , .{ opts.name, sel, dom, key_type });
            defer allocator.free(out_header);
            cli.out(out_header);

            if (mem.eql(u8, dns_pub, local_pub_b64)) {
                cli.out("  result: PASS — DNS public key matches local private key\n");
            } else {
                cli.err("  result: FAIL — DNS public key does NOT match local private key\n");
                process.exit(1);
            }
        }

        /// Base64 public key of a private key file, in whichever encoding `p=`
        /// uses for that algorithm.
        fn extractPublicKey(
            allocator: std.mem.Allocator,
            path: []const u8,
            key_type: []const u8,
        ) ![]u8 {
            if (mem.eql(u8, key_type, "ed25519")) {
                return extractEd25519PublicKey(allocator, path);
            }
            return extractRsaPublicKey(allocator, path);
        }

        fn extractRsaPublicKey(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
            // 0, not the RFC floor: this tool exists to tell an operator what is in
            // a key file, and refusing to load a weak key would leave them with an
            // error and no diagnosis. It warns instead, which is the more useful
            // answer.
            // `.permit_any` for the same reason as the 0 above: refusing to open a
            // badly-permissioned key would stop this tool doing the one thing an
            // operator ran it for. It reports the mode instead -- which is more use
            // than a refusal, because checking a key is the whole purpose.
            var key = try crypto.loadRsaKeyFile(path, 0, .permit_any);
            defer key.deinit();

            if (crypto.keyFileMode(path)) |mode| {
                if (mode & 0o077 != 0) {
                    // `crypto.KEY_PERMISSIONS_ADVICE` rather than a third wording of
                    // it. Both copies used to say "chmod 600 to fix" and stop there;
                    // the shared advice also says to `chown` the key to the user the
                    // daemon drops to, which is the half that had been missing and
                    // the half that bites after a privilege drop.
                    const msg = try std.fmt.allocPrint(
                        allocator,
                        "warning: {s} is mode {o}, {s}.\n" ++
                            "         {s} will refuse to load it as it stands.\n",
                        .{ path, mode, crypto.KEY_PERMISSIONS_ADVICE, opts.daemon },
                    );
                    defer allocator.free(msg);
                    cli.err(msg);
                }
            } else |_| {}

            const bits = crypto.signingKeyBits(&key);
            if (bits < crypto.RFC8301_MIN_RSA_BITS) {
                // One wording for both products. "anything signed with it" covers a
                // DKIM signature and an ARC seal without naming either, which is
                // what the two copies were doing differently for no reason.
                const msg = try std.fmt.allocPrint(
                    allocator,
                    "warning: this key is {d} bits. RFC 8301 3.2 requires at least {d}, and a\n" ++
                        "         conformant verifier treats anything signed with it as permanently\n" ++
                        "         failed. Generate a 2048-bit key instead.\n",
                    .{ bits, crypto.RFC8301_MIN_RSA_BITS },
                );
                defer allocator.free(msg);
                cli.err(msg);
            }

            return crypto.publicKeySpkiBase64(allocator, &key);
        }

        fn extractEd25519PublicKey(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
            // This tool exists to print the PUBLIC key, but the file it is pointed
            // at is a PRIVATE one, so the seed transits four buffers on the way to
            // the answer: the file text, its base64 decoding, a fixed-size copy, and
            // the expanded secret inside the derived keypair. None of them were
            // wiped (audit C-1).
            const content = try std.fs.cwd().readFileAlloc(allocator, path, 4096);
            defer {
                std.crypto.secureZero(u8, content);
                allocator.free(content);
            }

            const begin_end = mem.indexOf(u8, content, "-----\n") orelse return error.InvalidPem;
            const data_start = begin_end + 6;
            const end_marker = mem.indexOf(u8, content[data_start..], "\n-----") orelse
                return error.InvalidPem;
            const seed_b64 = content[data_start..][0..end_marker];

            const seed_bytes = try crypto.base64Decode(allocator, seed_b64);
            defer {
                std.crypto.secureZero(u8, seed_bytes);
                allocator.free(seed_bytes);
            }

            if (seed_bytes.len != 32) return error.InvalidSeedLength;

            var seed: [32]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            @memcpy(&seed, seed_bytes);

            var key = try crypto.loadEd25519Seed(seed);
            defer key.deinit();

            // RFC 8463 §3: `p=` for ed25519-sha256 is the bare 32-byte public key,
            // not the SubjectPublicKeyInfo the RSA path produces.
            return crypto.base64Encode(allocator, &key.ed25519_key_pair.?.public_key.toBytes());
        }
    };
}
