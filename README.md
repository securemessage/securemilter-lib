# securemilter-lib

Shared Zig library for the SecureMilter suite — a set of high-performance email authentication milters for Postfix.

## Overview

securemilter-lib provides the common infrastructure used by all four SecureMilter products:

- **[SecureSPF](https://pacyworld.dev/securemessage/securespf)** — SPF verification (RFC 7208)
- **[SecureDKIM](https://pacyworld.dev/securemessage/securedkim)** — DKIM signing and verification (RFC 6376, RFC 8463)
- **[SecureDMARC](https://pacyworld.dev/securemessage/securedmarc)** — DMARC policy evaluation (RFC 7489)
- **[SecureARC](https://pacyworld.dev/securemessage/securearc)** — ARC chain validation and sealing (RFC 8617)

## Modules

| Module | Description |
|--------|-------------|
| `milter` | Sendmail milter protocol v6 codec — packet framing, OPTNEG negotiation, command/response types |
| `listener` | TCP and Unix domain socket listener creation with SO_REUSEPORT |
| `worker` | Thread-per-core worker pool with per-worker kqueue event loop |
| `connection` | Per-connection milter state machine and buffered I/O |
| `dns` | Async DNS resolver integrated with kqueue (TXT, A, AAAA, MX, with TTL caching) |
| `auth_results` | RFC 8601 Authentication-Results header generation and parsing |
| `config` | INI-style config parser with `[section]` support |
| `crypto` | RSA-SHA256 via OpenSSL, Ed25519 via std.crypto, PEM key loading, base64 |
| `daemon` | Process daemonization, PID file, privilege drop, signal handling |
| `zmq` | ZMQ PUB socket for fire-and-forget event publishing |

## Usage

Add as a dependency in your `build.zig.zon`:

```zig
.securemilter = .{
    .url = "https://pacyworld.dev/securemessage/securemilter-lib/archive/v0.1.0.tar.gz",
    .hash = "...",
},
```

## Requirements

- Zig 0.15.x
- FreeBSD (kqueue/kevent)
- OpenSSL (`libcrypto`)
- libzmq4

## License

BSD-2-Clause — Copyright (c) 2026, Daniel Morante
