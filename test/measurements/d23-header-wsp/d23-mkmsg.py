#!/usr/bin/env python3
"""Write the D-23 probe message with byte-exact leading whitespace after each colon.

Every X-D23-* field varies only in what sits between the colon and the value, which
is precisely the run of octets a milter never sees unless SMFIP_HDR_LEADSPC is
negotiated. Written as bytes, with explicit CRLF, so no library can helpfully
normalise the thing being measured.
"""
import sys

HDRS = [
    (b"X-D23-Zero",    b"",           b"zero"),
    (b"X-D23-One",     b" ",          b"one"),
    (b"X-D23-Two",     b"  ",         b"two"),
    (b"X-D23-Three",   b"   ",        b"three"),
    (b"X-D23-Tab",     b"\t",         b"tab"),
    (b"X-D23-SpTabSp", b" \t ",       b"sptabsp"),
    (b"X-D23-Empty",   b"",           b""),
    (b"X-D23-EmptySp", b" ",          b""),
    (b"X-D23-EmptyTwo", b"  ",        b""),
]

subject = sys.argv[1].encode() if len(sys.argv) > 1 else b"d23-probe"
sender = sys.argv[2].encode() if len(sys.argv) > 2 else b"d23@bambania.com"
rcpt = sys.argv[3].encode() if len(sys.argv) > 3 else b"testuser@lab.test"

out = []
out.append(b"From: " + sender)
out.append(b"To: " + rcpt)
out.append(b"Subject: " + subject)
out.append(b"Date: Thu, 30 Jul 2026 12:00:00 -0500")
out.append(b"Message-ID: <" + subject + b"@d23.probe>")
for name, ws, val in HDRS:
    out.append(name + b":" + ws + val)

body = b"D-23 measurement probe.\r\n"
msg = b"\r\n".join(out) + b"\r\n\r\n" + body

with open("/tmp/d23.eml", "wb") as f:
    f.write(msg)

print("wrote /tmp/d23.eml,", len(msg), "bytes")
for name, ws, val in HDRS:
    print(f"  {name.decode():<16} sent-ws={ws!r:<10} value={val!r}")
