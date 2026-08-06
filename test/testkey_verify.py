#!/usr/bin/env python3
"""Pin the behaviour of the shared testkey tool across both products.

    python3 testkey_verify.py [-v]

`securemilter-lib/src/testkey.zig` is a generic instantiated twice, as
`securedkim-testkey` and `securearc-testkey`. It has no unit tests and cannot
have any: it is generic over the crypto package, and this library does not
depend on that package -- deliberately, since doing so to shorten one import
line would link OpenSSL into securespf and securedmarc, which have no keys. So
the generic cannot be instantiated in this library's own test build, and the
only automated statement about it was that both products compile.

This file is that statement made stronger. It drives both binaries against the
shared DNS fake and pins 17 behaviours per binary, which between them cover
every branch the two 244- and 246-line copies had before stage 5.1 merged them.

WHY IT LIVES HERE and not in either product: it asserts that the two binaries
agree, so it belongs to neither, and the thing it tests is in this repository.
It is the same argument that put the DNS fake next door in `dnsfake.py`.

WHY IT WAS NOT COMMITTED UNTIL NOW. Stage 5.1 left this as a throwaway in /tmp,
because it needed a DNS fake and there were four to choose from, each owned by a
product and none reachable from here. Consolidating them removed the obstacle
rather than working around it.

Both products must be built first:

    (cd ../../securedkim && zig build) && (cd ../../securearc && zig build)

SECUREDKIM_TESTKEY and SECUREARC_TESTKEY override the binary paths, for a
package build or a CI runner where they are not in the tree. Requires openssl(1)
for key generation. Exits non-zero on any failure, so it can gate a build.
"""

import argparse
import base64
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dnsfake import DnsFake, TxtZone   # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TOOLS = [
    ("securedkim", os.environ.get(
        "SECUREDKIM_TESTKEY",
        os.path.join(_ROOT, "securedkim", "zig-out", "bin", "securedkim-testkey"))),
    ("securearc", os.environ.get(
        "SECUREARC_TESTKEY",
        os.path.join(_ROOT, "securearc", "zig-out", "bin", "securearc-testkey"))),
]

DOMAIN = "example.com"


class Checker:
    def __init__(self, verbose):
        self.verbose = verbose
        self.failures = []
        self.passed = 0

    def check(self, label, ok, detail=""):
        if ok:
            self.passed += 1
            if self.verbose:
                print(f"  ok    {label}")
        else:
            self.failures.append(label)
            print(f"  FAIL  {label}")
            if detail:
                print(f"        {detail}")


def spki_b64(keypath):
    """The base64 body of a key's SPKI, which is what a DKIM p= tag holds."""
    pem = subprocess.run(
        ["openssl", "rsa", "-in", keypath, "-pubout", "-outform", "PEM"],
        capture_output=True, text=True, check=True).stdout
    return "".join(l for l in pem.splitlines() if not l.startswith("-----"))


def genrsa(path, bits):
    subprocess.run(["openssl", "genrsa", "-out", path, str(bits)],
                   capture_output=True, check=True)
    os.chmod(path, 0o600)


def gen_ed25519_seed(path):
    """The 32-byte-seed wrapper the tool parses for Ed25519."""
    with open(path, "w") as fh:
        fh.write("-----BEGIN ED25519 SEED-----\n")
        fh.write(base64.b64encode(os.urandom(32)).decode() + "\n")
        fh.write("-----END ED25519 SEED-----\n")
    os.chmod(path, 0o600)


def run(tool, selector, key, port, domain=DOMAIN):
    return subprocess.run(
        [tool, "-s", selector, "-d", domain, "-k", key,
         "-n", "127.0.0.1", "-p", str(port)],
        capture_output=True, text=True, timeout=30)


def build_zone(tmp):
    """Keys on disk and the zone that describes them."""
    good = os.path.join(tmp, "good.key")
    weak = os.path.join(tmp, "weak.key")
    ed = os.path.join(tmp, "ed25519.key")
    genrsa(good, 2048)
    # 512, not 1024. RFC 8301 3.2 sets the floor AT 1024, so a 1024-bit key is
    # legal and must NOT warn -- the first version of this file asserted a
    # warning for 1024 and failed, and the test was wrong, not the code.
    genrsa(weak, 512)
    gen_ed25519_seed(ed)

    pub = spki_b64(good)
    zone = {
        f"sel._domainkey.{DOMAIN}": f"v=DKIM1; k=rsa; p={pub}",
        # Same length, different tail: a mismatch rather than a parse failure.
        f"bad._domainkey.{DOMAIN}": f"v=DKIM1; k=rsa; p={pub[:-4]}AAAA",
        f"weak._domainkey.{DOMAIN}": f"v=DKIM1; k=rsa; p={spki_b64(weak)}",
        # p= present and empty is a REVOKED key (RFC 6376 3.6.1), which is a
        # different fact from a key that does not match.
        f"rev._domainkey.{DOMAIN}": "v=DKIM1; k=rsa; p=",
        # No p= at all: the tool must not treat the record as a key, in case a
        # sibling TXT at the same name is the real one.
        f"nop._domainkey.{DOMAIN}": "v=DKIM1; k=rsa",
        # K=rsa, not k=rsa. RFC 6376 3.2 tag names are case-SENSITIVE, so this
        # record specifies no algorithm and the default (rsa) applies.
        f"mixcase._domainkey.{DOMAIN}": f"v=DKIM1; K=rsa; p={pub}",
        f"ed._domainkey.{DOMAIN}": "v=DKIM1; k=ed25519; p=" + "A" * 43 + "=",
    }
    return zone, good, weak, ed


def verify_tool(c, name, tool, dns, good, weak, ed):
    port = dns.port

    r = run(tool, "sel", good, port)
    c.check(f"{name}: matching RSA key passes",
            r.returncode == 0 and "PASS" in r.stdout,
            f"rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
    c.check(f"{name}: algorithm is reported", "algorithm: rsa" in r.stdout, r.stdout)
    c.check(f"{name}: a good 2048-bit key warns about nothing", r.stderr == "", r.stderr)

    r = run(tool, "bad", good, port)
    c.check(f"{name}: a mismatched key fails with exit 1",
            r.returncode == 1 and "FAIL" in r.stderr, f"rc={r.returncode} {r.stderr!r}")

    r = run(tool, "weak", weak, port)
    c.check(f"{name}: a sub-floor key warns per RFC 8301",
            "RFC 8301" in r.stderr and "512 bits" in r.stderr, r.stderr)
    c.check(f"{name}: a weak key is still compared rather than refused",
            "PASS" in r.stdout, r.stdout)

    os.chmod(weak, 0o644)
    r = run(tool, "weak", weak, port)
    c.check(f"{name}: a group-readable key warns and names the mode",
            "mode 644" in r.stderr, r.stderr)
    # The daemon name is the whole reason this is a generic rather than a
    # copy, so it is the parameter most worth pinning.
    c.check(f"{name}: the permissions warning names this daemon",
            f"{name} will refuse" in r.stderr, r.stderr)
    # chmod alone is not the fix: the key is re-read AFTER the privilege drop,
    # so ownership matters as much as mode. Both pre-5.1 copies omitted this.
    c.check(f"{name}: the permissions warning advises chown as well as chmod",
            "chown" in r.stderr, r.stderr)
    os.chmod(weak, 0o600)

    r = run(tool, "rev", good, port)
    c.check(f"{name}: a revoked key (empty p=) is fatal, not a mismatch",
            r.returncode != 0 and "revoked" in r.stderr,
            f"rc={r.returncode} {r.stderr!r}")

    r = run(tool, "nop", good, port)
    c.check(f"{name}: a record with no p= at all is not found, not empty",
            r.returncode != 0 and "not found" in r.stderr, r.stderr)

    r = run(tool, "mixcase", good, port)
    c.check(f"{name}: K=rsa does not satisfy a lookup for k",
            "algorithm: rsa" in r.stdout, r.stdout)

    r = run(tool, "ed", ed, port)
    c.check(f"{name}: an Ed25519 key loads and compares",
            r.returncode == 1 and "FAIL" in r.stderr, f"rc={r.returncode} {r.stderr!r}")

    r = run(tool, "absent", good, port)
    c.check(f"{name}: a name with no record is a resolve failure",
            r.returncode != 0, r.stdout)

    r = subprocess.run([tool, "-h"], capture_output=True, text=True, timeout=30)
    # -p is why this file can exist at all: neither copy accepted a nameserver
    # port, so neither could be pointed at a fake and both went unexercised for
    # their entire existence.
    c.check(f"{name}: -h documents -p", "-p <port>" in r.stdout, r.stdout)
    c.check(f"{name}: -h names the right program",
            f"{name}-testkey [options]" in r.stdout, r.stdout)

    r = subprocess.run([tool, "-s", "sel"], capture_output=True, text=True, timeout=30)
    c.check(f"{name}: a missing -d is refused",
            r.returncode != 0 and "-d" in r.stderr, r.stderr)

    r = subprocess.run([tool, "--nope"], capture_output=True, text=True, timeout=30)
    c.check(f"{name}: an unknown option is refused", r.returncode != 0, r.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every check, not only failures")
    args = ap.parse_args()

    missing = [path for _, path in TOOLS if not os.path.exists(path)]
    if missing:
        sys.exit("not built: " + ", ".join(missing)
                 + "\nrun `zig build` in each product, or set "
                   "SECUREDKIM_TESTKEY / SECUREARC_TESTKEY")

    c = Checker(args.verbose)
    with tempfile.TemporaryDirectory() as tmp:
        zone, good, weak, ed = build_zone(tmp)
        # port 0: the fake picks an unused port and hands it to the tool, so two
        # runs at once cannot collide.
        with DnsFake(TxtZone(zone), port=0) as dns:
            for name, tool in TOOLS:
                print(f"{name}-testkey")
                verify_tool(c, name, tool, dns, good, weak, ed)

    total = c.passed + len(c.failures)
    print(f"\ntotal={total} passed={c.passed} failed={len(c.failures)}")
    if c.failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
