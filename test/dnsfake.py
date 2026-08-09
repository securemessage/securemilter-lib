"""One authoritative DNS fake for every conformance suite in the tree.

Each of the four products drives its own daemon's *real* resolver against this
rather than stubbing the lookup out, and that is the whole point: a resolver is
part of what the RFCs specify, and its failure modes are required to differ.
A query establishing that a key record does not exist means PERMFAIL, because
the signature can never verify; a query that merely fails to answer may only
mean TEMPFAIL. Stub the lookup and that distinction goes untested -- and it is
the distinction deciding whether a message is retried or rejected.

WHY THIS IS ONE FILE NOW, having deliberately been four.

`securearc/test/arc_valimail/txtdns.py` used to carry this refusal in its own
header: "The two are not shared because securespf and securearc are separate
repositories and a test helper is not worth a package." That was a considered
judgement and it is being overturned on evidence, not taste:

  - It was written when there were two copies. There were four by the time
    anyone counted: securearc's, plus `securedkim/test/rfc6376/dkimdns.py` and
    `securedmarc/test/rfc9989/dmarcdns.py` -- both of whose headers say
    "Adapted from txtdns.py" -- plus `securespf/test/rfc7208/mockdns.py`.
  - Three of those four held a BYTE-IDENTICAL copy of the wire codec below.
    `dkimdns.py`'s and `txtdns.py`'s `_encode_name`/`_decode_name`/`_txt_rdata`
    differed in nothing at all; `dmarcdns.py`'s differed in one docstring.
  - The premise turned out to be false. It is not a package: the six
    repositories are checked out side by side because build.zig.zon depends on
    `../securemilter-lib` by path, so this file is reachable with a `sys.path`
    insert -- which the dkimpy differential (now `interop/dkimpy-diff/` in
    the engineering-docs repository) had already been doing for two years to
    borrow `dkimdns` from a sibling directory, under the comment "shared, not
    duplicated".
  - A copied test helper has already produced phantom defects here twice. The
    worst is recorded in `securedkim/test/rfc6376/README.md`: a value-
    normalisation bug present in ONE copy served a TXT record per character and
    made the suite report ELEVEN product defects that did not exist. Four
    copies of a hand-rolled DNS server is four chances to certify the harness
    instead of the daemon.

WHAT IS SHARED AND WHAT IS NOT. The wire codec and the server loop are the
same job in all four suites, so they live here once. What a zone should *say*
is genuinely per-RFC, so that is a pluggable object with one method:

    zone.resolve(qname, qtype, qtype_name) -> (rcode | None, [(name, type, value)])

Returning `None` for the rcode means answer nothing at all, which is how a
timeout is expressed. `TxtZone` covers DKIM, ARC and DMARC -- a single TXT
lookup, with the differences between those three reduced to constructor input.
`RecordZone` covers RFC 7208, which needs A, AAAA, MX, PTR, CNAME, type-99 SPF,
CNAME chains and the openspf zonedata sentinels. Keeping them apart is
deliberate: a purpose-built TXT zone is easy to verify by eye, and folding it
into the general one would make every DKIM case depend on zonedata parsing it
never uses.

THE WIRE DETAILS THAT DIFFERED WERE RECONCILED, each verified against all four
suites rather than assumed equivalent. `mockdns.py` encoded TXT rdata as latin-1-with-replace where the
other three used utf-8; the two differ only above U+007F and the RFC 7208
zonedata contains no byte outside printable ASCII, so utf-8 is used and the two
suites carrying non-ASCII cases keep the encoding they already had. `mockdns.py`
also set RD and RA in its response flags where the other three set only QR and
AA; QR|AA is used here and the SPF suite still passes 203/203, so those bits
were decorative. It likewise answered with a TTL of 60 where the others used
300, which no suite can observe because every case spawns a fresh checker
process and no resolver cache outlives one. `decode_name` additionally gained
the compression-pointer loop guard that only `mockdns.py` had -- unreachable
from a query our own resolver emits, since the question name is never
compressed, but free to keep.
"""

import socket
import struct
import threading

# The query/answer types the suites need between them. RFC 7208 wants all of
# these; the TXT suites want exactly one.
TYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
        "AAAA": 28, "SPF": 99}
TYPE_NAME = {v: k for k, v in TYPE.items()}

TYPE_TXT = TYPE["TXT"]

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3

# A zone may hold this in place of a record's value to make the name answer
# SERVFAIL. That is the "failed to respond" branch of RFC 6376 6.1.2, which must
# be distinguishable from "does not exist".
#
# It is a module-level object rather than a string so that no record value can
# ever collide with it -- and it must be compared with `is`, never `isinstance`.
# Asking `isinstance(v, type(SERVFAIL))` is a test against `object`, which
# matches everything; that exact mistake is the one that produced eleven phantom
# defects in the RFC 6376 suite.
SERVFAIL = object()

# Held in place of a value to make the name answer nothing at all, so that the
# resolver's own timeout path runs.
TIMEOUT = object()


def encode_name(name):
    """Encode a dotted name as a sequence of DNS labels."""
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        # latin-1 with replacement never raises. A name outside ASCII cannot
        # reach here from any current suite, and a fake that crashes on one
        # would be reported as a product defect.
        raw = label.encode("latin-1", "replace")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(data, offset):
    """Decode a DNS name, following compression pointers.

    Returns `(name, next_offset)`, where `next_offset` is the octet after the
    name *as written at `offset`* -- so it is the start of the question's type
    field even when a pointer was followed.
    """
    labels = []
    jumped = False
    end = offset
    seen = set()
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if pointer in seen:
                # A malformed query pointing into its own chain would otherwise
                # spin this thread forever.
                raise ValueError("compression loop")
            seen.add(pointer)
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
        if not jumped:
            end = offset
    return ".".join(labels), end


def txt_rdata(value):
    """Encode a TXT rdata as one or more character-strings.

    Splitting at 255 octets is the wire format's requirement, not a choice, and
    it is load-bearing for these suites rather than incidental: a 2048-bit RSA
    key does not fit in one character-string, so every real-world RSA key record
    takes the joining path -- which is also the path that catches a resolver
    reading only the first string. RFC 8463 notes the contrast, an Ed25519 key
    being 44 base64 octets and fitting in one.

    A list value means the record is deliberately written as several
    character-strings, which RFC 7208 3.3 says a verifier must join with no
    separator. Serving that faithfully is the only way to test that we do.
    """
    parts = value if isinstance(value, list) else [value]
    out = b""
    for part in parts:
        raw = str(part).encode("utf-8")
        while len(raw) > 255:
            out += bytes([255]) + raw[:255]
            raw = raw[255:]
        out += bytes([len(raw)]) + raw
    if out == b"":
        out = b"\x00"
    return out


def rdata_for(rtype, value):
    """Encode one record's rdata. Raises ValueError for a type we cannot serve."""
    if rtype in ("TXT", "SPF"):
        return txt_rdata(value)
    if rtype == "A":
        return socket.inet_pton(socket.AF_INET, str(value))
    if rtype == "AAAA":
        return socket.inet_pton(socket.AF_INET6, str(value))
    if rtype == "MX":
        pref, host = value
        return struct.pack("!H", int(pref)) + encode_name(str(host))
    if rtype in ("PTR", "CNAME", "NS"):
        return encode_name(str(value))
    raise ValueError("unsupported record type %s" % rtype)


class TxtZone:
    """A flat map of name to TXT value, for the suites that only look up TXT.

    `records` maps a full name -- "sel._domainkey.example.com", or
    "_dmarc.example.com" -- to one of:

      - a string, served as a single TXT record;
      - a list of strings, served as *several* TXT records at that name, which
        RFC 9989 4.10 steps 2 and 6 need in order to reach the rule that a name
        answering with more than one DMARC record publishes none;
      - `SERVFAIL`, to answer SERVFAIL instead.

    A name absent from the map answers NXDOMAIN, which is how a case says "no
    record is published here". NOERROR-with-no-answer would say the name exists
    without a record, a different fact that RFC 6376 6.1.2 treats differently.
    """

    def __init__(self, records):
        # Order matters here, and it is the site of a recorded harness defect:
        # test the sentinel by identity FIRST, then a list, then wrap a bare
        # string. See the note on SERVFAIL above for what happens otherwise.
        self.records = {}
        for name, value in (records or {}).items():
            key = name.lower().rstrip(".")
            if value is SERVFAIL or value is TIMEOUT:
                self.records[key] = value
            elif isinstance(value, list):
                self.records[key] = value
            else:
                self.records[key] = [value]

    def resolve(self, qname, qtype, qtype_name):
        values = self.records.get(qname.lower().rstrip("."))
        if values is TIMEOUT:
            return None, []
        if values is SERVFAIL:
            return RCODE_SERVFAIL, []
        # A non-TXT query is NXDOMAIN even for a name this zone holds: these
        # suites publish nothing but TXT, so any other type genuinely does not
        # exist here.
        if values is None or qtype != TYPE_TXT:
            return RCODE_NXDOMAIN, []
        return RCODE_NOERROR, [(qname, "TXT", value) for value in values]

    def describe(self, qname):
        """A one-word state for the verbose log."""
        values = self.records.get(qname.lower().rstrip("."))
        if values is SERVFAIL:
            return "SERVFAIL"
        if values is TIMEOUT:
            return "TIMEOUT"
        return "hit" if values is not None else "NXDOMAIN"


class RecordZone:
    """A parsed openspf.org `zonedata` block, for the RFC 7208 suite.

    Indexed by lowercase owner name, holding `(type, value)` pairs, and carrying
    the two sentinels that specification uses:

      - a bare string entry `TIMEOUT`, meaning queries this name does not
        otherwise answer must go unanswered;
      - `TYPE: NONE`, meaning the type is explicitly absent rather than being a
        record whose value is the string "NONE".
    """

    def __init__(self, zonedata, duplicate_spf_to_txt=False):
        self.records = {}
        self.timeout_names = set()
        self.absent = {}

        for owner, entries in (zonedata or {}).items():
            owner_l = str(owner).lower().rstrip(".")
            rrs = []
            absent = set()
            for entry in entries or []:
                if entry is None:
                    continue
                # A bare string rather than a mapping is how the suite writes
                # TIMEOUT.
                if isinstance(entry, str):
                    if entry.upper() == "TIMEOUT":
                        self.timeout_names.add(owner_l)
                    continue
                for rtype, value in entry.items():
                    rtype_u = str(rtype).upper()
                    if isinstance(value, str) and value == "NONE":
                        absent.add(rtype_u)
                        continue
                    rrs.append((rtype_u, value))
            self.records[owner_l] = rrs
            if absent:
                self.absent[owner_l] = absent

        if duplicate_spf_to_txt:
            self._duplicate_spf_to_txt()

    def _duplicate_spf_to_txt(self):
        """Serve every type-99 SPF record as a TXT record as well.

        The suite header states this is the driver's job: the tests were written
        when both types were legal, and every section except "Selecting records"
        relies on the driver duplicating them so one specification exercises
        both TXT-only and SPF-aware implementations. RFC 7208 3.1 removed type
        SPF, so securespf queries TXT only and would otherwise see empty zones.
        """
        for owner, rrs in self.records.items():
            # A zone asserting `TXT: NONE` states there is no TXT record, so
            # synthesising one would contradict the thing under test.
            if "TXT" in self.absent.get(owner, ()):
                continue
            if any(t == "TXT" for t, _ in rrs):
                # Where the suite gives both, it is deliberately testing which
                # wins. Never synthesise over an explicit TXT.
                continue
            for rtype, value in list(rrs):
                if rtype == "SPF":
                    rrs.append(("TXT", value))

    def _lookup(self, name, qtype_name):
        """Return (rrs, timeout, exists) for a name and type."""
        key = name.lower().rstrip(".")
        rrs = self.records.get(key)
        if rrs is None:
            return [], False, False

        matching = [v for t, v in rrs if t == qtype_name]
        if matching:
            return matching, False, True

        # A bare TIMEOUT covers only the types the zone does not answer. That is
        # how the suite writes "the SPF record is returned but the TXT query
        # hangs" as against "the TXT record exists but the type-99 query hangs"
        # -- timing out every type for such a name makes one of those
        # unreachable.
        if key in self.timeout_names:
            return [], True, True
        return [], False, True

    def _cname(self, name):
        for rtype, value in self.records.get(name.lower().rstrip("."), []):
            if rtype == "CNAME":
                return str(value)
        return None

    def resolve(self, qname, qtype, qtype_name):
        # An unknown query type is NOERROR with no answer, not NXDOMAIN: the
        # zonedata says nothing about types it was never written to cover.
        if qtype_name is None:
            return RCODE_NOERROR, []

        answers = []
        name = qname

        # Follow a CNAME chain before answering, as a real recursive resolver
        # would. Bounded, so a deliberately looping zone cannot hang the harness.
        for _ in range(8):
            target = self._cname(name)
            if target is None or qtype_name == "CNAME":
                break
            answers.append((name, "CNAME", target))
            name = target

        rrs, timeout, exists = self._lookup(name, qtype_name)
        if timeout:
            return None, []
        if not exists:
            return RCODE_NXDOMAIN, answers
        return RCODE_NOERROR, answers + [(name, qtype_name, value) for value in rrs]

    def describe(self, qname):
        rrs = self.records.get(qname.lower().rstrip("."))
        if rrs is None:
            return "NXDOMAIN"
        return "hit"


class DnsFake:
    """A UDP DNS server answering from a zone, on loopback.

    Usable either as a context manager, which is what the TXT suites want:

        with DnsFake(TxtZone(records), port=5353) as dns:
            ...

    or started and stopped around a whole run with the zone swapped per case,
    which is what the RFC 7208 suite wants:

        dns = DnsFake()            # port=0 binds an unused port, readable now
        dns.start()
        dns.set_zone(RecordZone(zonedata, duplicate_spf_to_txt=True))

    The socket is bound in the constructor, so `.port` is valid before `start()`
    and an auto-allocated port can be handed to the daemon under test.
    """

    def __init__(self, zone=None, port=0, host="127.0.0.1", verbose=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        # A timeout rather than a blocking read, so stop() is a flag rather than
        # closing a socket out from under a thread parked in recvfrom.
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.zone = zone if zone is not None else TxtZone({})
        self.verbose = verbose
        self.running = False
        self.thread = None
        self.queries = []
        self._lock = threading.Lock()

    def set_zone(self, zone):
        """Swap the zone and forget the query log, for reuse across cases."""
        self.zone = zone
        with self._lock:
            self.queries = []

    def start(self):
        if self.running:
            return self
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False

    def query_log(self):
        """Every TXT query in arrival order, repeats included.

        TXT only, deliberately. RFC 9989 4.10 does not merely state what a tree
        walk must conclude -- it states the sequence of names it must query, and
        the eight-query bound exists to stop a deeply nested Author Domain being
        turned into an amplifier. Those assertions are about TXT lookups, so a
        query of another type must not silently join the sequence.
        """
        with self._lock:
            return list(self.queries)

    def distinct_queries(self):
        """Queried names in first-seen order, repeats collapsed.

        The resolver under test caches, so a name looked up during an earlier
        walk in the same process does not reach the wire again. That is correct
        behaviour, and the reason sequence assertions are made against
        single-walk scenarios.
        """
        seen = []
        for name in self.query_log():
            if name not in seen:
                seen.append(name)
        return seen

    def _serve(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                reply = self._respond(data)
            except Exception:
                continue
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass

    def _respond(self, query):
        if len(query) < 12:
            return None
        txn = query[0:2]
        if struct.unpack("!H", query[4:6])[0] < 1:
            return None
        qname, offset = decode_name(query, 12)
        if offset + 4 > len(query):
            return None
        qtype, _qclass = struct.unpack("!HH", query[offset:offset + 4])
        question = query[12:offset + 4]
        qtype_name = TYPE_NAME.get(qtype)

        if qtype == TYPE_TXT:
            with self._lock:
                self.queries.append(qname.lower().rstrip("."))

        if self.verbose:
            print(f"    dns: {qname} type={qtype} -> {self.zone.describe(qname)}")

        rcode, rrs = self.zone.resolve(qname, qtype, qtype_name)
        if rcode is None:
            # Answer nothing at all: the point of a timeout entry is to make the
            # resolver's own timeout path run.
            return None

        answers = b""
        count = 0
        for name, rtype, value in rrs:
            try:
                rdata = rdata_for(rtype, value)
            except ValueError:
                # A type the zone names but this fake cannot encode. Skipping it
                # is what the RFC 7208 driver has always done -- the record is
                # not part of what the case is testing.
                continue
            answers += (encode_name(name)
                        + struct.pack("!HHIH", TYPE[rtype], 1, 300, len(rdata))
                        + rdata)
            count += 1

        # QR=1, AA=1: we are authoritative for every zone a suite defines.
        flags = 0x8400 | rcode
        return txn + struct.pack("!HHHHH", flags, 1, count, 0, 0) + question + answers
