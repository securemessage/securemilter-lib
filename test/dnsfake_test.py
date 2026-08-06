"""Unit tests for the shared DNS fake.

Run with `python3 -m unittest dnsfake_test` from this directory, or plain
`python3 dnsfake_test.py`.

WHY A TEST HELPER HAS TESTS. The four conformance suites exercise this file
several hundred times per run, so it is not unexercised -- but a defect in a
harness does not present as a harness failure, it presents as a product defect,
and this specific file has produced eleven of those. The value-normalisation
trap in `TxtZone.__init__` is the one that did it: a bare string stored
unwrapped is iterated one character at a time, serving a TXT record per
character, and every key record becomes garbage that looks exactly like a
signature the daemon failed to verify. Nothing downstream can tell the
difference. So the cases below pin the *harness* behaviours whose failure would
be misread as a finding, plus the wire encodings the suites depend on being
faithful rather than convenient.
"""

import socket
import struct
import threading
import unittest

import dnsfake
from dnsfake import (RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL, SERVFAIL,
                     TIMEOUT, TYPE, DnsFake, RecordZone, TxtZone)


def query_packet(name, qtype=TYPE["TXT"], txn=b"\xab\xcd"):
    return (txn + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
            + dnsfake.encode_name(name) + struct.pack("!HH", qtype, 1))


def parse_reply(data):
    """Return (rcode, ancount, [rdata, ...]) from a response packet."""
    flags, _qd, ancount = struct.unpack("!HHH", data[2:8])
    _qname, offset = dnsfake.decode_name(data, 12)
    offset += 4
    rdatas = []
    for _ in range(ancount):
        _name, offset = dnsfake.decode_name(data, offset)
        _rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdatas.append(data[offset:offset + rdlen])
        offset += rdlen
    return flags & 0x000F, ancount, rdatas


def txt_strings(rdata):
    """Split a TXT rdata back into its character-strings."""
    out = []
    i = 0
    while i < len(rdata):
        n = rdata[i]
        out.append(rdata[i + 1:i + 1 + n])
        i += 1 + n
    return out


class TxtZoneNormalisation(unittest.TestCase):
    """The trap that produced eleven phantom defects."""

    def test_bare_string_is_one_record_not_one_per_character(self):
        zone = TxtZone({"k._domainkey.example.com": "v=DKIM1; p=AAAA"})
        rcode, rrs = zone.resolve("k._domainkey.example.com", TYPE["TXT"], "TXT")
        self.assertEqual(rcode, RCODE_NOERROR)
        self.assertEqual(len(rrs), 1)
        self.assertEqual(rrs[0][2], "v=DKIM1; p=AAAA")

    def test_sentinel_is_matched_by_identity_not_by_type(self):
        # `isinstance(v, type(SERVFAIL))` is a test against `object` and matches
        # every value. If that regressed, this record would come back as a
        # SERVFAIL rather than an answer.
        zone = TxtZone({"a.example.com": "plain", "b.example.com": SERVFAIL})
        self.assertEqual(zone.resolve("a.example.com", TYPE["TXT"], "TXT")[0],
                         RCODE_NOERROR)
        self.assertEqual(zone.resolve("b.example.com", TYPE["TXT"], "TXT")[0],
                         RCODE_SERVFAIL)

    def test_list_value_serves_several_records_at_one_name(self):
        # RFC 9989 4.10 steps 2 and 6: a name answering with more than one DMARC
        # record publishes none. Unreachable unless the fake can produce it.
        zone = TxtZone({"_dmarc.example.com": ["v=DMARC1; p=none",
                                               "v=DMARC1; p=reject"]})
        rcode, rrs = zone.resolve("_dmarc.example.com", TYPE["TXT"], "TXT")
        self.assertEqual(rcode, RCODE_NOERROR)
        self.assertEqual(len(rrs), 2)

    def test_names_are_matched_case_insensitively_and_without_trailing_dot(self):
        zone = TxtZone({"Sel._DomainKey.Example.COM.": "v=DKIM1"})
        rcode, _ = zone.resolve("sel._domainkey.example.com", TYPE["TXT"], "TXT")
        self.assertEqual(rcode, RCODE_NOERROR)

    def test_absent_name_is_nxdomain_not_empty_noerror(self):
        # NOERROR-with-no-answer says the name exists without a record, which
        # RFC 6376 6.1.2 treats differently from "does not exist".
        zone = TxtZone({})
        self.assertEqual(zone.resolve("nope.example.com", TYPE["TXT"], "TXT"),
                         (RCODE_NXDOMAIN, []))

    def test_non_txt_query_is_nxdomain_even_for_a_held_name(self):
        zone = TxtZone({"a.example.com": "v=DKIM1"})
        self.assertEqual(zone.resolve("a.example.com", TYPE["A"], "A")[0],
                         RCODE_NXDOMAIN)

    def test_timeout_sentinel_answers_nothing(self):
        zone = TxtZone({"a.example.com": TIMEOUT})
        self.assertEqual(zone.resolve("a.example.com", TYPE["TXT"], "TXT"),
                         (None, []))


class WireEncoding(unittest.TestCase):
    def test_long_value_splits_into_several_character_strings(self):
        # A 2048-bit RSA key record does not fit in one character-string, so
        # this is the path every real key takes -- and the path that catches a
        # resolver reading only the first string.
        value = "v=DKIM1; p=" + "A" * 400
        parts = txt_strings(dnsfake.txt_rdata(value))
        self.assertEqual(len(parts), 2)
        self.assertEqual(len(parts[0]), 255)
        self.assertEqual(b"".join(parts).decode(), value)

    def test_list_value_is_several_character_strings_in_one_record(self):
        # RFC 7208 3.3: a verifier must join these with no separator. Distinct
        # from a list in TxtZone, which is several separate records.
        parts = txt_strings(dnsfake.txt_rdata(["v=spf1 ", "-all"]))
        self.assertEqual(parts, [b"v=spf1 ", b"-all"])

    def test_empty_value_is_one_empty_character_string(self):
        # A revoked DKIM key is `p=` with nothing after it, and the record must
        # still exist -- an empty rdata would be a malformed answer.
        self.assertEqual(dnsfake.txt_rdata(""), b"\x00")

    def test_name_round_trips(self):
        encoded = dnsfake.encode_name("sel._domainkey.example.com")
        name, offset = dnsfake.decode_name(encoded, 0)
        self.assertEqual(name, "sel._domainkey.example.com")
        self.assertEqual(offset, len(encoded))

    def test_compression_loop_raises_rather_than_spinning(self):
        # A pointer at offset 0 aiming at offset 0. Without the guard the server
        # thread never returns.
        with self.assertRaises(ValueError):
            dnsfake.decode_name(b"\xc0\x00", 0)

    def test_unsupported_type_raises_so_the_server_can_skip_it(self):
        with self.assertRaises(ValueError):
            dnsfake.rdata_for("SOA", "whatever")


class RecordZoneSentinels(unittest.TestCase):
    def test_timeout_covers_only_types_the_zone_does_not_answer(self):
        # The suite writes "the SPF record is returned but the TXT query hangs"
        # this way. Timing out every type would make that case unreachable.
        zone = RecordZone({"example.com": [{"SPF": "v=spf1 -all"}, "TIMEOUT"]})
        self.assertEqual(zone.resolve("example.com", TYPE["SPF"], "SPF")[0],
                         RCODE_NOERROR)
        self.assertEqual(zone.resolve("example.com", TYPE["TXT"], "TXT"),
                         (None, []))

    def test_type_none_means_absent_not_a_record_saying_NONE(self):
        zone = RecordZone({"example.com": [{"TXT": "NONE"}, {"A": "192.0.2.1"}]})
        rcode, rrs = zone.resolve("example.com", TYPE["TXT"], "TXT")
        self.assertEqual((rcode, rrs), (RCODE_NOERROR, []))

    def test_spf_records_are_duplicated_to_txt_on_request(self):
        zone = RecordZone({"example.com": [{"SPF": "v=spf1 -all"}]},
                          duplicate_spf_to_txt=True)
        rcode, rrs = zone.resolve("example.com", TYPE["TXT"], "TXT")
        self.assertEqual(rcode, RCODE_NOERROR)
        self.assertEqual([v for _, _, v in rrs], ["v=spf1 -all"])

    def test_duplication_never_overwrites_an_explicit_txt(self):
        # Where the suite gives both, it is testing which one wins.
        zone = RecordZone({"example.com": [{"SPF": "v=spf1 -all"},
                                           {"TXT": "v=spf1 +all"}]},
                          duplicate_spf_to_txt=True)
        _rcode, rrs = zone.resolve("example.com", TYPE["TXT"], "TXT")
        self.assertEqual([v for _, _, v in rrs], ["v=spf1 +all"])

    def test_duplication_respects_txt_none(self):
        # Synthesising a TXT here would contradict the thing under test.
        zone = RecordZone({"example.com": [{"SPF": "v=spf1 -all"},
                                           {"TXT": "NONE"}]},
                          duplicate_spf_to_txt=True)
        self.assertEqual(zone.resolve("example.com", TYPE["TXT"], "TXT")[1], [])

    def test_cname_chain_is_followed_and_included_in_the_answer(self):
        zone = RecordZone({"a.example.com": [{"CNAME": "b.example.com"}],
                           "b.example.com": [{"TXT": "v=spf1 -all"}]})
        rcode, rrs = zone.resolve("a.example.com", TYPE["TXT"], "TXT")
        self.assertEqual(rcode, RCODE_NOERROR)
        self.assertEqual([(n, t) for n, t, _ in rrs],
                         [("a.example.com", "CNAME"), ("b.example.com", "TXT")])

    def test_cname_loop_is_bounded(self):
        zone = RecordZone({"a.example.com": [{"CNAME": "b.example.com"}],
                           "b.example.com": [{"CNAME": "a.example.com"}]})
        rcode, rrs = zone.resolve("a.example.com", TYPE["TXT"], "TXT")
        self.assertLessEqual(len(rrs), 9)
        self.assertIn(rcode, (RCODE_NOERROR, RCODE_NXDOMAIN))

    def test_unknown_query_type_is_empty_noerror_not_nxdomain(self):
        zone = RecordZone({"example.com": [{"TXT": "v=spf1 -all"}]})
        self.assertEqual(zone.resolve("example.com", 65535, None),
                         (RCODE_NOERROR, []))


class ServerOverTheWire(unittest.TestCase):
    """End to end through a real UDP socket, which is how the daemons see it."""

    def ask(self, dns, name, qtype=TYPE["TXT"]):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(query_packet(name, qtype), ("127.0.0.1", dns.port))
            return parse_reply(sock.recvfrom(4096)[0])
        finally:
            sock.close()

    def test_answers_a_txt_query(self):
        with DnsFake(TxtZone({"a.example.com": "v=DKIM1; p=xyz"})) as dns:
            rcode, ancount, rdatas = self.ask(dns, "a.example.com")
            self.assertEqual((rcode, ancount), (RCODE_NOERROR, 1))
            self.assertEqual(b"".join(txt_strings(rdatas[0])), b"v=DKIM1; p=xyz")

    def test_servfail_reaches_the_wire_as_servfail(self):
        with DnsFake(TxtZone({"a.example.com": SERVFAIL})) as dns:
            self.assertEqual(self.ask(dns, "a.example.com")[0], RCODE_SERVFAIL)

    def test_timeout_sends_nothing_at_all(self):
        with DnsFake(TxtZone({"a.example.com": TIMEOUT})) as dns:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            try:
                sock.sendto(query_packet("a.example.com"), ("127.0.0.1", dns.port))
                with self.assertRaises(socket.timeout):
                    sock.recvfrom(4096)
            finally:
                sock.close()

    def test_port_is_readable_before_start(self):
        # The RFC 7208 suite binds port 0 and hands the allocated port to the
        # daemon under test, so it must be known before the thread runs.
        dns = DnsFake(TxtZone({}))
        self.assertGreater(dns.port, 0)
        dns.stop()

    def test_query_log_records_txt_queries_in_order(self):
        # RFC 9989 4.10 makes the sequence of queried names part of the expected
        # output, not incidental traffic.
        zone = TxtZone({"_dmarc.a.b.example.com": "v=DMARC1; p=none"})
        with DnsFake(zone) as dns:
            self.ask(dns, "_dmarc.a.b.example.com")
            self.ask(dns, "_dmarc.b.example.com")
            self.ask(dns, "_dmarc.a.b.example.com")
            self.assertEqual(dns.query_log(), ["_dmarc.a.b.example.com",
                                               "_dmarc.b.example.com",
                                               "_dmarc.a.b.example.com"])
            self.assertEqual(dns.distinct_queries(), ["_dmarc.a.b.example.com",
                                                      "_dmarc.b.example.com"])

    def test_non_txt_queries_stay_out_of_the_log(self):
        with DnsFake(RecordZone({"example.com": [{"A": "192.0.2.1"}]})) as dns:
            self.ask(dns, "example.com", TYPE["A"])
            self.assertEqual(dns.query_log(), [])

    def test_set_zone_swaps_records_and_clears_the_log(self):
        dns = DnsFake(TxtZone({"a.example.com": "first"}), verbose=False).start()
        try:
            self.ask(dns, "a.example.com")
            dns.set_zone(TxtZone({"a.example.com": "second"}))
            _rcode, _n, rdatas = self.ask(dns, "a.example.com")
            self.assertEqual(b"".join(txt_strings(rdatas[0])), b"second")
            self.assertEqual(dns.query_log(), ["a.example.com"])
        finally:
            dns.stop()

    def test_a_record_is_served_as_four_octets(self):
        with DnsFake(RecordZone({"example.com": [{"A": "192.0.2.1"}]})) as dns:
            _rcode, _n, rdatas = self.ask(dns, "example.com", TYPE["A"])
            self.assertEqual(rdatas[0], socket.inet_aton("192.0.2.1"))

    def test_unencodable_record_is_skipped_rather_than_killing_the_answer(self):
        zone = RecordZone({"example.com": [{"SOA": "ns hostmaster 1 2 3 4 5"}]})
        with DnsFake(zone) as dns:
            rcode, ancount, _ = self.ask(dns, "example.com", TYPE["SOA"])
            self.assertEqual((rcode, ancount), (RCODE_NOERROR, 0))

    def test_server_thread_stops(self):
        dns = DnsFake(TxtZone({})).start()
        dns.stop()
        self.assertNotIn(dns.thread, threading.enumerate())


if __name__ == "__main__":
    unittest.main(verbosity=2)
