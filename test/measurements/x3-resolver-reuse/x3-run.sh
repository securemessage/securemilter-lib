#!/bin/sh
# X-3: does a per-worker DNS resolver actually reuse its cache across messages?
#
# Runs on the vnet jail host as root.
#
# THE QUESTION. X-3 said every daemon built a resolver per message and destroyed
# it afterwards, so the TTL cache and the negative cache never survived to be
# used. The fix makes the resolver thread-local per worker. "It compiles and the
# tests pass" does not answer whether the cache is now reused -- only counting
# the queries that leave the daemon does.
#
# THE INSTRUMENT. Count DNS query packets on the wire leaving the receiver jail,
# with tcpdump on the bridge. Not Unbound's own counters: Unbound answers most of
# these from its cache, so its "recursion" numbers would be near zero either way,
# and unbound-control is not enabled here. What X-3 is about is how many queries
# the DAEMON emits, and that is exactly one packet each on the wire.
#
# HOW TO READ IT. N identical messages are sent -- same sender domain, same DKIM
# selector, same everything -- so every lookup after the first is a repeat that a
# working cache must absorb.
#
#   before the fix   queries scale with N. Nothing is remembered between
#                    messages, so message 5 costs exactly what message 1 did.
#   after the fix    queries flatten. The first message through each worker pays
#                    the cold cost and the rest are served from memory.
#
# WHY THE FLOOR IS NOT 1x. WorkerThreads=2 in this lab and Postfix spreads
# connections across both workers, so up to TWO cold sets are expected -- one per
# worker thread, each with its own cache. A result of "2 cold sets for N=6" is
# the correct outcome, not a partial fix. Anything that still scales with N means
# the resolver is not being reused.
#
# TTL is the other thing that could flatten or un-flatten this dishonestly, so
# the messages are sent back to back: the lab zone's records must not expire
# mid-run or the second half would re-query for reasons unrelated to the fix.

set -eu

BASE=${BASE:-/root/rm}
. "$BASE/lab.conf"
: "${LAB_CONF_VERSION:?stale lab.conf: re-copy test/pentest/lab.conf to $BASE}"
lab_require_host

N=${N:-6}
IFACE=${IFACE:-bridge0}
OUT=${OUT:-/root/rm/results/x3-$(date +%s)}
mkdir -p "$OUT"

RCPT=${RCPT:-testuser@$LAB_DOMAIN}

echo "=== X-3 resolver reuse: $N identical messages, counting DNS queries from $RECV_IP"
echo

# One message, reused for every send: identical by construction, so any variation
# in query count is the daemons' doing and not the message's.
MSG=$OUT/msg.eml
NONCE=$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')
{
    printf 'From: boss@%s\n' "$LAB_DOMAIN"
    printf 'To: %s\n' "$RCPT"
    printf 'Subject: x3-%s\n' "$NONCE"
    printf 'Date: %s\n' "$(date -R)"
    printf 'Message-ID: <x3-%s@%s>\n' "$NONCE" "$LAB_DOMAIN"
    printf '\nx3 measurement\n'
} > "$MSG"

# Sign it once with the lab key so the DKIM path has a real signature to fetch a
# key for -- an unsigned message would exercise SPF and DMARC but leave the
# securedkim lookup, the one D-4 amplified, untouched.
SIGNED=$OUT/msg-signed.eml
perl "$BASE/dkimsign.pl" --key "$DKIM_KEY" --domain "$LAB_DOMAIN" \
    --selector "$DKIM_SELECTOR" --headers from:to:subject:date:message-id \
    --input "$MSG" > "$SIGNED"

# Count query packets only (not responses): src is the jail, dst port 53.
tcpdump -n -i "$IFACE" -w "$OUT/dns.pcap" \
    "udp and dst port 53 and src host $RECV_IP" >/dev/null 2>&1 &
TCPDUMP_PID=$!
# tcpdump needs to be listening before the first packet or the count is short.
sleep 2

i=1
while [ "$i" -le "$N" ]; do
    perl "$BASE/send.pl" "$RECV_IP" "boss@$LAB_DOMAIN" "$RCPT" "$SIGNED" x3.probe \
        > "$OUT/send-$i.log" 2>&1 || true
    printf '  sent %d/%d\n' "$i" "$N"
    i=$((i + 1))
done

# Let the last message's lookups finish before the capture stops.
sleep 3
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

TOTAL=$(tcpdump -n -r "$OUT/dns.pcap" 2>/dev/null | wc -l | tr -d ' ')

echo
echo "--- every query, by name ($TOTAL packets for $N messages):"
tcpdump -n -r "$OUT/dns.pcap" 2>/dev/null |
    awk '{print $(NF-2), $(NF-1)}' | sort | uniq -c | sort -rn

# Not everything on the wire is a milter lookup, and counting the total would
# flatter or damn the fix for traffic it has nothing to do with:
#
#   NS? .      the DNS health monitor probing each configured nameserver on its
#              own timer. Independent of message volume, and deliberately not
#              cached -- its entire job is to keep asking.
#   PTR?       Postfix resolving the connecting client's reverse name, before
#              any milter is consulted.
#
# What X-3 governs is the TXT lookups the milters make: the SPF record, the DKIM
# public key, and the DMARC record.
echo
echo "--- the queries X-3 governs (want: flat in N, not $N)"
for q in "$LAB_DOMAIN." "$DKIM_SELECTOR._domainkey.$LAB_DOMAIN." "_dmarc.$LAB_DOMAIN."; do
    _c=$(tcpdump -n -r "$OUT/dns.pcap" 2>/dev/null | grep -c "TXT? $q" || true)
    case $q in
        _dmarc*) _who="securedmarc  (control: already per-worker since X-3 part 1)" ;;
        *_domainkey*) _who="securedkim" ;;
        *) _who="securespf" ;;
    esac
    printf '  %-46s %2s  %s\n' "$q" "$_c" "$_who"
done

echo
echo "A count of 1-2 is the expected PASS: WorkerThreads=2 means up to two cold"
echo "caches. A count equal to $N means the resolver is still per-message."
echo "evidence: $OUT"
