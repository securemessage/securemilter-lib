#!/bin/sh
# X-3: does SIGHUP actually drop the per-worker resolver?
#
# Runs on the vnet jail host as root.
#
# WHY THIS EXISTS SEPARATELY FROM x3-run.sh. That script proves the cache now
# survives across messages, which is the benefit. This one proves the cache can
# still be got rid of, which is the safety property that benefit is traded
# against -- and it is the half that is easy to get wrong and impossible to
# notice. A resolver that is never dropped passes x3-run.sh perfectly while
# quietly serving answers from nameservers the operator has already removed from
# the config, for as long as the daemon runs.
#
# The reload hook that drops it is new code with no other test. Until this ran,
# "the resolver is dropped on SIGHUP" was a claim in a comment.
#
# THE SHAPE. Three phases against one unchanging message, counting queries for
# one name on the wire:
#
#   phase 1  first message      -> 1 query   (cold cache, has to ask)
#   phase 2  second message     -> 0 queries (warm cache, must not ask)
#   phase 3  SIGHUP, then send  -> 1 query   (cache dropped, has to ask again)
#
# Phase 2 is what makes phase 3 mean anything. Without it, a query in phase 3
# could just be a resolver that never caches at all, and the test would pass for
# precisely the wrong reason.

set -eu

BASE=${BASE:-/root/rm}
. "$BASE/lab.conf"
: "${LAB_CONF_VERSION:?stale lab.conf: re-copy test/pentest/lab.conf to $BASE}"
lab_require_host

IFACE=${IFACE:-bridge0}
OUT=${OUT:-/root/rm/results/x3reload-$(date +%s)}
mkdir -p "$OUT"
RCPT=${RCPT:-testuser@$LAB_DOMAIN}

# securespf's lookup is the cleanest probe of the three: exactly one TXT for the
# sender domain per uncached evaluation, no chain length or signature count to
# confound the count.
WATCH="TXT? $LAB_DOMAIN."
DAEMON=securespf

MSG=$OUT/msg.eml
NONCE=$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')
{
    printf 'From: boss@%s\n' "$LAB_DOMAIN"
    printf 'To: %s\n' "$RCPT"
    printf 'Subject: x3reload-%s\n' "$NONCE"
    printf 'Date: %s\n' "$(date -R)"
    printf 'Message-ID: <x3r-%s@%s>\n' "$NONCE" "$LAB_DOMAIN"
    printf '\nx3 reload measurement\n'
} > "$MSG"

# Start from a cold cache, or phase 1 measures nothing: a resolver still holding
# this name from an earlier run would make phase 1 look identical to phase 2.
echo "=== restarting $DAEMON in $RECV_JAIL for a known-cold cache"
jexec "$RECV_JAIL" pkill -f "/usr/local/sbin/$DAEMON " 2>/dev/null || true
sleep 1
jexec "$RECV_JAIL" /usr/sbin/daemon -f -p "/var/run/$DAEMON.pid" -t "$DAEMON" \
    "/usr/local/sbin/$DAEMON" -c "$MILTER_ETC/$DAEMON.conf"
sleep 2

send_one() {
    perl "$BASE/send.pl" "$RECV_IP" "boss@$LAB_DOMAIN" "$RCPT" "$MSG" x3r.probe \
        > "$OUT/send-$1.log" 2>&1 || true
}

# Count queries for $WATCH during one send.
phase() {
    _label=$1
    _pcap=$OUT/$1.pcap
    tcpdump -n -i "$IFACE" -w "$_pcap" \
        "udp and dst port 53 and src host $RECV_IP" >/dev/null 2>&1 &
    _td=$!
    sleep 2
    send_one "$_label"
    sleep 3
    kill "$_td" 2>/dev/null || true
    wait "$_td" 2>/dev/null || true
    tcpdump -n -r "$_pcap" 2>/dev/null | grep -c "$WATCH" || true
}

P1=$(phase p1-cold)
P2=$(phase p2-warm)

echo "=== SIGHUP $DAEMON"
_pid=$(jexec "$RECV_JAIL" pgrep -f "/usr/local/sbin/$DAEMON " | head -1)
[ -n "$_pid" ] || { echo "FAIL: $DAEMON not running, nothing to signal" >&2; exit 1; }
jexec "$RECV_JAIL" kill -HUP "$_pid"
# The hook runs when the worker next reaches the top of its loop; the reload
# wakes it, but give it room rather than racing the signal.
sleep 3

P3=$(phase p3-after-hup)

echo
printf 'phase 1  cold cache            %s query(ies)   want 1\n' "$P1"
printf 'phase 2  warm cache            %s query(ies)   want 0\n' "$P2"
printf 'phase 3  after SIGHUP          %s query(ies)   want 1\n' "$P3"
echo

if [ "$P1" -ge 1 ] && [ "$P2" -eq 0 ] && [ "$P3" -ge 1 ]; then
    echo "PASS: the cache is real (phase 2) and SIGHUP drops it (phase 3)"
elif [ "$P2" -ne 0 ]; then
    echo "FAIL: phase 2 queried again -- the resolver is not caching across"
    echo "      messages at all, so phase 3 proves nothing. X-3 is not done."
elif [ "$P3" -eq 0 ]; then
    echo "FAIL: phase 3 was served from cache -- SIGHUP did NOT drop the"
    echo "      resolver. A nameserver change would never take effect, and the"
    echo "      daemon would answer from a config the operator has replaced."
else
    echo "INCONCLUSIVE: phase 1 never queried; the cache was not cold to start."
fi
echo "evidence: $OUT"
