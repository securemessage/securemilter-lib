#!/bin/sh
# D-23 measurement: what does the MTA hand a milter, and what does it deliver?
#
# Two observations per header, and the pair is the point:
#
#   RECEIVED  the octets the milter was given   (from the instrumented daemon's log)
#   DELIVERED the octets the MTA finally wrote  (from the Maildir file)
#
# Our signing code reconstructs `name + ": " + value` from RECEIVED. If that
# reconstruction does not reproduce DELIVERED, a c=simple signature we generate
# cannot verify against the message a receiver actually sees -- and the width of
# that gap is exactly the severity question D-23 is blocked on.
set -u

BASE=/root/rm
. "$BASE/lab.conf"

TAG=${1:-d23-postfix-1}

python3.12 "$BASE/d23-mkmsg.py" "$TAG" "d23@bambania.com" "$RCPT" >/dev/null || exit 1

MARK=$(wc -l < "$MAILLOG" | tr -d ' ')
ls -1 "$MAILDIR" 2>/dev/null | sort > /tmp/d23-mark

perl "$BASE/send.pl" "$RECV_IP" "d23@bambania.com" "$RCPT" /tmp/d23.eml probe.pentest >/dev/null 2>&1

i=0
while [ "$i" -lt 20 ]; do
    NEW=$(ls -1 "$MAILDIR" 2>/dev/null | sort | comm -13 /tmp/d23-mark -)
    [ -n "$NEW" ] && break
    sleep 1
    i=$((i + 1))
done

echo "=== RECEIVED by the milter (SMFIC_HEADER value, as hex)"
tail -n "+$((MARK + 1))" "$MAILLOG" | grep 'D23MEAS' | sed 's/.*D23MEAS //'

echo
echo "=== DELIVERED by the MTA (Maildir bytes, as hex)"
if [ -z "$NEW" ]; then
    echo "  NO DELIVERY -- measurement incomplete"
    exit 1
fi
for f in $NEW; do
    python3.12 - "$MAILDIR/$f" <<'PY'
import sys
raw = open(sys.argv[1], 'rb').read()
head = raw.split(b'\r\n\r\n', 1)[0].split(b'\n\n', 1)[0]
for line in head.replace(b'\r\n', b'\n').split(b'\n'):
    if line.startswith(b'X-D23'):
        name, _, rest = line.partition(b':')
        print(f"  name=[{name.decode()}] sep+value_len={len(rest)} hex=[{rest.hex()}]")
PY
done
