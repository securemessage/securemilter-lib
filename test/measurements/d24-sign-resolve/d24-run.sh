#!/bin/sh
# D-24 reproduction: does a SigningTable/KeyTable config actually sign?
#
# Three configs, one question each. The discriminator for "which key signed
# this" is KEY SIZE, not the d= tag the daemon prints: a.example gets a 2048-bit
# key and b.example a 3072-bit one, so an RSA signature is 344 base64 chars for
# a and 512 for b. That makes "it claimed d=b.example but signed with a's key"
# arithmetic rather than a matter of trusting the header.
#
# The DAEMON runs inside the sender jail and the CLIENT on the host, because
# neither can host both: the jails carry the OpenSSL the binary links against
# (libcrypto.so.12, absent on the host) and the host carries perl (absent in the
# jails). Same split D-23 settled on, for the same two reasons.
#
# Because the jails are VNET, bind the jail's own address -- 127.0.0.1 inside a
# VNET jail is not the host's loopback and is unreachable from outside it.
#
# Usage: d24-run.sh [jail] [jail-ip]

set -e
JAIL="${1:-milter-sender}"
IP="${2:-10.99.0.1}"
BIN=/usr/local/sbin/securedkim      # path INSIDE the jail
JD=/root/d24                        # working dir, jail view
D="/Storage/Jails/$JAIL$JD"         # same dir, host view
PORT=8899

mkdir -p "$D/keys"

# --- keys: deliberately different sizes, that is the whole trick -------------
if [ ! -f "$D/keys/a.key" ]; then
    openssl genrsa -out "$D/keys/a.key" 2048 2>/dev/null
    openssl genrsa -out "$D/keys/b.key" 3072 2>/dev/null
    echo "keys: a.example=2048-bit (b= is 344 b64 chars), b.example=3072-bit (512 chars)"
fi

cat > "$D/signing-table" <<EOF
*@b.example  b.example
EOF

# Paths inside the config are the JAIL's view, not the host's.
cat > "$D/key-table" <<EOF
b.example  b.example:selb:$JD/keys/b.key
EOF

mkcfg() {
    _name=$1; shift
    {
        echo "[global]"
        # Foreground, so the pid we background IS the daemon. Without this the
        # parent forks and exits, `kill $!` reaps a corpse, and the real daemon
        # keeps the port -- the same teardown trap sendmail sprang during D-23.
        echo "Foreground = true"
        echo "Syslog = false"
        echo "PidFile = $JD/securedkim.pid"
        echo "[listener:sign]"
        echo "Socket = inet:$PORT@$IP"
        echo "Mode = sign"
        for line in "$@"; do echo "$line"; done
    } > "$D/$_name.conf"
}

mkcfg shorthand "Domain = a.example" "Selector = sela" "KeyFile = $JD/keys/a.key"
mkcfg tableonly "SigningTable = $JD/signing-table" "KeyTable = $JD/key-table"
mkcfg mixed \
    "Domain = a.example" "Selector = sela" "KeyFile = $JD/keys/a.key" \
    "SigningTable = $JD/signing-table" "KeyTable = $JD/key-table"

probe() {
    _cfg=$1; _from=$2; _label=$3
    echo
    echo "=== $_label"
    echo "--- config: $(grep -vE '^\[|^$' "$D/$_cfg.conf" | grep -vE 'Socket|Mode|Syslog' | tr '\n' ';')"
    jexec "$JAIL" "$BIN" -c "$JD/$_cfg.conf" > "$D/$_cfg.log" 2>&1 &
    _pid=$!
    # Wait for the listener rather than sleeping blind.
    _i=0
    while [ $_i -lt 50 ]; do
        jexec "$JAIL" sockstat -4l 2>/dev/null | grep -q ":$PORT" && break
        _i=$((_i + 1)); sleep 0.1
    done
    perl /root/rm/signclient.pl "$IP" "$PORT" "$_from" || true
    echo "--- daemon log: $(wc -l < "$D/$_cfg.log" | tr -d ' ') lines"
    grep -iE 'sign|key|table|error|warn' "$D/$_cfg.log" | sed 's/^/    /' || echo "    (nothing about signing)"
    kill "$_pid" 2>/dev/null || true
    wait "$_pid" 2>/dev/null || true
    # Prove it: a listener left behind would silently poison the next probe.
    if jexec "$JAIL" sockstat -4l 2>/dev/null | grep -q ":$PORT"; then
        echo "    WARNING: port $PORT still listening after teardown"
        jexec "$JAIL" pkill -f "$JD/$_cfg.conf" 2>/dev/null || true
    fi
}

probe shorthand "user@a.example" "CONTROL: shorthand Domain/KeyFile, sender matches"
probe tableonly "user@b.example" "CASE (a): SigningTable+KeyTable only, no KeyFile"
probe mixed     "user@b.example" "CASE (b): both configured, sender hits the TABLE not the shorthand"

# --- the other half: configs that can never sign must REFUSE, not start quietly --
#
# Fixing the resolution is only half of D-24. The reason it went unnoticed is that
# a broken signing config started cleanly, so these check the daemon now declines
# and names the problem. Each of them started fine and signed nothing before.

cat > "$D/bad-entry-table" <<EOF
*@c.example  c.example
EOF

mkcfg no_keytable "SigningTable = $JD/signing-table"
mkcfg no_signtable "KeyTable = $JD/key-table"
mkcfg missing_entry "SigningTable = $JD/bad-entry-table" "KeyTable = $JD/key-table"
mkcfg missing_keyfile "SigningTable = $JD/signing-table" "KeyTable = $JD/absent-key-table"

cat > "$D/absent-key-table" <<EOF
b.example  b.example:selb:$JD/keys/does-not-exist.key
EOF

refuses() {
    _cfg=$1; _label=$2
    echo
    echo "=== REFUSAL: $_label"
    if jexec "$JAIL" "$BIN" -c "$JD/$_cfg.conf" > "$D/$_cfg.log" 2>&1; then
        echo "    NOT REFUSED -- daemon started. This is the D-24 silence."
    else
        echo "    exit=$? (refused)"
    fi
    # Show every line the daemon logged, not a keyword guess. The first pass
    # filtered on words like "cannot" and hid a message that said "nothing can be
    # signed" -- a harness that quietly drops the evidence is worse than none.
    grep '^securedkim' "$D/$_cfg.log" | sed 's/^/    /' \
        || echo "    REFUSED BUT SAID NOTHING -- as bad as starting"
}

refuses no_keytable    "SigningTable with no KeyTable"
refuses no_signtable   "KeyTable with no SigningTable"
refuses missing_entry  "SigningTable entry the KeyTable does not define"
refuses missing_keyfile "KeyTable row whose key file is absent"

echo
echo "=== how to read this"
echo "control  : expect a DKIM-Signature, d=a.example, b= 344 chars"
echo "case (a) : defect if modifications=0 AND the log says nothing"
echo "case (b) : defect if d=b.example but b= is 344 chars (a's 2048-bit key)"
