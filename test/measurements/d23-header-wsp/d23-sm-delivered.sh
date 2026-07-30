#!/bin/sh
# What sendmail finally WRITES, as opposed to what it handed the milter.
# Delivered to a file via a fresh recipient so the bytes are unambiguous.
set -u
BASE=/root/rm
. "$BASE/lab.conf"

jexec milter-receiver sh -c 'pw usermod root -m 2>/dev/null; true'
jexec milter-receiver sh -c 'rm -f /var/mail/root'

python3.12 "$BASE/d23-mkmsg.py" d23-sm-delivered "d23@bambania.com" "root@localhost" >/dev/null

perl -e '
use strict; use warnings; use IO::Socket::INET;
my ($host, $port, $file) = @ARGV;
my $s = IO::Socket::INET->new(PeerAddr=>$host, PeerPort=>$port, Proto=>"tcp", Timeout=>10) or die "connect: $!\n";
sub rd { my $l = <$s>; while (defined $l && $l =~ /^\d\d\d-/) { $l = <$s>; } return $l // ""; }
rd();
print $s "HELO probe.pentest\r\n"; rd();
print $s "MAIL FROM:<d23\@bambania.com>\r\n"; rd();
print $s "RCPT TO:<root\@localhost>\r\n"; rd();
print $s "DATA\r\n"; rd();
open my $fh, "<:raw", $file or die $!;
my $m = do { local $/; <$fh> };
$m =~ s/\r?\n/\r\n/g;
print $s $m, "\r\n.\r\n";
print "  DATA: ", rd();
print $s "QUIT\r\n";
' "$RECV_IP" 2526 /tmp/d23.eml 2>&1

sleep 4
echo
echo "=== DELIVERED by SENDMAIL (mailbox bytes, as hex)"
jexec milter-receiver cat /var/mail/root 2>/dev/null > /tmp/d23-smbox
python3.12 - /tmp/d23-smbox <<'PY'
import sys
raw = open(sys.argv[1], 'rb').read()
if not raw:
    print("  EMPTY -- delivery did not land"); raise SystemExit
for line in raw.replace(b'\r\n', b'\n').split(b'\n'):
    if line.startswith(b'X-D23'):
        n, _, rest = line.partition(b':')
        print(f"  name=[{n.decode()}] sep+value_len={len(rest)} hex=[{rest.hex()}]")
PY
