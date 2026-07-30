#!/bin/sh
# Drive sendmail (port 2526 on the jail IP) from the lab host, same probe message.
set -u

BASE=/root/rm
. "$BASE/lab.conf"

TAG=${1:-d23-sendmail-1}
python3.12 "$BASE/d23-mkmsg.py" "$TAG" "d23@bambania.com" "testuser@localhost" >/dev/null || exit 1

MARK=$(wc -l < "$MAILLOG" | tr -d ' ')

perl -e '
use strict; use warnings; use IO::Socket::INET;
my ($host, $port, $file) = @ARGV;
my $s = IO::Socket::INET->new(PeerAddr=>$host, PeerPort=>$port, Proto=>"tcp", Timeout=>10)
    or die "connect $host:$port: $!\n";
sub rd { my $l = <$s>; while (defined $l && $l =~ /^\d\d\d-/) { $l = <$s>; } return $l // ""; }
rd();
print $s "HELO probe.pentest\r\n"; rd();
print $s "MAIL FROM:<d23\@bambania.com>\r\n"; rd();
print $s "RCPT TO:<testuser\@localhost>\r\n"; rd();
print $s "DATA\r\n"; rd();
open my $fh, "<:raw", $file or die "$file: $!\n";
my $m = do { local $/; <$fh> };
$m =~ s/\r?\n/\r\n/g;
print $s $m;
print $s "\r\n.\r\n";
print "  sendmail DATA response: ", rd();
print $s "QUIT\r\n";
' "$RECV_IP" 2526 /tmp/d23.eml 2>&1

sleep 3
echo
echo "=== RECEIVED by the milter, from SENDMAIL (SMFIC_HEADER value, as hex)"
tail -n "+$((MARK + 1))" "$MAILLOG" | grep 'D23MEAS' | sed 's/.*D23MEAS //'
