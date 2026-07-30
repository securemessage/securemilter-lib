#!/usr/bin/perl
# Drive a sign-mode securedkim listener and print what it actually did.
#
# The lab pentest suite only ever exercises the VERIFY side: it signs with
# dkimsign.pl and asks the daemon to check the result. Nothing in it asks the
# daemon to sign, which is why D-24 -- a documented signing config that signs
# nothing at all -- was invisible to 23 passing probes.
#
# This speaks the milter protocol directly and decodes the end-of-message
# modification packets, so the answer to "did it sign, and with what" comes from
# the wire rather than from a log line the daemon may never write.
#
# Usage: d24-sign.pl <host> <port> <mail-from> [from-header]
#
# Prints one ADDHEADER/INSHEADER line per modification, then the final action.

use strict;
use warnings;
use IO::Socket::INET;

my ($host, $port, $mail_from, $from_hdr) = @ARGV;
die "usage: d24-sign.pl <host> <port> <mail-from> [from-header]\n"
    unless defined $host && defined $port && defined $mail_from;
$from_hdr //= $mail_from;

$SIG{ALRM} = sub { print "RESULT: watchdog timeout\n"; exit 124 };
alarm 60;

my $s = IO::Socket::INET->new(
    PeerHost => $host, PeerPort => $port, Proto => 'tcp', Timeout => 10,
) or die "connect $host:$port: $!\n";
$s->autoflush(1);
binmode $s;

sub put {
    my ($cmd, $payload) = @_;
    $payload //= '';
    print $s pack('N', 1 + length $payload) . $cmd . $payload;
}

sub get {
    my $hdr = '';
    while (length($hdr) < 4) {
        my $n = read($s, my $buf, 4 - length $hdr);
        return () unless $n;
        $hdr .= $buf;
    }
    my $len = unpack('N', $hdr);
    return () if $len < 1;
    my $body = '';
    while (length($body) < $len) {
        my $n = read($s, my $buf, $len - length $body);
        return () unless $n;
        $body .= $buf;
    }
    return (substr($body, 0, 1), substr($body, 1));
}

# Ask for every action (ADDHDRS included) and no protocol opt-outs, so the
# daemon has no excuse not to send us its header modifications.
put('O', pack('NNN', 6, 0x1FF, 0));
my ($oc, $od) = get();
die "no optneg reply\n" unless defined $oc;
printf "OPTNEG: reply=%s actions=0x%x protocol=0x%x\n", $oc,
    unpack('N', substr($od, 4, 4)), unpack('N', substr($od, 8, 4));

put('C', "localhost\0" . pack('C', 4) . pack('n', 25) . "127.0.0.1\0");
get();
put('H', "sender.test\0");
get();
put('M', "<$mail_from>\0");
get();
put('R', "<rcpt\@example.net>\0");
get();

for my $h (
    [ 'From',    "<$from_hdr>" ],
    [ 'To',      '<rcpt@example.net>' ],
    [ 'Subject', 'D-24 signing resolution probe' ],
    [ 'Date',    'Thu, 30 Jul 2026 12:00:00 +0000' ],
    [ 'Message-ID', '<d24probe@sender.test>' ],
) {
    put('L', "$h->[0]\0$h->[1]\0");
    get();
}
put('N');
get();
put('B', "D-24 probe body.\r\n");
get();
put('E');

# Everything interesting happens here: modification packets, then a final action.
my $mods = 0;
while (my ($c, $d) = get()) {
    if ($c eq 'h') {                          # SMFIR_ADDHEADER
        my ($name, $value) = split /\0/, $d, 2;
        $value =~ s/\0$//;
        $mods++;
        print "ADDHEADER: $name:$value\n";
    } elsif ($c eq 'i') {                     # SMFIR_INSHEADER
        my $idx = unpack('N', substr($d, 0, 4));
        my ($name, $value) = split /\0/, substr($d, 4), 2;
        $value =~ s/\0$//;
        $mods++;
        print "INSHEADER[$idx]: $name:$value\n";
    } elsif ($c eq 'c' || $c eq 'a' || $c eq 'r' || $c eq 'd' || $c eq 't') {
        print "FINAL: $c\n";
        last;
    } else {
        print "OTHER: $c\n";
    }
}
print "RESULT: modifications=$mods\n";
close $s;
