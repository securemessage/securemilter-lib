#!/bin/sh
# Stand up FreeBSD base sendmail on a spare port, pointed at the same milter
# Postfix is using, so the two MTAs answer the same question with the same
# instrumented daemon on the other end.
#
# sendmail is the reference implementation of the milter API, so its behaviour is
# what SMFIP_HDR_LEADSPC is defined against. Postfix reimplements the protocol and
# could reasonably differ -- which is the whole reason both are measured.
set -u

JAIL=milter-receiver
PORT=2526

jexec "$JAIL" sh -c 'cat > /etc/mail/d23.mc' <<'MC'
divert(-1)
include(`/usr/share/sendmail/cf/m4/cf.m4')
divert(0)
VERSIONID(`D-23 measurement config')
OSTYPE(freebsd6)
DOMAIN(generic)
define(`confDONT_PROBE_INTERFACES', `True')
define(`confQUEUE_LA', `99')
define(`confREFUSE_LA', `99')
FEATURE(`no_default_msa')
INPUT_MAIL_FILTER(`d23', `S=inet:8890@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
DAEMON_OPTIONS(`Port=2526, Name=MTA-d23, Addr=127.0.0.1')
MAILER(local)
MAILER(smtp)
MC

echo "=== building d23.cf"
jexec "$JAIL" sh -c 'cd /etc/mail && make d23.cf 2>&1 | tail -3'
jexec "$JAIL" ls -la /etc/mail/d23.cf 2>/dev/null || { echo "  .cf BUILD FAILED"; exit 1; }

echo "=== starting sendmail on 127.0.0.1:$PORT"
jexec "$JAIL" /usr/libexec/sendmail/sendmail -bd -C/etc/mail/d23.cf -ODaemonPortOptions=Port=$PORT,Addr=127.0.0.1
sleep 2
jexec "$JAIL" sockstat -4l 2>/dev/null | grep ":$PORT " || echo "  NOT LISTENING"
