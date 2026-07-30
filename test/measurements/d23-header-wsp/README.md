# D-23: what does an MTA hand a milter, and what does it deliver?

A one-off measurement, kept because an audit severity now rests on it. If Postfix or
sendmail change this behaviour, the rating in `AUDIT-REPORT.md` §6 (D-23) and §11.40
becomes wrong, and this is how you find out.

## The question

`securedkim` and `securearc` rebuild each header field as `name + ": " + value`,
because a milter is handed a name and a value rather than the field's original octets.
`c=simple` hashes the field verbatim, so any difference between the reconstruction and
the delivered bytes breaks the signature.

The severity was blocked on one unmeasured fact: **does the MTA strip one leading
whitespace character, or all of it?** An earlier working note asserted "all". It was
never tested, and it is wrong.

## The result — Postfix 3.11.5 and FreeBSD base sendmail, byte-identical

Without `SMFIP_HDR_LEADSPC`, which is what ships today:

| sent after `:`  | milter receives | MTA delivers after `:` | our `": " + value` |
|-----------------|-----------------|------------------------|--------------------|
| *(nothing)*     | `zero`          | `zero`                 | **mismatch**       |
| `·`             | `one`           | `·one`                 | match              |
| `··`            | `·two`          | `··two`                | match              |
| `···`           | `··three`       | `···three`             | match              |
| `→`             | `→tab`          | `→tab`                 | **mismatch**       |
| `·→·`           | `→·sptabsp`     | `·→·sptabsp`           | match              |
| *(nothing)*, empty | *(empty)*    | *(empty)*              | **mismatch**       |
| `·`, empty      | *(empty)*       | `·`                    | match              |
| `··`, empty     | `·`             | `··`                   | match              |

`·` = SP (0x20), `→` = HTAB (0x09).

**The rule: exactly one leading SP is stripped, if and only if one is present. A TAB is
never stripped. Delivered output is verbatim — neither MTA normalises the field.**

So the reconstruction is correct whenever the original had at least one leading space,
and wrong in two shapes: no whitespace at all after the colon, and leading whitespace
that begins with a tab. The empty-value case already on file is a sub-case of the first.

**The lost information is exactly one bit per header** — "was there a leading space?" —
and it is genuinely unrecoverable, not merely inconvenient: `Name:value` and
`Name:·value` arrive at the milter as byte-identical values.

## The fix's precondition, also measured

Both MTAs **offer** `SMFIP_HDR_LEADSPC` (`offered_protocol=0x001fffff`, bit 20) and both
**agree** to it when asked. With the flag negotiated, the received value matched the
delivered bytes exactly in all nine shapes above. So `c=simple` can be made faithful,
and the fix is to negotiate the flag and stop fabricating the separator.

That was worth measuring rather than reading: §11.27 records the last time a confident
claim about milter capability in this codebase turned out to be wrong.

## Running it again

Needs the lab (`vnet.morante.com`) and a **temporarily instrumented** daemon — the
shipping build does not log header octets, and should not. Two blocks, both reverted
after the measurement:

- `worker.zig` `handleHeader` — hex-dump `hdr.value` for names starting `X-D23`.
- `worker.zig` `handleOptneg` — log the MTA's offered protocol mask and the agreed one.

To measure the flag's effect, also set `.header_leading_space = true` in the daemon's
`skip_flags`.

Then:

```
scp d23-*.{py,sh} root@vnet:/root/rm/
/root/rm/d23-run.sh          # Postfix, both sides
/root/rm/d23-sendmail.sh     # stand sendmail up on 2526 against the same milter
/root/rm/d23-sm2.sh          # sendmail, received side
/root/rm/d23-sm-delivered.sh # sendmail, delivered side
```

Tear down afterwards: kill the sendmail daemons **by pid** — it rewrites its argv to
`sendmail: accepting connections`, so `pkill -f d23.cf` does not match it — remove
`/etc/mail/d23.{mc,cf}`, redeploy the shipping binary, and re-run the pentest suite to
confirm the lab is back where it started.
