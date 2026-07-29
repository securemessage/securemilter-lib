#!/bin/sh
# Enforce the megaplan's 400-line-per-file code quality requirement.
#
#   check-line-limit.sh <srcdir> <allowlist>            check, exit 1 on violation
#   check-line-limit.sh <srcdir> <allowlist> --update   rewrite the allowlist
#
# The requirement existed from the start and drifted to 17 files in violation,
# the worst at 4.2x, because nothing checked it. A limit with no gate is a
# preference.
#
# This is a RATCHET, not an exemption list. Each allowlisted file carries its
# current line count as a personal ceiling, so an existing offender may not grow
# either. That distinction is the whole point: the most expensive drift was not a
# new file appearing over the limit, it was `evaluate.zig` going 434 -> 896 -> 1120
# while already over it. A plain list of exempt paths would have permitted every
# line of that.
#
# When a file drops below its recorded ceiling the check fails too, asking for the
# allowlist to be tightened. That is deliberate: a ratchet that only loosens is
# not a ratchet, and the alternative -- a warning nobody actions -- is how the
# original requirement was lost.
set -u

LIMIT=400

SRCDIR=${1:?usage: check-line-limit.sh <srcdir> <allowlist> [--update]}
ALLOWLIST=${2:?usage: check-line-limit.sh <srcdir> <allowlist> [--update]}
MODE=${3:-check}

[ -d "$SRCDIR" ] || { echo "not a directory: $SRCDIR" >&2; exit 2; }

# Allowlist format: "<ceiling> <path>", one per line, '#' comments ignored.
ceiling_for() {
    [ -f "$ALLOWLIST" ] || { echo ""; return; }
    awk -v want="$1" '$1 !~ /^#/ && $2 == want { print $1; found = 1 }
                      END { if (!found) print "" }' "$ALLOWLIST"
}

# Test files are excluded: a table-driven test legitimately grows with the number
# of cases it covers, and splitting one to satisfy a limit aimed at readability of
# production logic would be cargo-culting the rule against its own purpose.
list_sources() {
    find "$SRCDIR" -name '*.zig' ! -name '*_test.zig' | sort
}

if [ "$MODE" = "--update" ]; then
    tmp=$(mktemp)
    {
        echo "# Per-file line ceilings for files over the ${LIMIT}-line limit."
        echo "# A ratchet: these may shrink, never grow. Regenerate with"
        echo "#   zig build lint -- --update"
        echo "# An empty file below this header means the limit is met everywhere."
    } > "$tmp"
    list_sources | while IFS= read -r f; do
        n=$(grep -c "" "$f")
        [ "$n" -gt "$LIMIT" ] && echo "$n $f" >> "$tmp"
    done
    mv "$tmp" "$ALLOWLIST"
    echo "allowlist rewritten: $ALLOWLIST"
    exit 0
fi

violations=0
slack=0

for f in $(list_sources); do
    n=$(grep -c "" "$f")
    ceiling=$(ceiling_for "$f")

    if [ -z "$ceiling" ]; then
        # Not allowlisted, so the plain limit applies.
        if [ "$n" -gt "$LIMIT" ]; then
            echo "OVER LIMIT   $f: $n lines (limit $LIMIT)"
            violations=$((violations + 1))
        fi
        continue
    fi

    if [ "$n" -gt "$ceiling" ]; then
        echo "GREW         $f: $n lines, ceiling $ceiling"
        violations=$((violations + 1))
    elif [ "$n" -lt "$ceiling" ]; then
        echo "ratchet      $f: now $n lines, ceiling still $ceiling — tighten it"
        slack=$((slack + 1))
    fi
done

if [ "$violations" -gt 0 ]; then
    echo
    echo "$violations file(s) violate the line limit."
    echo "Split them, or if you are deliberately accepting the debt, record the"
    echo "ceiling with: zig build lint -- --update"
    exit 1
fi

if [ "$slack" -gt 0 ]; then
    echo
    echo "$slack file(s) shrank below their recorded ceiling. Tighten the ratchet:"
    echo "  zig build lint -- --update"
    exit 1
fi

echo "line limit ok (<= $LIMIT, or within recorded ceiling)"
