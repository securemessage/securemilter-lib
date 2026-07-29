#!/bin/sh
# Track the megaplan's 400-line-per-file code quality GOAL.
#
#   check-line-limit.sh <srcdir> <allowlist>            check
#   check-line-limit.sh <srcdir> <allowlist> --update   rewrite the allowlist
#
# 400 is a GOAL, not a hard limit. A cohesive 430-line file is better than two
# artificial 215-line halves, and a checker that forces the second outcome is
# actively harmful -- it manufactures seams that do not follow the code's own
# structure, which is worse than the length it set out to fix.
#
# So what is enforced here is DIRECTION, not a threshold:
#
#   never worse    an allowlisted file may not grow. This is the real teeth,
#                  because the expensive drift was not a new oversized file
#                  appearing -- it was `evaluate.zig` going 434 -> 896 -> 1120
#                  while already over the goal. A plain list of exempt paths
#                  would have permitted every line of that.
#
#   deliberate     a file newly over the goal stops the build once, and clears by
#                  recording a ceiling for it. Deviation is allowed; it just has
#                  to be a conscious act that shows up in the diff rather than
#                  something that happens quietly over eleven commits.
#
#   self-tightening  progress is banked automatically. When a file shrinks, its
#                  ceiling drops to match and the run still succeeds. An earlier
#                  version failed the build to demand a manual --update, which was
#                  friction with no safety value: it punished the one behaviour
#                  the tool exists to encourage. Leaving the ceiling stale instead
#                  would be worse -- it silently re-permits every line just
#                  removed.
set -u

# The goal. Exceeded knowingly, never drifted past.
GOAL=400

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
# of cases it covers, and splitting one to satisfy a goal aimed at the readability
# of production logic would be cargo-culting the rule against its own purpose.
list_sources() {
    find "$SRCDIR" -name '*.zig' ! -name '*_test.zig' | sort
}

write_allowlist() {
    tmp=$(mktemp)
    {
        echo "# Files currently over the ${GOAL}-line goal, with the ceiling each"
        echo "# may not exceed. Ceilings tighten by themselves as files shrink; a"
        echo "# file that reaches the goal drops off this list entirely."
        echo "#"
        echo "# Adding an entry by hand is how you knowingly accept a long file:"
        echo "#   zig build lint -- --update"
        echo "# An empty list below means every file meets the goal."
    } > "$tmp"
    list_sources | while IFS= read -r f; do
        n=$(grep -c "" "$f")
        [ "$n" -gt "$GOAL" ] && echo "$n $f" >> "$tmp"
    done
    mv "$tmp" "$ALLOWLIST"
}

if [ "$MODE" = "--update" ]; then
    write_allowlist
    echo "allowlist rewritten: $ALLOWLIST"
    exit 0
fi

grew=0
newly_over=0
progress=0

for f in $(list_sources); do
    n=$(grep -c "" "$f")
    ceiling=$(ceiling_for "$f")

    if [ -z "$ceiling" ]; then
        # Not recorded, so this file is newly over the goal.
        if [ "$n" -gt "$GOAL" ]; then
            echo "over goal    $f: $n lines (goal $GOAL)"
            newly_over=$((newly_over + 1))
        fi
        continue
    fi

    if [ "$n" -gt "$ceiling" ]; then
        echo "GREW         $f: $n lines, ceiling $ceiling"
        grew=$((grew + 1))
    elif [ "$n" -lt "$ceiling" ]; then
        if [ "$n" -gt "$GOAL" ]; then
            echo "tightened    $f: $ceiling -> $n"
        else
            echo "REACHED GOAL $f: $ceiling -> $n, now under $GOAL"
        fi
        progress=$((progress + 1))
    fi
done

if [ "$grew" -gt 0 ] || [ "$newly_over" -gt 0 ]; then
    echo
    [ "$grew" -gt 0 ] && \
        echo "$grew file(s) grew past a ceiling. This is the one thing the goal is" && \
        echo "meant to prevent: length that accretes rather than being chosen."
    [ "$newly_over" -gt 0 ] && \
        echo "$newly_over file(s) newly over the ${GOAL}-line goal. Split along a seam the" && \
        echo "code already has -- or, if the length is genuinely the right shape for it," && \
        echo "say so on purpose and the ceiling will hold it there:"
    echo "  zig build lint -- --update"
    exit 1
fi

# Bank the progress. Only reached when nothing grew and nothing is newly over, so
# rewriting cannot paper over a failure.
if [ "$progress" -gt 0 ]; then
    write_allowlist
    echo
    echo "$progress ceiling(s) tightened in $ALLOWLIST -- commit it alongside the change"
    echo "that earned it, so the lines removed cannot quietly come back."
    exit 0
fi

echo "line goal ok (<= $GOAL, or within a recorded ceiling)"
