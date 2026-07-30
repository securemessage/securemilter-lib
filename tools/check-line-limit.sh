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

# EVERY .zig file is measured, including *_test.zig.
#
# Skipping those files entirely was the last of the relocation loophole, and it
# survived the 2026-07-29 fix below because that fix only addressed test BLOCKS.
# A test's explanation lives ABOVE the `test` line, so it was production in
# main.zig and invisible in main_test.zig -- moving a well-commented test still
# moved the number. Measuring every file removes the difference; `prod_lines`
# already discards the tests themselves wherever they are, so a test file
# contributes only its imports and helpers, which is exactly right: those ARE
# logic a reader has to hold.
list_sources() {
    find "$SRCDIR" -name '*.zig' | sort
}

# Count PRODUCTION lines: everything outside a top-level `test` block.
#
# Excluding test FILES while counting test BLOCKS was a loophole, and it was
# walked through three times on 2026-07-29. The same test counted against
# main.zig and counted for nothing in main_test.zig, so the cheapest way to
# "reduce" a file was to relocate its tests -- which changes no production line
# and makes the code harder to read, since Zig's convention is to keep a test
# beside the thing it tests. securedkim/src/main.zig went 1305 -> 1140 that way
# and its production size was 1107 before and after.
#
# The rule is now uniform: TESTS NEVER COUNT, wherever they live. That removes
# the incentive to move them and makes the number mean what it claims to --
# the size of the logic a reader has to hold in their head.
#
# A TEST'S LEADING COMMENT BLOCK IS PART OF THE TEST. Comments and blank lines
# are held back and only charged when real code follows them; a `test` line
# discards whatever is held. Without this the rule above is false in the way
# that matters most -- an explanation of what a test defends against is exactly
# the thing worth writing, and charging it as production made the cheapest way
# to satisfy the gate "delete the reasoning" or "move the test to a file the
# checker skips". A metric that bills you for documenting a regression test is
# steering away from the behaviour it exists to encourage.
#
# `zig fmt` guarantees a top-level closing brace at column 0, which is what
# makes this safe to do with a line scan rather than a parser.
prod_lines() {
    awk '
        !intest && /^test[ \t{"]/ { intest = 1; pending = 0; next }
        intest && /^\}/          { intest = 0; next }
        intest                    { next }
        /^[ \t]*\/\//             { pending++; next }
        /^[ \t]*$/                { pending++; next }
                                  { n += pending; pending = 0; n++ }
        END                       { print n + 0 }
    ' "$1"
}

# The first line of the generated header. Everything above it in an existing
# allowlist is operator-written and must survive a rewrite; this marker is the
# boundary between the two.
HEADER_MARK="# Files currently over the "

write_allowlist() {
    tmp=$(mktemp)

    # Carry over the operator's rationale.
    #
    # This function used to regenerate the file from scratch, which DELETED every
    # comment it did not itself emit -- and not only under --update: the
    # self-tightening path below calls it too, so a note explaining a ceiling was
    # one shrinking commit away from being lost. That happened twice on 2026-07-29
    # and was recovered from git both times; the second time it took an 11-line
    # block explaining three RFC 8617 ceilings with it.
    #
    # A ceiling without its reason is just a number, and the number is the part a
    # reader can already get from `wc -l`. The reason is the whole value of the
    # file, so the tool must not be the thing that removes it.
    #
    # Only comment and blank lines are carried, and only those above the marker,
    # so an entry line can never survive into the regenerated list and be counted
    # twice.
    if [ -f "$ALLOWLIST" ]; then
        awk -v mark="$HEADER_MARK" '
            index($0, mark) == 1 { exit }
            /^#/ || /^[ \t]*$/   { print }
        ' "$ALLOWLIST" > "$tmp"
    fi

    {
        echo "${HEADER_MARK}${GOAL}-line goal, with the ceiling each"
        echo "# may not exceed. Ceilings tighten by themselves as files shrink; a"
        echo "# file that reaches the goal drops off this list entirely."
        echo "#"
        echo "# Adding an entry by hand is how you knowingly accept a long file:"
        echo "#   zig build lint -- --update"
        echo "# An empty list below means every file meets the goal."
        echo "#"
        echo "# WHY A CEILING EXISTS BELONGS ABOVE THIS HEADER. Comments there are"
        echo "# preserved when the list is rewritten; this header and the entries"
        echo "# under it are regenerated every time a ceiling moves."
    } >> "$tmp"

    list_sources | while IFS= read -r f; do
        n=$(prod_lines "$f")
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
    n=$(prod_lines "$f")
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
