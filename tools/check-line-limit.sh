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

# A TEST LIVES BESIDE THE THING IT TESTS. Refused, not advised.
#
# Measuring every file made relocation gain nothing for a test BODY, and that was
# believed to be the end of it. It was not. A shared test HELPER is a top-level
# declaration wherever it lives, so moving tests out still moved the helper lines
# off the production file's ceiling and onto a new file with no ceiling at all --
# and by 2026-08-05 five files had been split that way, three of them citing each
# other as precedent in their own headers, one of them stating outright that it
# existed "so the line-limit gate excludes it". Two ceilings went up when they
# were folded back, which is the size of what the split had been hiding.
#
# The rule has two halves and only the first one is a metric:
#
#   comments and tests never count       `prod_lines` below
#   a test lives beside its subject      here
#
# Without the second half the first is an invitation: if tests are free where
# they are, the only thing moving them can buy is hiding their scaffolding.
#
# As of 2026-08-05 `prod_lines` finally implements the first half as written --
# every comment is free, not just one above a `test` -- which makes the second
# half the only thing standing between a relocated test and a lower number, and
# therefore load-bearing rather than advisory.
#
# Enforced by name because that is what a reader and a `find` can both see. A
# genuine external harness is a separate build target with its own root, not a
# file dropped into src/.
refuse_relocated_tests() {
    found=$(find "$SRCDIR" -name '*_test.zig' | sort)
    [ -n "$found" ] || return 0

    echo "$found" | while IFS= read -r f; do
        echo "relocated tests  $f"
    done
    echo
    echo "A test belongs in the file it tests. Neither tests nor comments are"
    echo "counted against any file's length -- anywhere -- so moving them out buys"
    echo "nothing except moving their shared helpers off that file's ceiling --"
    echo "which is the accounting error this gate exists to prevent."
    echo "Fold each one back into its subject and delete the file."
    exit 1
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
# A COMMENT IS NEVER CHARGED, WHEREVER IT IS. Not above a test, not above a
# function, not at the top of the file.
#
# This was half-implemented until 2026-08-05. Comments were held back and charged
# as soon as real code followed them, so only a comment block directly above a
# `test` line came out free -- and the header two blocks up nonetheless stated the
# rule as "comments and tests never count", which the code did not do. 41% of what
# the gate was measuring across the six packages was comment text: 21,353 counted
# lines fell to 12,408 when the rule was applied as written, and 15 files over the
# goal fell to 2.
#
# The argument for charging them does not survive contact with the stated purpose
# of the number, which is "the size of the logic a reader has to hold in their
# head". A comment is not logic; it is the thing that makes logic cost less to
# hold. Billing for it makes the cheapest way to satisfy the gate "delete the
# reasoning", in a codebase whose entire review standard is that the reasoning is
# written down -- and it was already recognised as unacceptable for tests, for
# exactly this reason, without the same conclusion being drawn one line further
# out.
#
# WHAT THIS DOES NOT EXCUSE. Thirteen files stopped being flagged the moment this
# landed, having had no code removed. That is honest -- they were never 500 lines
# of logic -- but it means the length metric is no longer what justifies the
# remaining consolidation work. Duplication is, and no version of this counter has
# ever been able to see it.
#
# Worked example from the same day: `securearc/src/arc.zig` held a FOURTH live copy
# of the tag scanner that lives in `securemilter_crypto.sig_header`. On the old
# scale that file measured 420 and was on the allowlist -- so the gate was
# complaining about it, and complaining about the wrong thing, since what was
# actually wrong was 17 lines of duplicated function. On this scale it measures
# 234 and the gate says nothing at all. Deleting the copy moved the number by 17.
# A metric that is equally uninformative before and after is not the tool for this
# class of defect, at either calibration.
#
# Zig has no block comments, so `//` at the start of a line is unambiguous: a
# multi-line string literal's continuation lines begin `\\`, and a `//` inside a
# string cannot be the first token on its line.
#
# `zig fmt` guarantees a top-level closing brace at column 0, which is what
# makes the test-block scan safe to do with a line scan rather than a parser.
prod_lines() {
    awk '
        !intest && /^test[ \t{"]/ { intest = 1; next }
        intest && /^\}/          { intest = 0; next }
        intest                    { next }
        /^[ \t]*\/\//             { next }
        /^[ \t]*$/                { next }
                                  { n++ }
        END                       { print n + 0 }
    ' "$1"
}

# The first line of the generated header. Everything above it in an existing
# allowlist is operator-written and must survive a rewrite; this marker is the
# boundary between the two.
#
# THE BOUNDARY MUST BE STATED AT THE BOUNDARY. An earlier version of this header
# closed with "WHY A CEILING EXISTS BELONGS ABOVE THIS HEADER" -- eight lines
# BELOW this marker, and therefore inside the region that is thrown away. The
# entries are at the bottom of the file, so a reader arrives from the bottom and
# meets that sentence first, writes immediately above it as instructed, and loses
# the note on the next rewrite with a zero exit status. That is exactly the
# failure the carry-over below was added to prevent, reintroduced by the
# documentation instead of the code. The rule is now carried BY the marker line,
# which is the only place it cannot drift away from what it describes -- and note
# that it could not simply be moved next to the old marker: the boundary is the
# first generated line, so anything emitted above it would be carried over as
# prose on the next rewrite AND re-emitted, growing a duplicate header every run.
HEADER_MARK="# WRITE THE REASON FOR A CEILING ABOVE THIS LINE."

# The boundary used before the marker carried the rule. Still recognised so an
# allowlist written by that version migrates in one rewrite instead of having its
# old header preserved as prose and duplicated.
HEADER_MARK_LEGACY="# Files currently over the "

# Everything from the first of either marker is generated, so `below` is set --
# not `exit` -- when the caller wants the tail rather than the head.
split_at_marker() {
    awk -v mark="$HEADER_MARK" -v legacy="$HEADER_MARK_LEGACY" -v want="$1" '
        {
            if (!below && (index($0, mark) == 1 || index($0, legacy) == 1)) below = 1
            if (want == "below") { if (below) print }
            else if (!below) print
        }
    ' "$2"
}

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
        split_at_marker above "$ALLOWLIST" | grep -e '^#' -e '^[[:space:]]*$' > "$tmp"
    fi

    {
        echo "$HEADER_MARK"
        echo "#"
        echo "# From here down is regenerated whenever a ceiling moves. A comment"
        echo "# above that line is preserved; one below it is reported and then lost."
        echo "#"
        echo "# Files currently over the ${GOAL}-line goal, with the ceiling each"
        echo "# may not exceed. Ceilings tighten by themselves as files shrink; a"
        echo "# file that reaches the goal drops off this list entirely."
        echo "#"
        echo "# Adding an entry by hand is how you knowingly accept a long file:"
        echo "#   zig build lint -- --update"
        echo "# An empty list below means every file meets the goal."
    } >> "$tmp"

    list_sources | while IFS= read -r f; do
        n=$(prod_lines "$f")
        [ "$n" -gt "$GOAL" ] && echo "$n $f" >> "$tmp"
    done

    # Say what is being thrown away.
    #
    # The carry-over above cannot rescue a comment written BELOW the boundary,
    # and the previous header invited exactly that. Losing operator prose is bad;
    # losing it with a zero exit status and no output is what let it happen
    # twice. Anything dropped is echoed here, so the worst case is a paste back
    # into the right place rather than a trip through the reflog.
    if [ -f "$ALLOWLIST" ]; then
        split_at_marker below "$ALLOWLIST" | grep '^#' | while IFS= read -r line; do
            grep -qxF "$line" "$tmp" || echo "NOT PRESERVED (below the boundary): $line" >&2
        done
    fi

    mv "$tmp" "$ALLOWLIST"
}

# Before anything else, and in --update mode too: a relocated test file must not
# be bankable. Recording a ceiling for one would make the split official.
refuse_relocated_tests

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
