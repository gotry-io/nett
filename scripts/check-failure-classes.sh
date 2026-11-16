#!/usr/bin/env bash
# Every guard named in docs/failure-classes.md exists, and every lab scenario and CI step named
# there runs in CI: a guard that does not run does not guard.
set -euo pipefail
cd "$(dirname "$0")/.."

doc=docs/failure-classes.md
ci=.github/workflows/ci.yml
failed=0
fail() {
    echo "$doc: $1" >&2
    failed=1
}

# The backquotes are the Markdown code spans around each guard
# shellcheck disable=SC2016
guards=$(grep -oE '`(lab|ci|nett-[a-z-]+):[^`<]+`' "$doc" | tr -d '`')
[ -n "$guards" ] || fail "no guards found"
while IFS= read -r guard; do
    kind=${guard%%:*}
    name=${guard#*:}
    case $kind in
        lab)
            # A match arm of `nett-lab run`, alone or with others: "a" | "b" => ...
            grep -qE "^ +(\"[a-z0-9-]+\" \| )*\"$name\"( \| \"[a-z0-9-]+\")* =>" crates/nett-lab/src/main.rs ||
                fail "lab scenario $name does not exist"
            grep -qE "\| $name( |\$)" "$ci" || fail "lab scenario $name does not run in $ci"
            ;;
        ci)
            grep -qF -- "- name: $name" .github/workflows/*.yml || fail "CI step \"$name\" does not exist"
            ;;
        *)
            if [ ! -d "crates/$kind" ]; then
                fail "crate $kind does not exist"
            elif ! grep -rqE "fn $name\(" "crates/$kind"; then
                fail "test $name is not in crates/$kind"
            fi
            ;;
    esac
done <<< "$guards"
echo "$(wc -l <<< "$guards" | tr -d ' ') guards checked"
exit $failed
