#!/usr/bin/env bash
#
# check_alibaba_copyright.sh
#
# Verify: every upstream-derived source file that originally carried an
# Alibaba copyright line still carries it in HEAD. Catches accidental
# removal during refactor.
#
# Usage: ./scripts/license/check_alibaba_copyright.sh
# Requires: 'upstream' git remote pointing at alibaba/xquic, fetched.
#
set -euo pipefail

if ! git rev-parse --verify upstream/main >/dev/null 2>&1; then
    echo "error: 'upstream/main' not available. Run:" >&2
    echo "  git remote add upstream https://github.com/alibaba/xquic.git" >&2
    echo "  git fetch upstream main" >&2
    exit 2
fi

violations=0
while IFS= read -r f; do
    # Skip files deleted in HEAD (intentional removal is fine)
    [ -e "$f" ] || continue
    # Only check C/C++ sources
    case "$f" in
        *.c|*.h|*.cpp|*.hpp) ;;
        *) continue ;;
    esac
    # Did upstream's version of this file have an Alibaba copyright line?
    if git show "upstream/main:$f" 2>/dev/null | grep -qE 'Copyright.*Alibaba'; then
        # Verify HEAD still has it
        if ! grep -qE 'Copyright.*Alibaba' "$f"; then
            echo "FAIL: $f: Alibaba copyright line removed" >&2
            violations=$((violations + 1))
        fi
    fi
done < <(git ls-tree -r --name-only upstream/main)

if [ "$violations" -gt 0 ]; then
    echo "FAIL: $violations file(s) had Alibaba copyright removed" >&2
    exit 1
fi
echo "OK: Alibaba copyright preserved on all applicable files"
