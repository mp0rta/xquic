#!/usr/bin/env bash
#
# check_mp0rta_copyright.sh
#
# Verify: every fork-introduced source file (added relative to upstream/main,
# excluding third_party/) carries an mp0rta @copyright line within the first
# 20 lines.
#
# Usage: ./scripts/license/check_mp0rta_copyright.sh
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
    case "$f" in
        third_party/*) continue ;;
        *.c|*.h|*.cpp|*.hpp) ;;
        *) continue ;;
    esac
    if ! head -20 "$f" | grep -qE 'Copyright.*mp0rta'; then
        echo "FAIL: $f: Missing mp0rta @copyright in fork-added file" >&2
        violations=$((violations + 1))
    fi
done < <(git diff --name-only --diff-filter=A upstream/main..HEAD)

if [ "$violations" -gt 0 ]; then
    echo "FAIL: $violations fork-added file(s) lack mp0rta @copyright" >&2
    exit 1
fi
echo "OK: All fork-added source files carry mp0rta @copyright"
