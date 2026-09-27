#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Third-party dependency license scan, wired into `make license-scan` (and from
# there into `make check`). Scans Go (go-licenses) and npm (license-checker) dependencies, FAILS
# if any distributed component carries a copyleft-incompatible license (GPL/AGPL/SSPL family),
# and on success regenerates THIRD-PARTY-LICENSES.md so the inventory can never silently drift
# from the actual dependency set. Tool versions are pinned (not @latest) for reproducibility.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

go_licenses_ver="v2.0.1"
license_checker_ver="25.0.1"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "license-scan: running go-licenses (pinned ${go_licenses_ver})..." >&2
# --template '' switches go-licenses/v2's `report` subcommand into its CSV format
# (module,url,license) instead of the default markdown table; github.com/rosschiu/kiban/* first-party rows are
# dropped below (this scan is about DEPENDENCIES, never our own code — that's `make license-check`).
# No `|| true`: a go-licenses failure (network error, tool crash, ...) must never fall through as
# an empty inventory that still PASSES the scan. A nonzero exit is a real scan failure and must
# fail this script.
if ! go run "github.com/google/go-licenses/v2@${go_licenses_ver}" report ./... --template '' \
	> "$work/go-licenses.csv" 2>"$work/go-licenses.err"; then
	echo "license-scan: FAIL — go-licenses report failed:" >&2
	sed 's/^/    /' "$work/go-licenses.err" >&2
	exit 1
fi
grep -v '^github.com/rosschiu/kiban' "$work/go-licenses.csv" > "$work/go-deps.csv" || true
if [ ! -s "$work/go-deps.csv" ]; then
	echo "license-scan: FAIL — go-licenses produced an empty Go dependency inventory (expected at least one third-party module)" >&2
	exit 1
fi

echo "license-scan: running npm license-checker (pinned ${license_checker_ver}) over web/..." >&2
if ! (cd web && npx --yes "license-checker@${license_checker_ver}" --json --excludePrivatePackages) \
	> "$work/npm-licenses.json" 2>"$work/npm-licenses.err"; then
	echo "license-scan: FAIL — npm license-checker failed:" >&2
	sed 's/^/    /' "$work/npm-licenses.err" >&2
	exit 1
fi
if ! npm_entry_count="$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$work/npm-licenses.json" 2>"$work/npm-licenses-parse.err")"; then
	echo "license-scan: FAIL — could not parse npm license-checker JSON output:" >&2
	sed 's/^/    /' "$work/npm-licenses-parse.err" >&2
	exit 1
fi
if [ "$npm_entry_count" -eq 0 ]; then
	echo "license-scan: FAIL — npm license-checker produced an empty npm dependency inventory (expected at least one third-party package)" >&2
	exit 1
fi

echo "license-scan: checking for copyleft-incompatible and unknown/unclassified licenses..." >&2
# Word-boundary match on the license id itself (never a bare substring of "GPL", which would
# also false-positive on e.g. "MPL") — matches GPL-2.0/GPL-3.0/AGPL-3.0/SSPL-1.0 and their
# "-or-later"/"-only" SPDX suffix variants. Also fail on UNKNOWN/unclassified entries — an
# unclassified license is not proof of compatibility, it is proof the scan couldn't tell.
forbidden_regex='(^|[^A-Za-z])(A?GPL)(-[0-9]+(\.[0-9]+)*)?([^A-Za-z]|$)|SSPL'
# NOTE: "Unlicense" (the actual public-domain-dedication SPDX license, https://unlicense.org) is
# deliberately NOT matched here — it is a real, classified, permissive license, distinct from
# license-checker's own "UNLICENSED" (no license field found at all) and go-licenses'/npm's
# "UNKNOWN"/"unclassified" (the scanner could not determine a license).
unknown_regex='(^|[^A-Za-z0-9])(UNKNOWN|UNLICENSED|unclassified)([^A-Za-z0-9]|$)'

go_violations="$(grep -inE "$forbidden_regex" "$work/go-deps.csv" || true)"
go_unknown="$(grep -inE "$unknown_regex" "$work/go-deps.csv" || true)"
npm_violations="$(python3 - "$work/npm-licenses.json" <<'PYEOF'
import json, re, sys
data = json.load(open(sys.argv[1]))
pat = re.compile(r'(^|[^A-Za-z])(A?GPL)(-[0-9]+(\.[0-9]+)*)?([^A-Za-z]|$)|SSPL')
for pkg, info in data.items():
    lic = str(info.get("licenses", ""))
    if pat.search(lic):
        print(f"{pkg}: {lic}")
PYEOF
)"
npm_unknown="$(python3 - "$work/npm-licenses.json" <<'PYEOF'
import json, re, sys
data = json.load(open(sys.argv[1]))
pat = re.compile(r'(^|[^A-Za-z0-9])(UNKNOWN|UNLICENSED|unclassified)([^A-Za-z0-9]|$)')
for pkg, info in data.items():
    lic = str(info.get("licenses", ""))
    if not lic.strip() or pat.search(lic):
        print(f"{pkg}: {lic or '(empty)'}")
PYEOF
)"

if [ -n "$go_violations" ] || [ -n "$npm_violations" ] || [ -n "$go_unknown" ] || [ -n "$npm_unknown" ]; then
	echo "license-scan: FAIL — a distributed component carries a forbidden, unknown, or unclassified license:" >&2
	[ -n "$go_violations" ] && { echo "  Go (copyleft-incompatible):" >&2; echo "$go_violations" | sed 's/^/    /' >&2; }
	[ -n "$go_unknown" ] && { echo "  Go (unknown/unclassified):" >&2; echo "$go_unknown" | sed 's/^/    /' >&2; }
	[ -n "$npm_violations" ] && { echo "  npm (copyleft-incompatible):" >&2; echo "$npm_violations" | sed 's/^/    /' >&2; }
	[ -n "$npm_unknown" ] && { echo "  npm (unknown/unclassified):" >&2; echo "$npm_unknown" | sed 's/^/    /' >&2; }
	exit 1
fi

echo "license-scan: PASS — no GPL/AGPL/SSPL-family or unknown/unclassified license found in any Go or npm dependency" >&2

# Regenerate the inventory doc so it can never drift from what was actually scanned.
out="THIRD-PARTY-LICENSES.md"
{
	echo "# Third-Party License Inventory"
	echo
	echo "Generated by \`make license-scan\` (\`scripts/license-scan.sh\`); regenerate after any"
	echo "dependency change, never hand-edit."
	echo
	echo "Scanned $(date -u +%Y-%m-%d) with go-licenses \`${go_licenses_ver}\` and npm"
	echo "license-checker \`${license_checker_ver}\`. Gate: \`make license-scan\` fails this build if"
	echo "any entry below is later found to carry a GPL/AGPL/SSPL-family license — none do as of"
	echo "this scan."
	echo
	echo "## Go dependencies ($(wc -l < "$work/go-deps.csv" | tr -d ' ') entries)"
	echo
	echo "| Module | License | Source |"
	echo "|---|---|---|"
	while IFS=',' read -r mod url lic; do
		[ -z "$mod" ] && continue
		echo "| \`$mod\` | $lic | $url |"
	done < "$work/go-deps.csv" | sort -u
	echo
	echo "## npm dependencies (web/ workspace, $(python3 -c "import json;print(len(json.load(open('$work/npm-licenses.json'))))") entries)"
	echo
	echo "| Package | License |"
	echo "|---|---|"
	python3 - "$work/npm-licenses.json" <<'PYEOF'
import json, sys
data = json.load(open(sys.argv[1]))
for pkg in sorted(data):
    lic = data[pkg].get("licenses", "?")
    print(f"| `{pkg}` | {lic} |")
PYEOF
} > "$out"

echo "license-scan: wrote $out" >&2
