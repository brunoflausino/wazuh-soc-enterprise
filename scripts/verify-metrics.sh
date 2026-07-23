#!/usr/bin/env bash
#
# verify-metrics.sh — recount repository metrics and check them against the
# numbers published in README.md, integrations/README.md and METRICS.md.
#
# Exit 0 = everything agrees. Exit 1 = at least one document is out of date.
# Run before every push. Wire into CI so a stale badge fails the build.
#
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; BOLD=$'\033[1m'; NC=$'\033[0m'
FAIL=0

pass() { printf "  ${GREEN}PASS${NC}  %s\n" "$1"; }
fail() { printf "  ${RED}FAIL${NC}  %s\n" "$1"; FAIL=1; }
warn() { printf "  ${YELLOW}WARN${NC}  %s\n" "$1"; }

printf "\n${BOLD}Repository metric verification${NC}\n"
printf "%s\n\n" "------------------------------------------------------------"

# ---------------------------------------------------------------- counts ----
INTEGRATION_DIRS=$(find integrations -mindepth 1 -maxdepth 1 -type d \
                     ! -name ml-research | sort)

TOTAL=0
printf "${BOLD}Integrations by category${NC}\n"
for d in $INTEGRATION_DIRS; do
  n=$(find "$d" -maxdepth 1 -name '*.md' ! -name 'README.md' | wc -l | tr -d ' ')
  TOTAL=$((TOTAL + n))
  printf "  %-42s %3d\n" "${d#integrations/}" "$n"
done
printf "  %-42s ${BOLD}%3d${NC}\n\n" "TOTAL" "$TOTAL"

RULE_FILES=$(find rules -name '*.xml' 2>/dev/null | wc -l | tr -d ' ')
RULE_COUNT=$(grep -rhoE '<rule[[:space:]]+id="[0-9]+"' rules/*.xml 2>/dev/null | wc -l | tr -d ' ')
DECODER_COUNT=$(grep -rhoE '<decoder[[:space:]]+name=' decoders/*.xml 2>/dev/null | wc -l | tr -d ' ')
PLAYBOOKS=$(find playbooks -maxdepth 1 -name '*.md' ! -name 'README.md' 2>/dev/null | wc -l | tr -d ' ')
REPORTS=$(find incident-reports -maxdepth 1 -name '*.md' ! -name 'README.md' ! -name 'TEMPLATE.md' 2>/dev/null | wc -l | tr -d ' ')

printf "${BOLD}Other artifacts${NC}\n"
printf "  %-42s %3d\n" "published rule files" "$RULE_FILES"
printf "  %-42s %3d\n" "published rules (counted in XML)" "$RULE_COUNT"
printf "  %-42s %3d\n" "published decoders (counted in XML)" "$DECODER_COUNT"
printf "  %-42s %3d\n" "playbooks" "$PLAYBOOKS"
printf "  %-42s %3d\n\n" "incident reports" "$REPORTS"

# ------------------------------------------------------- cross-doc checks ----
printf "${BOLD}Cross-document consistency${NC}\n"

check_number() {
  # check_number <file> <regex matching "<context><number>"> <expected> <label>
  # The trailing number of the match is the metric. %20 sequences are stripped
  # first so URL-encoded spaces in shields.io badges are never read as figures.
  local file="$1" pattern="$2" expected="$3" label="$4" found
  found=$(sed 's/%20/_/g' "$file" 2>/dev/null \
          | grep -oE "$(printf '%s' "$pattern" | sed 's/%20/_/g')" \
          | grep -oE '[0-9]+$' | head -1)
  if [ -z "$found" ]; then
    warn "$label — no figure found in $file"
  elif [ "$found" = "$expected" ]; then
    pass "$label — $file says $found"
  else
    fail "$label — $file says $found, actual is $expected"
  fi
}

check_number "README.md" \
  'Documented%20Integrations-[0-9]+' "$TOTAL" "README badge (integrations)"
check_number "integrations/README.md" \
  'Documented Integrations \([0-9]+' "$TOTAL" "Catalog header"
check_number "integrations/README.md" \
  'TOTAL\*\* \| \*\*[0-9]+' "$TOTAL" "Catalog status table"
check_number "METRICS.md" \
  'Documented integrations \| \*\*[0-9]+' "$TOTAL" "METRICS.md"

# Rule/decoder badges are lab-attested until the corpus is published.
if [ "$RULE_COUNT" -eq 0 ]; then
  warn "rules/ is empty — rule and decoder counts remain lab-attested, not verifiable here"
else
  check_number "README.md" 'Custom%20Rules-[0-9]+' "$RULE_COUNT" "README badge (rules)"
  check_number "README.md" 'Custom%20Decoders-[0-9]+' "$DECODER_COUNT" "README badge (decoders)"
fi

# ------------------------------------------------------------ hygiene ------
printf "\n${BOLD}Repository hygiene${NC}\n"

DEBRIS=$(find . -path ./.git -prune -o -type f \
           \( -iname '*TESTE*' -o -iname '*teste*' -o -iname '*.bak' \
              -o -iname '*~' -o -iname '.DS_Store' \) -print 2>/dev/null)
if [ -z "$DEBRIS" ]; then
  pass "no scratch, backup or test-artifact files committed"
else
  fail "scratch files committed:"; printf "          %s\n" $DEBRIS
fi

BROKEN=0
while IFS= read -r link; do
  f="${link%%::*}"; t="${link##*::}"
  case "$t" in http*|\#*|mailto:*) continue ;; esac
  t="${t%%#*}"
  [ -z "$t" ] && continue
  target="$(dirname "$f")/$t"
  [ -e "$target" ] || { fail "broken link in $f -> $t"; BROKEN=1; }
done < <(grep -rhoE '\[[^]]*\]\([^)]+\)' --include='*.md' . 2>/dev/null \
         | grep -v '^\./\.git' >/dev/null 2>&1; \
         grep -rEoH '\]\([^)]+\)' --include='*.md' . 2>/dev/null \
         | sed 's/:\](/::/' | sed 's/)$//')
[ "$BROKEN" -eq 0 ] && pass "no broken relative links"

# --------------------------------------------------------------- verdict ----
printf "\n%s\n" "------------------------------------------------------------"
if [ "$FAIL" -eq 0 ]; then
  printf "${GREEN}${BOLD}All metrics consistent.${NC}\n\n"
else
  printf "${RED}${BOLD}Inconsistencies found. Update METRICS.md first, then propagate.${NC}\n\n"
fi
exit "$FAIL"
