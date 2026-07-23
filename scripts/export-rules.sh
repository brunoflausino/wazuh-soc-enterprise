#!/usr/bin/env bash
#
# export-rules.sh — export custom Wazuh rules and decoders from the live manager
# into this repository, with host-specific values redacted.
#
# Run ON the Wazuh manager, from the repository root:
#     sudo ./scripts/export-rules.sh
#
# The script never pushes. It stages files and prints a review checklist.
# Read the diff before committing. Redaction is a safety net, not a guarantee.
#
set -euo pipefail

OSSEC_RULES="/var/ossec/etc/rules"
OSSEC_DECODERS="/var/ossec/etc/decoders"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST_RULES="$REPO_ROOT/rules"
DEST_DECODERS="$REPO_ROOT/decoders"
STAMP="$(date +%Y%m%d-%H%M%S)"

BOLD=$'\033[1m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'

[ -d "$OSSEC_RULES" ] || { printf "${RED}%s not found — run this on the Wazuh manager.${NC}\n" "$OSSEC_RULES"; exit 1; }

mkdir -p "$DEST_RULES" "$DEST_DECODERS"

# Back up whatever is already staged, per this lab's change-management policy.
if compgen -G "$DEST_RULES/*.xml" > /dev/null; then
  mkdir -p "$REPO_ROOT/.export-backups/$STAMP"
  cp "$DEST_RULES"/*.xml "$REPO_ROOT/.export-backups/$STAMP/" 2>/dev/null || true
  printf "${YELLOW}Previous export backed up to .export-backups/%s${NC}\n" "$STAMP"
fi

# ------------------------------------------------------------- redaction ----
# Each sed expression removes a class of host-specific or sensitive value.
# Extend this list rather than hand-editing exported files.
redact() {
  sed -E \
    -e 's#\b(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]+\.[0-9]+#<LAB_INTERNAL_IP>#g' \
    -e 's#(password|passwd|pwd|secret|token|api_?key|authkey)([[:space:]]*[=:>][[:space:]]*)[^<[:space:]]+#\1\2<REDACTED>#gI' \
    -e 's#/home/[a-z_][a-z0-9_-]*#/home/<USER>#g' \
    -e 's#\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b#<EMAIL_REDACTED>#g' \
    -e 's#\b[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\b#<MAC_REDACTED>#g'
}

printf "\n${BOLD}Exporting rules${NC}\n"
COUNT_R=0
for f in "$OSSEC_RULES"/*.xml; do
  base="$(basename "$f")"
  case "$base" in
    # Skip Wazuh's own shipped ruleset; only custom work belongs in the portfolio.
    0*-*_rules.xml) continue ;;
  esac
  redact < "$f" > "$DEST_RULES/$base"
  n=$(grep -cE '<rule[[:space:]]+id=' "$DEST_RULES/$base" || true)
  printf "  %-44s %3d rules\n" "$base" "$n"
  COUNT_R=$((COUNT_R + n))
done

printf "\n${BOLD}Exporting decoders${NC}\n"
COUNT_D=0
for f in "$OSSEC_DECODERS"/*.xml; do
  base="$(basename "$f")"
  case "$base" in 0*-*_decoders.xml) continue ;; esac
  redact < "$f" > "$DEST_DECODERS/$base"
  n=$(grep -cE '<decoder[[:space:]]+name=' "$DEST_DECODERS/$base" || true)
  printf "  %-44s %3d decoders\n" "$base" "$n"
  COUNT_D=$((COUNT_D + n))
done

# ------------------------------------------------------- integrity checks ----
printf "\n${BOLD}Totals${NC}\n"
printf "  rules exported     %d\n" "$COUNT_R"
printf "  decoders exported  %d\n\n" "$COUNT_D"

printf "${BOLD}Duplicate rule IDs${NC}\n"
DUPES=$(grep -rhoE '<rule id="[0-9]+"' "$DEST_RULES"/*.xml 2>/dev/null \
        | grep -oE '[0-9]+' | sort -n | uniq -d)
if [ -z "$DUPES" ]; then
  printf "  ${GREEN}none${NC}\n"
else
  printf "  ${RED}COLLISIONS — fix before trusting analysisd:${NC}\n"
  printf "    %s\n" $DUPES
fi

printf "\n${BOLD}Residual sensitive-looking strings (manual review required)${NC}\n"
LEFTOVER=$(grep -rniE 'password|secret|token|api_?key|[0-9]{1,3}(\.[0-9]{1,3}){3}' \
             "$DEST_RULES" "$DEST_DECODERS" 2>/dev/null \
           | grep -v 'REDACTED\|LAB_INTERNAL_IP\|0\.0\.0\.0\|127\.0\.0\.1' || true)
if [ -z "$LEFTOVER" ]; then
  printf "  ${GREEN}none detected${NC}\n"
else
  printf "${YELLOW}%s${NC}\n" "$LEFTOVER"
fi

cat <<EOF

${BOLD}Before committing${NC}
  1. git diff --stat rules/ decoders/
  2. Read every changed file. Redaction catches patterns, not judgement.
  3. Check public IPs: any address left in a rule should be a published
     threat indicator, never lab infrastructure.
  4. Update METRICS.md: rules=$COUNT_R decoders=$COUNT_D
  5. ./scripts/verify-metrics.sh
EOF
