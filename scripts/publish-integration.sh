#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# publish-integration.sh
#
# Prepara documentação de uma ferramenta para o repositório wazuh-soc-enterprise
# sem fazer git commit/push.
#
# Uso:
#   ./scripts/publish-integration.sh <category> <tool> <source_dir> [asset1 asset2 ...]
#
# Exemplo:
#   ./scripts/publish-integration.sh \
#     threat-intelligence \
#     caldera \
#     /home/brunoflausino/documentos-substituicao-soc-github/caldera \
#     /home/brunoflausino/documentos-substituicao-soc-github/caldera/dashboard-alerts-timeline.png \
#     /home/brunoflausino/documentos-substituicao-soc-github/caldera/dashboard-attacks-by-technique.png \
#     /home/brunoflausino/documentos-substituicao-soc-github/caldera/dashboard-full-view.png
# ============================================================================

ROOT="${ROOT:-$HOME/wazuh-soc-enterprise}"
INTEGRATIONS_DIR="$ROOT/integrations"
SCRIPTS_DIR="$ROOT/scripts"

CATEGORIES=(
  "authentication"
  "data-protection"
  "incident-response"
  "network-security"
  "threat-intelligence"
)

usage() {
  cat <<EOF
Usage:
  $0 <category> <tool> <source_dir> [asset1 asset2 ...]

Current main categories:
  - authentication
  - data-protection
  - incident-response
  - network-security
  - threat-intelligence

What the script does:
  1. Validates repository structure
  2. Creates integrations/<category>/assets/<tool>/
  3. Backs up existing <tool>-integration.md and assets/<tool>/
  4. Copies the source markdown into <tool>-integration.md
  5. Rewrites image paths from assets/... to assets/<tool>/...
  6. Copies any image files passed as extra arguments
  7. Prints review commands (no git commit / no git push)

Examples:
  $0 threat-intelligence caldera /path/to/caldera docs1.png docs2.png docs3.png
  $0 threat-intelligence cowrie  /path/to/cowrie  a.png b.png c.png
EOF
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
}

is_valid_category() {
  local category="$1"
  for c in "${CATEGORIES[@]}"; do
    [[ "$c" == "$category" ]] && return 0
  done
  return 1
}

[[ $# -ge 3 ]] || usage

CATEGORY="$1"
TOOL="$2"
SOURCE_DIR="$3"
shift 3
ASSET_FILES=("$@")

require_cmd cp
require_cmd sed
require_cmd find
require_cmd mkdir
require_cmd date

[[ -d "$ROOT" ]] || { echo "ERROR: repo root not found: $ROOT" >&2; exit 1; }
[[ -d "$INTEGRATIONS_DIR" ]] || { echo "ERROR: integrations dir not found: $INTEGRATIONS_DIR" >&2; exit 1; }
[[ -d "$SCRIPTS_DIR" ]] || { echo "ERROR: scripts dir not found: $SCRIPTS_DIR" >&2; exit 1; }

is_valid_category "$CATEGORY" || {
  echo "ERROR: invalid category: $CATEGORY" >&2
  echo "Valid categories: ${CATEGORIES[*]}" >&2
  exit 1
}

[[ -d "$SOURCE_DIR" ]] || { echo "ERROR: source dir not found: $SOURCE_DIR" >&2; exit 1; }

# Preferências de origem do markdown:
# 1) <tool>-integration.md
# 2) README.md
# 3) github.md
DOC_SOURCE=""
if [[ -f "$SOURCE_DIR/${TOOL}-integration.md" ]]; then
  DOC_SOURCE="$SOURCE_DIR/${TOOL}-integration.md"
elif [[ -f "$SOURCE_DIR/README.md" ]]; then
  DOC_SOURCE="$SOURCE_DIR/README.md"
elif [[ -f "$SOURCE_DIR/github.md" ]]; then
  DOC_SOURCE="$SOURCE_DIR/github.md"
else
  echo "ERROR: no suitable markdown source found in $SOURCE_DIR" >&2
  echo "Expected one of: ${TOOL}-integration.md, README.md, github.md" >&2
  exit 1
fi

DEST_DIR="$INTEGRATIONS_DIR/$CATEGORY"
DEST_DOC="$DEST_DIR/${TOOL}-integration.md"
DEST_ASSETS_DIR="$DEST_DIR/assets/$TOOL"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$ROOT/.publication-backups/$CATEGORY/$TOOL/$TIMESTAMP"

mkdir -p "$DEST_ASSETS_DIR"
mkdir -p "$BACKUP_DIR"

echo "== Publication prep =="
echo "Repo root      : $ROOT"
echo "Category       : $CATEGORY"
echo "Tool           : $TOOL"
echo "Source dir     : $SOURCE_DIR"
echo "Doc source     : $DOC_SOURCE"
echo "Dest doc       : $DEST_DOC"
echo "Dest assets    : $DEST_ASSETS_DIR"
echo "Backup dir     : $BACKUP_DIR"
echo

# Backup do estado anterior, se existir
if [[ -f "$DEST_DOC" ]]; then
  cp -a "$DEST_DOC" "$BACKUP_DIR/"
  echo "Backed up existing doc."
fi

if [[ -d "$DEST_ASSETS_DIR" ]] && [[ -n "$(find "$DEST_ASSETS_DIR" -mindepth 1 -maxdepth 1 2>/dev/null)" ]]; then
  mkdir -p "$BACKUP_DIR/assets"
  cp -a "$DEST_ASSETS_DIR" "$BACKUP_DIR/assets/"
  echo "Backed up existing assets."
fi

# Copia o markdown principal
cp -a "$DOC_SOURCE" "$DEST_DOC"

# Reescreve caminhos relativos de imagens:
# assets/foo.png   -> assets/<tool>/foo.png
# ![](/absolute/local/path.png) permanece inalterado para revisão manual
sed -i "s#](assets/#](assets/${TOOL}/#g" "$DEST_DOC"
sed -i "s#src=\"assets/#src=\"assets/${TOOL}/#g" "$DEST_DOC"

# Copia os assets passados na linha de comando
if [[ ${#ASSET_FILES[@]} -gt 0 ]]; then
  echo
  echo "Copying explicit assets:"
  for asset in "${ASSET_FILES[@]}"; do
    [[ -f "$asset" ]] || { echo "ERROR: asset not found: $asset" >&2; exit 1; }
    cp -a "$asset" "$DEST_ASSETS_DIR/"
    echo "  - $(basename "$asset")"
  done
fi

echo
echo "Done."
echo
echo "Next review commands:"
echo "  grep -R \"assets/\" \"$DEST_DOC\""
echo "  ls -lh \"$DEST_ASSETS_DIR\""
echo "  git status"
echo
echo "Suggested staging:"
echo "  git add \"$DEST_DOC\" \"$DEST_ASSETS_DIR\""
