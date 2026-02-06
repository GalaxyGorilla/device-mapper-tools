#!/usr/bin/env bash
# Minimal first-boot manifest consumer (DRY RUN by default).
#
# This is intentionally conservative and auditable. It currently:
# - parses the manifest JSON
# - prints intended activation steps
#
# Later we can extend it to actually call dmsetup/cryptsetup when you are ready.
set -euo pipefail

MANIFEST=${1:-manifest.json}
MODE=${MODE:-dry-run}

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

if [[ ! -f "$MANIFEST" ]]; then
  echo "Manifest not found: $MANIFEST" >&2
  exit 2
fi

echo "[apply_manifest] mode=$MODE manifest=$MANIFEST"

ver=$(jq -r '.manifest_version' "$MANIFEST")
if [[ "$ver" != "1" ]]; then
  echo "Unsupported manifest_version: $ver" >&2
  exit 2
fi

echo "Images:"
jq -r '.images | to_entries[] | "- \(.key): \(.value.path) (\(.value.bytes) bytes)"' "$MANIFEST"

echo

echo "Stack (bottom -> top):"
jq -r '.stack[] | "- \(.type)\t\(.name // "-")"' "$MANIFEST"

echo

echo "Planned actions (not executing):"
echo "- Attach images to block devices (loop or real)"
echo "- Activate device-mapper targets in order"

echo

echo "Activation plan (stubs):"
# Note: We don't know device paths here; just show intended ordering.
idx=0
jq -c '.stack[]' "$MANIFEST" | while read -r layer; do
  t=$(echo "$layer" | jq -r '.type')
  n=$(echo "$layer" | jq -r '.name // "-"')
  echo "  [$idx] $t ($n)"
  if [[ "$t" == "dm-integrity" ]]; then
    jq -r '.integrity // {} | "      integrity: tag_size=\(.tag_size//"?") block_size=\(.block_size//"?") mode=\(.mode//"?") buffer_sectors=\(.buffer_sectors//"?")"' "$MANIFEST"
  fi
  if [[ "$t" == "dm-crypt" ]]; then
    jq -r '.crypt // {} | "      crypt: cipher=\(.cipher//"?") key_bytes=\(.key_bytes//"?") sector_size=\(.sector_size//"?") iv_offset=\(.iv_offset//"?")"' "$MANIFEST"
  fi
  idx=$((idx+1))
done

echo

echo "- Mount/use final mapped device"

echo

echo "NOTE: This script is a stub; execution mode will be added once the repo contains the dm-crypt side and your target constraints are clear."
