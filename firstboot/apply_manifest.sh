#!/bin/sh
# initramfs-friendly manifest consumer for device-mapper-tools
#
# Default: DRY RUN (prints a plan).
# To execute: MODE=apply ./apply_manifest.sh manifest.env
#
# This script intentionally prefers:
# - POSIX shell
# - dmsetup + keyctl (embedded-friendly)
# - minimal dependencies
#
# Manifest formats:
# - manifest.env (preferred): POSIX shell KEY=VALUE file
# - manifest.json (optional): only supported if jq is present

set -eu

MODE=${MODE:-dry-run}
MANIFEST=${1:-manifest.env}

need() {
  command -v "$1" >/dev/null 2>&1
}

say() {
  printf '%s\n' "$*"
}

die() {
  say "ERROR: $*" >&2
  exit 2
}

load_env_manifest() {
  # shellcheck disable=SC1090
  . "$MANIFEST"

  : "${STACK_ORDER:?missing STACK_ORDER}"
  : "${DATA_IMAGE:?missing DATA_IMAGE}"

  # Optional: INTEGRITY_META_IMAGE, CRYPT_MODE, CRYPT_CIPHER, CRYPT_KEY_BYTES, CRYPT_SECTOR_SIZE, CRYPT_IV_OFFSET
}

load_json_manifest() {
  need jq || die "jq not found; cannot read JSON manifest in initramfs. Provide manifest.env instead."

  DATA_IMAGE=$(jq -r '.images.data.path' "$MANIFEST")
  INTEGRITY_META_IMAGE=$(jq -r '.images.integrity_meta.path // empty' "$MANIFEST")

  # Stack order as comma-separated types
  STACK_ORDER=$(jq -r '[.stack[].type] | join(",")' "$MANIFEST")

  CRYPT_MODE=$(jq -r '.crypt.mode // ""' "$MANIFEST")
  CRYPT_CIPHER=$(jq -r '.crypt.cipher // ""' "$MANIFEST")
  CRYPT_KEY_BYTES=$(jq -r '.crypt.key_bytes // ""' "$MANIFEST")
  CRYPT_SECTOR_SIZE=$(jq -r '.crypt.sector_size // ""' "$MANIFEST")
  CRYPT_IV_OFFSET=$(jq -r '.crypt.iv_offset // ""' "$MANIFEST")

  INTEGRITY_TAG_SIZE=$(jq -r '.integrity.tag_size // ""' "$MANIFEST")
  INTEGRITY_BLOCK_SIZE=$(jq -r '.integrity.block_size // ""' "$MANIFEST")
  INTEGRITY_MODE=$(jq -r '.integrity.mode // ""' "$MANIFEST")
  INTEGRITY_BUFFER_SECTORS=$(jq -r '.integrity.buffer_sectors // ""' "$MANIFEST")

  export DATA_IMAGE INTEGRITY_META_IMAGE STACK_ORDER CRYPT_MODE CRYPT_CIPHER CRYPT_KEY_BYTES CRYPT_SECTOR_SIZE CRYPT_IV_OFFSET
  export INTEGRITY_TAG_SIZE INTEGRITY_BLOCK_SIZE INTEGRITY_MODE INTEGRITY_BUFFER_SECTORS
}

# --- dm activation helpers (stubs / minimal) ---------------------------------

# NOTE: We do not (yet) implement loop setup here, because initramfs typically
# uses real block devices. You can point DATA_DEV at a block device path.

activate_dm_integrity() {
  : "${DATA_DEV:?missing DATA_DEV (block device path)}"
  : "${META_DEV:?missing META_DEV (block device path)}"
  : "${INTEGRITY_TAG_SIZE:?missing INTEGRITY_TAG_SIZE}"
  : "${INTEGRITY_MODE:?missing INTEGRITY_MODE (J/D/B/R)}"
  : "${INTEGRITY_BUFFER_SECTORS:?missing INTEGRITY_BUFFER_SECTORS}"

  need dmsetup || {
    if [ "$MODE" = "apply" ]; then
      die "dmsetup not found"
    fi
    say "[dm-integrity] dmsetup not found (dry-run: skipping)"
    return 0
  }

  # Determine device size in 512-byte sectors
  SECTORS=$(blockdev --getsz "$DATA_DEV" 2>/dev/null || true)
  [ -n "$SECTORS" ] || die "could not determine size (sectors) for $DATA_DEV (need blockdev)"

  NAME=${INTEGRITY_NAME:-integrity}

  TABLE="0 $SECTORS integrity $DATA_DEV 0 $INTEGRITY_TAG_SIZE $INTEGRITY_MODE 2 meta_device:$META_DEV buffer_sectors:$INTEGRITY_BUFFER_SECTORS"

  say "[dm-integrity] name=$NAME table=$TABLE"

  if [ "$MODE" = "apply" ]; then
    dmsetup remove -f "$NAME" >/dev/null 2>&1 || true
    dmsetup create "$NAME" --table "$TABLE"
  fi

  INTEGRITY_DEV="/dev/mapper/$NAME"
  export INTEGRITY_DEV
}

load_key_into_keyring() {
  need keyctl || die "keyctl not found"

  KEY_DESC=${CRYPT_KEY_DESC:-dm-key}
  if [ -n "${CRYPT_KEY_HEX:-}" ]; then
    need xxd || die "xxd required for CRYPT_KEY_HEX"
    KEYID=$(printf '%s' "$CRYPT_KEY_HEX" | xxd -r -p | keyctl padd user "$KEY_DESC" @s)
  elif [ -n "${CRYPT_KEY_BIN:-}" ]; then
    KEYID=$(keyctl padd user "$KEY_DESC" @s < "$CRYPT_KEY_BIN")
  else
    die "missing key material: provide CRYPT_KEY_HEX or CRYPT_KEY_BIN"
  fi

  export KEYID KEY_DESC
  say "[keyctl] loaded key desc=$KEY_DESC id=$KEYID"
}

activate_dm_crypt_plain() {
  : "${CRYPT_KEY_BYTES:?missing CRYPT_KEY_BYTES}"

  need dmsetup || {
    if [ "$MODE" = "apply" ]; then
      die "dmsetup not found"
    fi
    say "[dm-crypt] dmsetup not found (dry-run: skipping)"
    return 0
  }

  UNDER_DEV=${CRYPT_UNDER_DEV:-${INTEGRITY_DEV:-${DATA_DEV:-}}}
  [ -n "$UNDER_DEV" ] || die "no underlying device for dm-crypt (set DATA_DEV or activate dm-integrity first)"

  SECTORS=$(blockdev --getsz "$UNDER_DEV" 2>/dev/null || true)
  [ -n "$SECTORS" ] || die "could not determine size (sectors) for $UNDER_DEV"

  NAME=${CRYPT_NAME:-crypt}
  CIPHER=${CRYPT_CIPHER:-capi:cbc(aes)-plain}
  IV_OFFSET=${CRYPT_IV_OFFSET:-0}
  SECTOR_SIZE=${CRYPT_SECTOR_SIZE:-512}

  load_key_into_keyring

  # dmsetup crypt table:
  # 0 <sectors> crypt <cipher> <key> <iv_offset> <dev> <offset> <opts>
  # keyring key form: :<key_bytes>:user:<desc>
  KEY_FIELD=":${CRYPT_KEY_BYTES}:user:${KEY_DESC}"

  TABLE="0 $SECTORS crypt $CIPHER $KEY_FIELD $IV_OFFSET $UNDER_DEV 0 1 sector_size:$SECTOR_SIZE"
  say "[dm-crypt] name=$NAME table=$TABLE"

  if [ "$MODE" = "apply" ]; then
    dmsetup remove -f "$NAME" >/dev/null 2>&1 || true
    dmsetup create "$NAME" --table "$TABLE"
  fi

  CRYPT_DEV="/dev/mapper/$NAME"
  export CRYPT_DEV
}

# --- main --------------------------------------------------------------------

say "[apply_manifest] mode=$MODE manifest=$MANIFEST"

if [ ! -f "$MANIFEST" ]; then
  die "manifest not found: $MANIFEST"
fi

case "$MANIFEST" in
  *.env)
    load_env_manifest
    ;;
  *.json)
    load_json_manifest
    ;;
  *)
    die "unknown manifest format (expected .env or .json)"
    ;;
esac

say "Stack order: $STACK_ORDER"

# STACK_ORDER is a comma-separated list of layer types, bottom->top.
# Supported: raw,dm-integrity,dm-crypt
# raw layer is just DATA_DEV in initramfs.

IFS=','
for layer in $STACK_ORDER; do
  case "$layer" in
    raw)
      # In initramfs, the raw backing is usually a block device.
      # CI artifacts may be used to provision it, but that is outside this script.
      : "${DATA_DEV:=}"
      if [ -z "$DATA_DEV" ]; then
        say "[raw] DATA_DEV not set (ok for dry-run; required for apply)"
      else
        say "[raw] DATA_DEV=$DATA_DEV"
      fi
      ;;
    dm-integrity)
      # Requires DATA_DEV and META_DEV.
      activate_dm_integrity
      ;;
    dm-crypt)
      # Currently only plain dm-crypt activation is implemented.
      if [ "${CRYPT_MODE:-plain}" != "plain" ]; then
        die "dm-crypt mode '$CRYPT_MODE' not implemented in initramfs shell path yet"
      fi
      activate_dm_crypt_plain
      ;;
    *)
      die "unsupported layer: $layer"
      ;;
  esac

done

say "Done."
if [ -n "${CRYPT_DEV:-}" ]; then
  say "Final mapped device: $CRYPT_DEV"
elif [ -n "${INTEGRITY_DEV:-}" ]; then
  say "Final mapped device: $INTEGRITY_DEV"
fi
