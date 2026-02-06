#!/bin/sh
# initramfs-friendly manifest consumer for device-mapper-tools
#
# Default: DRY RUN (prints a plan).
# To execute: DMT_MODE=apply ./apply_manifest.sh manifest.env
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

DMT_MODE=${DMT_MODE:-dry-run}
DMT_PHASE=${DMT_PHASE:-bootstrap}   # bootstrap | sealed
DMT_FAIL_ACTION=${DMT_FAIL_ACTION:-panic}  # panic | reboot | shell | exit
DMT_MOUNT_CMD=${DMT_MOUNT_CMD:-}

# Rootfs mount configuration can come from manifest.env.
DMT_ROOTFS_MOUNTPOINT=${DMT_ROOTFS_MOUNTPOINT:-${ROOTFS_MOUNTPOINT:-/newroot}}
DMT_ROOTFS_FSTYPE=${DMT_ROOTFS_FSTYPE:-${ROOTFS_FSTYPE:-}}

# Sensible defaults:
# - bootstrap: rw (so system can finish provisioning)
# - sealed: ro (+ ext4 errors=panic when fstype is ext4)
if [ "$DMT_PHASE" = "sealed" ]; then
  if [ -n "${DMT_ROOTFS_OPTS:-}" ]; then
    MOUNT_OPTS=$DMT_ROOTFS_OPTS
  elif [ -n "${DMT_ROOTFS_OPTS_SEALED:-${ROOTFS_OPTS_SEALED:-}}" ]; then
    MOUNT_OPTS=${DMT_ROOTFS_OPTS_SEALED:-$ROOTFS_OPTS_SEALED}
  else
    if [ "$DMT_ROOTFS_FSTYPE" = "ext4" ]; then
      MOUNT_OPTS="ro,errors=panic"
    else
      MOUNT_OPTS="ro"
    fi
  fi
else
  if [ -n "${DMT_ROOTFS_OPTS:-}" ]; then
    MOUNT_OPTS=$DMT_ROOTFS_OPTS
  elif [ -n "${DMT_ROOTFS_OPTS_BOOTSTRAP:-${ROOTFS_OPTS_BOOTSTRAP:-}}" ]; then
    MOUNT_OPTS=${DMT_ROOTFS_OPTS_BOOTSTRAP:-$ROOTFS_OPTS_BOOTSTRAP}
  else
    MOUNT_OPTS="rw"
  fi
fi

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

# shellcheck disable=SC1090
. "$(dirname "$0")/lib_fail.sh" 2>/dev/null || true

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
# uses real block devices. You can point DMT_DATA_BDEV at a block device path.

activate_dm_integrity() {
  : "${DMT_DATA_BDEV:?missing DMT_DATA_BDEV (block device path)}"
  : "${DMT_INTEGRITY_META_BDEV:?missing DMT_INTEGRITY_META_BDEV (block device path)}"
  : "${INTEGRITY_TAG_SIZE:?missing INTEGRITY_TAG_SIZE}"
  : "${INTEGRITY_MODE:?missing INTEGRITY_MODE (J/D/B/R)}"
  : "${INTEGRITY_BUFFER_SECTORS:?missing INTEGRITY_BUFFER_SECTORS}"

  need dmsetup || {
    if [ "$DMT_MODE" = "apply" ]; then
      die "dmsetup not found"
    fi
    say "[dm-integrity] dmsetup not found (dry-run: skipping)"
    return 0
  }

  # Determine device size in 512-byte sectors
  SECTORS=$(blockdev --getsz "$DMT_DATA_BDEV" 2>/dev/null || true)
  [ -n "$SECTORS" ] || die "could not determine size (sectors) for $DMT_DATA_BDEV (need blockdev)"

  NAME=${INTEGRITY_NAME:-integrity}

  TABLE="0 $SECTORS integrity $DMT_DATA_BDEV 0 $INTEGRITY_TAG_SIZE $INTEGRITY_MODE 2 meta_device:$DMT_INTEGRITY_META_BDEV buffer_sectors:$INTEGRITY_BUFFER_SECTORS"

  say "[dm-integrity] name=$NAME table=$TABLE"

  if [ "$DMT_MODE" = "apply" ]; then
    dmsetup remove -f "$NAME" >/dev/null 2>&1 || true
    dmsetup create "$NAME" --table "$TABLE"
  fi

  INTEGRITY_DEV="/dev/mapper/$NAME"
  export INTEGRITY_DEV
}

load_key_into_keyring() {
  need keyctl || die "keyctl not found"

  KEY_DESC=${DMT_CRYPT_KEY_DESC:-dm-key}
  if [ -n "${DMT_CRYPT_KEY_HEX:-}" ]; then
    need xxd || die "xxd required for DMT_CRYPT_KEY_HEX"
    KEYID=$(printf '%s' "$DMT_CRYPT_KEY_HEX" | xxd -r -p | keyctl padd user "$KEY_DESC" @s)
  elif [ -n "${DMT_CRYPT_KEY_BIN:-}" ]; then
    KEYID=$(keyctl padd user "$KEY_DESC" @s < "$DMT_CRYPT_KEY_BIN")
  else
    die "missing key material: provide DMT_CRYPT_KEY_HEX or DMT_CRYPT_KEY_BIN"
  fi

  export KEYID KEY_DESC
  say "[keyctl] loaded key desc=$KEY_DESC id=$KEYID"
}

activate_dm_crypt_plain() {
  : "${CRYPT_KEY_BYTES:?missing CRYPT_KEY_BYTES}"

  need dmsetup || {
    if [ "$DMT_MODE" = "apply" ]; then
      die "dmsetup not found"
    fi
    say "[dm-crypt] dmsetup not found (dry-run: skipping)"
    return 0
  }

  UNDER_DEV=${DMT_CRYPT_UNDER_BDEV:-${INTEGRITY_DEV:-${DMT_DATA_BDEV:-}}}
  [ -n "$UNDER_DEV" ] || die "no underlying device for dm-crypt (set DMT_DATA_BDEV or activate dm-integrity first)"

  SECTORS=$(blockdev --getsz "$UNDER_DEV" 2>/dev/null || true)
  [ -n "$SECTORS" ] || die "could not determine size (sectors) for $UNDER_DEV"

  NAME=${DMT_CRYPT_NAME:-${CRYPT_NAME:-crypt}}
  CIPHER=${DMT_CRYPT_CIPHER:-${CRYPT_CIPHER:-capi:cbc(aes)-plain}}
  IV_OFFSET=${DMT_CRYPT_IV_OFFSET:-${CRYPT_IV_OFFSET:-0}}
  SECTOR_SIZE=${DMT_CRYPT_SECTOR_SIZE:-${CRYPT_SECTOR_SIZE:-512}}

  load_key_into_keyring

  # dmsetup crypt table:
  # 0 <sectors> crypt <cipher> <key> <iv_offset> <dev> <offset> <opts>
  # keyring key form: :<key_bytes>:user:<desc>
  KEY_FIELD=":${CRYPT_KEY_BYTES}:user:${KEY_DESC}"

  TABLE="0 $SECTORS crypt $CIPHER $KEY_FIELD $IV_OFFSET $UNDER_DEV 0 1 sector_size:$SECTOR_SIZE"
  say "[dm-crypt] name=$NAME table=$TABLE"

  if [ "$DMT_MODE" = "apply" ]; then
    dmsetup remove -f "$NAME" >/dev/null 2>&1 || true
    dmsetup create "$NAME" --table "$TABLE"
  fi

  CRYPT_DEV="/dev/mapper/$NAME"
  export CRYPT_DEV
}

# --- main --------------------------------------------------------------------

say "[apply_manifest] mode=$DMT_MODE phase=$DMT_PHASE manifest=$MANIFEST"

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
# raw layer is just DMT_DATA_BDEV in initramfs.

IFS=','
for layer in $STACK_ORDER; do
  case "$layer" in
    raw)
      # In initramfs, the raw backing is usually a block device.
      # CI artifacts may be used to provision it, but that is outside this script.
      : "${DMT_DATA_BDEV:=}"
      if [ -z "$DMT_DATA_BDEV" ]; then
        say "[raw] DMT_DATA_BDEV not set (ok for dry-run; required for apply)"
      else
        say "[raw] DMT_DATA_BDEV=$DMT_DATA_BDEV"
      fi
      ;;
    dm-integrity)
      # Requires DMT_DATA_BDEV and DMT_INTEGRITY_META_BDEV.
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

FINAL_DEV="${CRYPT_DEV:-${INTEGRITY_DEV:-}}"

say "Done."
if [ -n "$FINAL_DEV" ]; then
  say "Final mapped device: $FINAL_DEV"
fi

default_mount_cmd() {
  # Default mount command if none provided:
  # mount -t <fstype?> -o <opts> <final_dev> <mountpoint>
  # In dry-run mode we may not have created mappings; guess the expected /dev/mapper path.
  if [ -z "$FINAL_DEV" ]; then
    if [ "$DMT_MODE" != "apply" ]; then
      if echo ",$STACK_ORDER," | grep -q ",dm-crypt,"; then
        FINAL_DEV="/dev/mapper/${DMT_CRYPT_NAME:-${CRYPT_NAME:-crypt}}"
      elif echo ",$STACK_ORDER," | grep -q ",dm-integrity,"; then
        FINAL_DEV="/dev/mapper/${INTEGRITY_NAME:-integrity}"
      elif echo ",$STACK_ORDER," | grep -q ",dm-verity,"; then
        FINAL_DEV="/dev/mapper/${VERITY_NAME:-verity}"
      fi
    fi
  fi
  [ -n "$FINAL_DEV" ] || die "no final mapped device to mount"
  cmd="mount"
  if [ -n "$DMT_ROOTFS_FSTYPE" ]; then
    cmd="$cmd -t $DMT_ROOTFS_FSTYPE"
  fi
  cmd="$cmd -o $MOUNT_OPTS $FINAL_DEV $DMT_ROOTFS_MOUNTPOINT"
  printf '%s' "$cmd"
}

if [ -n "$DMT_MOUNT_CMD" ]; then
  EFFECTIVE_MOUNT_CMD=$DMT_MOUNT_CMD
else
  EFFECTIVE_MOUNT_CMD=$(default_mount_cmd)
fi

if [ "$DMT_PHASE" = "sealed" ]; then
  say "[sealed] executing mount command"
  if [ "$DMT_MODE" = "apply" ]; then
    sh -c "$EFFECTIVE_MOUNT_CMD" || fail_action "$DMT_FAIL_ACTION" "mount command failed"
  else
    say "[sealed] dry-run: would run: $EFFECTIVE_MOUNT_CMD"
  fi
else
  # bootstrap
  say "[bootstrap] executing mount command"
  if [ "$DMT_MODE" = "apply" ]; then
    sh -c "$EFFECTIVE_MOUNT_CMD" || die "mount command failed (bootstrap)"
  else
    say "[bootstrap] dry-run: would run: $EFFECTIVE_MOUNT_CMD"
  fi
fi
