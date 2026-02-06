#!/usr/bin/env bash
# dm-integrity offline format + activation smoke test
# Requires: sudo, losetup, dmsetup, dm_mod, integrity target in kernel
set -euo pipefail

DATA_MB=${1:-64}
TAG_SIZE=${TAG_SIZE:-32}
MODE=${MODE:-J}
BUF_SECTORS=${BUF_SECTORS:-128}
NAME=${NAME:-dmint_selftest}

WORKDIR=$(mktemp -d)
DATA_IMG="$WORKDIR/data.img"
META_IMG="$WORKDIR/meta.img"
PAYLOAD_IN="$WORKDIR/payload.bin"
PAYLOAD_OUT="$WORKDIR/payload_out.bin"

cleanup() {
  set +e
  sudo /sbin/dmsetup remove -f "$NAME" >/dev/null 2>&1 || true
  if [[ -n "${DATA_LOOP:-}" ]]; then sudo /usr/sbin/losetup -d "$DATA_LOOP" >/dev/null 2>&1 || true; fi
  if [[ -n "${META_LOOP:-}" ]]; then sudo /usr/sbin/losetup -d "$META_LOOP" >/dev/null 2>&1 || true; fi
  rm -rf "$WORKDIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[+] Creating images in $WORKDIR"
truncate -s "${DATA_MB}M" "$DATA_IMG"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
python3 "$SCRIPT_DIR/dm_integrity_offline_format.py" \
  --data-image "$DATA_IMG" \
  --meta-image "$META_IMG" \
  --tag-size "$TAG_SIZE" \
  --compat v1

sudo /sbin/modprobe dm_mod

DATA_LOOP=$(sudo /usr/sbin/losetup --find --show "$DATA_IMG")
META_LOOP=$(sudo /usr/sbin/losetup --find --show "$META_IMG")
SECTORS=$(( $(stat -c%s "$DATA_IMG") / 512 ))

echo "[+] DATA_LOOP=$DATA_LOOP META_LOOP=$META_LOOP SECTORS=$SECTORS"

TABLE="0 $SECTORS integrity $DATA_LOOP 0 $TAG_SIZE $MODE 2 meta_device:$META_LOOP buffer_sectors:$BUF_SECTORS"

echo "[+] dmsetup table: $TABLE"
sudo /sbin/dmsetup remove -f "$NAME" >/dev/null 2>&1 || true
sudo /sbin/dmsetup create "$NAME" --table "$TABLE"

DEV="/dev/mapper/$NAME"

echo "[+] dmsetup status/table"
sudo /sbin/dmsetup status "$NAME" || true
sudo /sbin/dmsetup table "$NAME" || true

# IO smoke test
head -c 1048576 /dev/urandom > "$PAYLOAD_IN"
sudo dd if="$PAYLOAD_IN" of="$DEV" bs=4096 seek=1024 conv=fsync status=none 2>/dev/null || sudo dd if="$PAYLOAD_IN" of="$DEV" bs=4096 seek=1024 conv=fsync
sudo dd if="$DEV" of="$PAYLOAD_OUT" bs=4096 skip=1024 count=256 status=none 2>/dev/null || sudo dd if="$DEV" of="$PAYLOAD_OUT" bs=4096 skip=1024 count=256

cmp -s "$PAYLOAD_IN" "$PAYLOAD_OUT"

echo "[+] IO_OK"

sudo /sbin/dmsetup remove "$NAME"

# optional kernel log hint
echo "[+] If you need kernel logs: sudo dmesg -T | tail -n 200"
