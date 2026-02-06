#!/bin/sh
set -eu

# Basic output-level test to ensure initramfs script can run in sealed mode without explicit mount cmd.

TD=$(mktemp -d)
trap 'rm -rf "$TD"' EXIT

cat > "$TD/manifest.env" <<'EOF'
STACK_ORDER=raw,dm-crypt
DATA_IMAGE=data.img
CRYPT_MODE=plain
CRYPT_CIPHER="capi:cbc(aes)-plain"
CRYPT_KEY_BYTES=32
CRYPT_SECTOR_SIZE=512
CRYPT_IV_OFFSET=0
EOF

# sealed mode without mount cmd should NOT fail (it uses default mount cmd).
DMT_PHASE=sealed DMT_MODE=dry-run DMT_DATA_BDEV=/dev/xxx DMT_CRYPT_KEY_HEX=00 ./initramfs/apply_manifest.sh "$TD/manifest.env" >/dev/null 2>&1

echo OK
