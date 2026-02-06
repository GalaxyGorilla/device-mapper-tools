# device-mapper-tools

Small utilities related to Linux device-mapper, designed for **unprivileged CI/CD** workflows.

The overall model is:

1. **CI/CD (unprivileged):** create/format image artifacts as pure file operations.
2. **First boot (privileged, on target):** perform the minimum required activation steps (dmsetup, key retrieval, etc.).

To connect these two worlds we use a small JSON **manifest** (see `spec/manifest.schema.json`).

## dm-integrity offline formatter (unprivileged)

`tools/dm-integrity/dm_integrity_format.py` formats a **dm-integrity meta_device** image file offline, without needing `CAP_SYS_ADMIN` (no dmsetup/loop/devmapper ioctls). This is useful for CI pipelines that can create artifacts unprivileged, and only activate dm-integrity in a privileged stage.

### Quick start

```bash
truncate -s 64M data.img
python3 tools/dm-integrity/dm_integrity_format.py \
  --data-image data.img \
  --meta-image integrity.meta.img
```

### Privileged smoke test

```bash
./tools/dm-integrity/dm_integrity_selftest.sh 64
```

## dm-crypt (offline, unprivileged)

`tools/dm-crypt/dm_crypt_plain_cbc.py` encrypts/decrypts a raw image using dm-crypt compatible settings (AES-CBC, IV=plain). This is a building block for unprivileged CI pipelines.

(Your first-boot activation will still need kernel dm-crypt + key handling.)

## Manifest (CI artifact)

Create a manifest describing the artifacts + intended stack:

```bash
python3 tools/compose/make_manifest.py \
  --data data.img \
  --integrity-meta integrity.meta.img \
  --crypt-header crypt.header.img \
  --stack integrity-then-crypt \
  --out manifest.json
```

On the embedded device, `firstboot/apply_manifest.sh` currently prints the intended actions (dry run). Later we can extend it to actually activate dm targets.

