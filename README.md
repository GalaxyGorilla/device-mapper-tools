# device-mapper-tools

Utilities for building **device-mapper based storage images** (dm-crypt, dm-integrity, dm-verity) in environments where you **cannot** use privileged kernel interfaces (typical CI/CD runners).

The guiding idea is a two-step workflow:

1. **CI/CD (unprivileged):** do everything that is *pure file I/O* (create images, encrypt files, format dm-integrity metadata, compute hashes, …).
2. **First boot (privileged, on the embedded target):** do the minimum privileged work (activate dm targets with `dmsetup`, load keys with `keyctl`, mount, provision, …).

This repo helps you produce the right **artifacts** in step 1 and a small **activation plan** for step 2.

---

## TL;DR: how you’re supposed to use this

### Step 1 (CI): build artifacts + manifest

Use the composer to build an output directory with images and a manifest:

```sh
truncate -s 64M fs.img

python3 tools/compose/build_stack.py \
  --in fs.img \
  --outdir out \
  --stack crypt-only \
  --profile plain-crypt \
  --key-hex <your-hex-key>
```

This produces (example):

- `out/data.img` (the image that will back the bottom layer)
- `out/integrity.meta.img` (if the stack includes dm-integrity)
- `out/manifest.json` (human/tool-friendly)

For initramfs use, convert the JSON manifest to a tiny shell-friendly file:

```sh
tools/compose/make_manifest_env.sh out/manifest.json out/manifest.env
```

### Step 2 (target initramfs): activate the stack

On the embedded target you typically have real block devices (no loop), and you must provide key material from a device-specific source.

`firstboot/apply_manifest.sh` is **POSIX `/bin/sh`** and is designed to run in an **initramfs**.

Dry-run (prints a plan):

```sh
MODE=dry-run firstboot/apply_manifest.sh out/manifest.env
```

Apply (actually runs `dmsetup` + `keyctl`):

```sh
export DATA_DEV=/dev/<your-data-blockdev>
export META_DEV=/dev/<your-meta-blockdev>      # only for stacks using dm-integrity
export CRYPT_KEY_HEX=<hex-key>                 # or CRYPT_KEY_BIN=/path/key.bin

MODE=apply firstboot/apply_manifest.sh out/manifest.env
```

---

## Common configurations

This repo intentionally exposes a small set of “common” stack shapes:

- `crypt-only` (plain dm-crypt)
- `integrity-only` (dm-integrity standalone)
- `integrity-then-crypt`
- `crypt-then-integrity`
- `verity-only` (dm-verity hash tree + root hash)
- `verity-then-crypt`
- `crypt-then-verity`

And “profiles” that describe *what kind of crypt you want*:

- `plain-crypt`: unprivileged offline encryption (today: AES-CBC plain IV; more modes like XTS planned)
- `aead`: **intent only** (dm-crypt authenticated mode + dm-integrity tags). The manifest records the intent/parameters; first-boot activation support is added once a verified dmsetup recipe is locked down.

---

## Artifacts and the manifest

The manifest is the contract between CI and the target.

- **`manifest.json`** is the canonical format (see `spec/manifest.schema.json`).
- **`manifest.env`** is a minimal, initramfs-friendly derivative used by the shell firstboot script.

The manifest records:

- paths + sizes + sha256 of the produced artifacts
- the stack ordering (bottom → top)
- parameters needed for activation (e.g. dm-integrity tag size, dm-crypt cipher/sector size, dm-verity root hash, etc.)

---

## Tests

Run the (unprivileged) test suite:

```sh
./tests/run_tests.sh
```

## Tools

### dm-integrity (offline formatting)

`tools/dm-integrity/dm_integrity_format.py`

Formats a **dm-integrity meta_device** image offline (no privileged ioctls). Defaults are conservative for broad kernel compatibility (6.x).

Smoke test (requires privilege for dmsetup/loop):

```sh
./tools/dm-integrity/dm_integrity_selftest.sh 64
```

### dm-crypt (offline helper)

`tools/dm-crypt/dm_crypt_plain_cbc.py`

Encrypt/decrypt a raw image using dm-crypt compatible settings (AES-CBC, IV=plain). This is a CI building block.

### Compose

- `tools/compose/build_stack.py` (recommended entry point)
- `tools/compose/make_manifest.py` (lower-level manifest generator)
- `tools/compose/make_manifest_env.sh` (JSON → ENV for initramfs)

### First boot (initramfs)

`firstboot/apply_manifest.sh`

- POSIX shell
- prefers `dmsetup + keyctl`
- defaults to dry-run

---

## Security notes (short)

- CI artifacts should generally **not** embed device-unique secrets.
- Prefer loading keys on target (TPM/secure element/OTP/HSM) and using `keyctl` + dmsetup keyring integration.
- Always treat the output images as sensitive if they contain encrypted payloads or metadata that leaks access patterns.
