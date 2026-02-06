# device-mapper-tools

Utilities for building **device-mapper based storage images** (dm-crypt, dm-integrity, dm-verity) in environments where you **cannot** use privileged kernel interfaces (typical CI/CD runners).

## What this project enables (practical view)

1. A CI/CD pipeline generates one or more **partition images** containing the desired content.
2. This project can apply **dm-* stacks offline** by producing derived artifacts (e.g. encrypted images, integrity metadata, verity hash trees) and a **manifest** describing how to activate them.
3. On the embedded target, an **initramfs script** consumes the manifest plus **environment variables** (device paths, key sources, policy) to activate `/dev/mapper/*` devices using `dmsetup` + `keyctl`.

The guiding idea (lifecycle/policy) is a three-step workflow:

1. **CI/CD (unprivileged):** do everything that is *pure file I/O* (create images, encrypt files, format dm-integrity metadata, compute hashes, …).
2. **Bootstrap boot (privileged, on the embedded target):** first activation while the system is still “allowed to settle”. You activate the stack and bring the system into a known-good state.
3. **Sealed boots (privileged, on the embedded target):** later boots are *fail-closed*. If activation or mount fails (e.g. due to tampering causing I/O errors), the initramfs takes a fatal action (default: panic).

This repo helps you produce the right **artifacts** in step 1 and a small **activation plan** for steps 2 and 3.

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

### Step 2 (target initramfs, bootstrap): first activation

On the embedded target you typically have real block devices (no loop), and you must provide key material from a device-specific source.

`initramfs/apply_manifest.sh` is **POSIX `/bin/sh`** and is designed to run in an **initramfs**.

Bootstrap (default) will activate the stack and (optionally) run a mount command.

Dry-run (prints a plan):

```sh
MODE=dry-run initramfs/apply_manifest.sh out/manifest.env
```

Apply (actually runs `dmsetup` + `keyctl`):

```sh
export DATA_DEV=/dev/<your-data-blockdev>
export META_DEV=/dev/<your-meta-blockdev>      # only for stacks using dm-integrity
export CRYPT_KEY_HEX=<hex-key>                 # or CRYPT_KEY_BIN=/path/key.bin

# Optional: try mounting root
export DMTOOLS_MOUNT_CMD='mount -t ext4 /dev/mapper/crypt /newroot'

MODE=apply initramfs/apply_manifest.sh out/manifest.env
```

### Step 3 (target initramfs, sealed): fail closed

In sealed mode, a mount command is optional: by default the script mounts the final mapped device at `/newroot`.
If mounting fails, the initramfs takes a fatal action (default: panic).

```sh
export DMTOOLS_PHASE=sealed
# Optional: override mount behavior
# export DMTOOLS_MOUNT_CMD='mount -t ext4 -o ro,errors=panic /dev/mapper/crypt /newroot'
# Or use defaults (also can be embedded into manifest.json):
export DMTOOLS_NEWROOT=/newroot
export DMTOOLS_MOUNT_FSTYPE=ext4
# If unset, sealed mode defaults to:
# - ext4: ro,errors=panic
# - others: ro
# You can override explicitly:
# export DMTOOLS_MOUNT_OPTS='ro,errors=panic'

# Optional: what to do if mount fails (default: panic)
export DMTOOLS_FAIL_ACTION=panic   # panic | reboot | shell | exit

MODE=apply initramfs/apply_manifest.sh out/manifest.env
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
- **`manifest.env`** is a minimal, initramfs-friendly derivative used by the shell initramfs script.

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

### Initramfs activation

`initramfs/apply_manifest.sh`

- POSIX shell
- prefers `dmsetup + keyctl`
- defaults to dry-run

---

## Security notes (short)

- CI artifacts should generally **not** embed device-unique secrets.
- Prefer loading keys on target (TPM/secure element/OTP/HSM) and using `keyctl` + dmsetup keyring integration.
- Always treat the output images as sensitive if they contain encrypted payloads or metadata that leaks access patterns.
