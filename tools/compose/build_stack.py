#!/usr/bin/env python3
"""Compose CI-friendly artifacts for device-mapper stacks.

Design goals
------------
- Works unprivileged (pure file I/O).
- Produces artifacts + manifest.json.
- Defers anything requiring CAP_SYS_ADMIN (dmsetup/loop) or secrets that should
  be device-unique to first boot.

Currently supported
-------------------
- dm-integrity meta_device offline format (journal mode, compat v1)
- dm-crypt offline encryption for legacy/plain use-cases (AES-CBC, IV=plain)

AEAD note
---------
"AEAD" here means the common Linux setup where dm-crypt (authenticated mode)
uses dm-integrity to store tags. Correct activation is best done with
cryptsetup on the target. This tool therefore records an AEAD intent in the
manifest but does not attempt to generate dm-crypt AEAD tags offline.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DMINT_FMT = REPO_ROOT / "tools" / "dm-integrity" / "dm_integrity_format.py"
DMCRYPT_CBC = REPO_ROOT / "tools" / "dm-crypt" / "dm_crypt_plain_cbc.py"
MAKE_MANIFEST = REPO_ROOT / "tools" / "compose" / "make_manifest.py"


def run(cmd: list[str]) -> None:
    subprocess.check_call(cmd)


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build stack artifacts + manifest.json (unprivileged)")
    ap.add_argument("--in", dest="in_path", required=True, help="Input plaintext image (e.g. filesystem image)")
    ap.add_argument("--outdir", default="out", help="Output directory")

    ap.add_argument(
        "--stack",
        required=True,
        choices=["integrity-then-crypt", "crypt-then-integrity", "integrity-only", "crypt-only"],
        help="Stack order from bottom to top",
    )
    ap.add_argument(
        "--profile",
        required=True,
        choices=["plain-crypt", "aead"],
        help="Crypt profile: plain dm-crypt (offline encrypt) or AEAD intent (firstboot activation)",
    )

    # dm-integrity knobs
    ap.add_argument("--integrity-tag-size", type=int, default=32)
    ap.add_argument("--integrity-block-size", type=int, default=512)
    ap.add_argument("--integrity-mode", choices=["J", "B", "D", "R"], default="J")
    ap.add_argument("--integrity-buffer-sectors", type=int, default=128)

    # dm-crypt (plain) knobs
    ap.add_argument("--crypt-sector-size", type=int, default=512)
    ap.add_argument("--crypt-iv-offset", type=int, default=0)
    ap.add_argument("--crypt-start-sector", type=int, default=0)

    k = ap.add_mutually_exclusive_group()
    k.add_argument("--key-hex", help="AES key as hex (passed to dm_crypt_plain_cbc.py)")
    k.add_argument("--key-file-hex", help="File with ASCII hex key")
    k.add_argument("--key-file-bin", help="File with raw key bytes")

    ap.add_argument("--manifest", default="manifest.json")

    args = ap.parse_args()

    outdir = Path(args.outdir)
    ensure_dir(outdir)

    in_path = Path(args.in_path)
    if not in_path.is_file():
        raise SystemExit(f"input not found: {in_path}")

    # Always copy the input plaintext as a separate artifact (useful for debugging / later provisioning)
    plain_copy = outdir / "input.plain.img"
    if plain_copy.resolve() != in_path.resolve():
        shutil.copyfile(in_path, plain_copy)

    integrity_meta = None
    crypt_header = None

    # Decide what becomes the bottom "data" image in the manifest.
    # For plain-crypt, bottom is encrypted backing image.
    # For AEAD intent, we keep bottom as plaintext artifact (firstboot will provision into mapped device).
    data_img = outdir / "data.img"

    if args.profile == "plain-crypt":
        # Encrypt plaintext -> encrypted backing image.
        # (We do not generate keys automatically; CI should supply keys explicitly.)
        if not (args.key_hex or args.key_file_hex or args.key_file_bin):
            raise SystemExit("plain-crypt profile requires a key: provide --key-hex or --key-file-hex or --key-file-bin")

        run(["python3", str(DMCRYPT_CBC), "enc",
             "--in", str(plain_copy),
             "--out", str(data_img),
             "--sector-size", str(args.crypt_sector_size),
             "--iv-offset", str(args.crypt_iv_offset),
             "--start-sector", str(args.crypt_start_sector),
        ] + (["--key-hex", args.key_hex] if args.key_hex else [])
          + (["--key-file-hex", args.key_file_hex] if args.key_file_hex else [])
          + (["--key-file-bin", args.key_file_bin] if args.key_file_bin else []))

        # Placeholder: header artifact not produced by this tool; for dmsetup activation you may use keyring.
        # We still allow a dummy file, but keep manifest field optional.
    else:
        # AEAD intent: keep data.img as the plaintext input for now.
        shutil.copyfile(plain_copy, data_img)

    # If stack includes dm-integrity, format meta image sized for data image.
    if "integrity" in args.stack:
        integrity_meta = outdir / "integrity.meta.img"
        run([
            "python3", str(DMINT_FMT),
            "--data-image", str(data_img),
            "--meta-image", str(integrity_meta),
            "--tag-size", str(args.integrity_tag_size),
            "--block-size", str(args.integrity_block_size),
            "--buffer-sectors", str(args.integrity_buffer_sectors),
            "--compat", "v1",
        ])

    # Build manifest.
    manifest_path = outdir / args.manifest

    # crypt_header is optional for now; compose expects one when stack includes dm-crypt.
    # For approachability, create a tiny placeholder header file when needed.
    if "crypt" in args.stack:
        crypt_header = outdir / "crypt.header.placeholder"
        if not crypt_header.exists():
            crypt_header.write_bytes(b"placeholder\n")

    stack = args.stack

    make_cmd = [
        "python3", str(MAKE_MANIFEST),
        "--data", str(data_img),
        "--stack", stack,
        "--out", str(manifest_path),
    ]

    # crypt intent
    if "crypt" in args.stack:
        if args.profile == "aead":
            make_cmd += ["--crypt-mode", "aead", "--crypt-aead-tag-size", str(args.integrity_tag_size)]
        else:
            make_cmd += ["--crypt-mode", "plain"]
    if integrity_meta is not None:
        make_cmd += [
            "--integrity-meta", str(integrity_meta),
            "--integrity-tag-size", str(args.integrity_tag_size),
            "--integrity-block-size", str(args.integrity_block_size),
            "--integrity-mode", args.integrity_mode,
            "--integrity-buffer-sectors", str(args.integrity_buffer_sectors),
        ]
    if crypt_header is not None:
        make_cmd += [
            "--crypt-header", str(crypt_header),
            "--crypt-sector-size", str(args.crypt_sector_size),
            "--crypt-iv-offset", str(args.crypt_iv_offset),
        ]

    run(make_cmd)

    print(str(manifest_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
