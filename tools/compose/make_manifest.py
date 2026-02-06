#!/usr/bin/env python3
"""Create a manifest.json describing offline-prepared images and intended dm stack.

This is intentionally simple and CI-friendly:
- pure userspace, unprivileged
- computes file size + sha256
- records dm-integrity formatting parameters (if provided)
- records desired stack direction (integrity->crypt or crypt->integrity)

The manifest is meant to be consumed by a small privileged first-boot helper
that can activate device-mapper layers on real hardware.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
from typing import Any, Dict, Optional


def sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def image_entry(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    st = os.stat(path)
    return {
        "path": path,
        "bytes": st.st_size,
        "sha256": sha256_file(path),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Path to data image (or partition image)")
    ap.add_argument("--integrity-meta", help="Path to dm-integrity meta_device image")
    ap.add_argument("--crypt-header", help="Path to dm-crypt header artifact (optional)")
    ap.add_argument("--verity-hash", help="Path to dm-verity hash tree artifact (optional)")

    ap.add_argument(
        "--stack",
        required=True,
        choices=[
            "integrity-then-crypt",
            "crypt-then-integrity",
            "integrity-only",
            "crypt-only",
            "verity-only",
            "verity-then-crypt",
            "crypt-then-verity",
        ],
        help="Stack order from bottom to top",
    )

    # dm-integrity parameters (optional, but recommended when integrity-meta is present)
    ap.add_argument("--integrity-tag-size", type=int, default=32)
    ap.add_argument("--integrity-block-size", type=int, default=512)
    ap.add_argument("--integrity-mode", choices=["J", "B", "D", "R"], default="J")
    ap.add_argument("--integrity-buffer-sectors", type=int, default=128)
    ap.add_argument("--integrity-compat", choices=["v1"], default="v1")

    # dm-crypt parameters (firstboot activation)
    ap.add_argument("--crypt-mode", choices=["plain", "aead"], default="plain")
    ap.add_argument("--crypt-cipher", default="capi:cbc(aes)-plain", help="dm-crypt cipher spec (dmsetup table field, when used)")
    ap.add_argument("--crypt-key-bytes", type=int, default=32, help="Key length in bytes (dmsetup crypt field)")
    ap.add_argument("--crypt-sector-size", type=int, default=512)
    ap.add_argument("--crypt-iv-offset", type=int, default=0)
    ap.add_argument("--crypt-aead-tag-size", type=int, default=16, help="AEAD tag size in bytes (common default: 16)")

    # dm-verity parameters
    ap.add_argument("--verity-hash-alg", default="sha256")
    ap.add_argument("--verity-data-block-size", type=int, default=4096)
    ap.add_argument("--verity-hash-block-size", type=int, default=4096)
    ap.add_argument("--verity-salt-hex", default="")
    ap.add_argument("--verity-root-hash-hex", default="")

    # rootfs mount hints (optional but recommended)
    ap.add_argument("--rootfs-fstype", default="")
    ap.add_argument("--rootfs-mountpoint", default="/newroot")
    ap.add_argument("--rootfs-opts-bootstrap", default="")
    ap.add_argument("--rootfs-opts-sealed", default="")

    ap.add_argument("--out", default="manifest.json")

    args = ap.parse_args()

    images: Dict[str, Any] = {
        "data": image_entry(args.data),
    }
    if args.integrity_meta:
        images["integrity_meta"] = image_entry(args.integrity_meta)
    if args.crypt_header:
        images["crypt_header"] = image_entry(args.crypt_header)
    if args.verity_hash:
        images["verity_hash"] = image_entry(args.verity_hash)

    integrity = None
    if args.integrity_meta:
        integrity = {
            "compat": args.integrity_compat,
            "tag_size": args.integrity_tag_size,
            "block_size": args.integrity_block_size,
            "mode": args.integrity_mode,
            "buffer_sectors": args.integrity_buffer_sectors,
        }

    crypt = None
    if args.crypt_header:
        crypt = {
            "mode": args.crypt_mode,
            "cipher": args.crypt_cipher,
            "key_bytes": args.crypt_key_bytes,
            "sector_size": args.crypt_sector_size,
            "iv_offset": args.crypt_iv_offset,
        }
        if args.crypt_mode == "aead":
            crypt["aead"] = {"tag_size": args.crypt_aead_tag_size}

    # Describe stack bottom-to-top.
    stack = [{"type": "raw", "name": "data", "params": {"image": "images.data"}}]

    def push_integrity() -> None:
        if not args.integrity_meta:
            raise SystemExit("--integrity-meta is required for stacks that include dm-integrity")
        stack.append(
            {
                "type": "dm-integrity",
                "name": "integrity",
                "params": {
                    "meta": "images.integrity_meta",
                    "integrity": "integrity",
                },
            }
        )

    def push_crypt() -> None:
        if not args.crypt_header:
            # crypt tool might be configured to use a raw key source on firstboot, but for now require header artifact
            raise SystemExit("--crypt-header is required for stacks that include dm-crypt")
        stack.append({"type": "dm-crypt", "name": "crypt", "params": {"crypt": "crypt", "header": "images.crypt_header"}})

    def push_verity() -> None:
        if not args.verity_hash:
            raise SystemExit("--verity-hash is required for stacks that include dm-verity")
        stack.append({"type": "dm-verity", "name": "verity", "params": {"hash": "images.verity_hash", "verity": "verity"}})

    if args.stack == "integrity-then-crypt":
        push_integrity(); push_crypt()
    elif args.stack == "crypt-then-integrity":
        push_crypt(); push_integrity()
    elif args.stack == "integrity-only":
        push_integrity()
    elif args.stack == "crypt-only":
        push_crypt()
    elif args.stack == "verity-only":
        push_verity()
    elif args.stack == "verity-then-crypt":
        push_verity(); push_crypt()
    elif args.stack == "crypt-then-verity":
        push_crypt(); push_verity()

    rootfs = {
        "mountpoint": args.rootfs_mountpoint,
    }
    if args.rootfs_fstype:
        rootfs["fstype"] = args.rootfs_fstype
    if args.rootfs_opts_bootstrap:
        rootfs["opts_bootstrap"] = args.rootfs_opts_bootstrap
    if args.rootfs_opts_sealed:
        rootfs["opts_sealed"] = args.rootfs_opts_sealed

    manifest: Dict[str, Any] = {
        "manifest_version": 1,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "images": images,
        "stack": stack,
        "rootfs": rootfs,
        "firstboot": {
            "required": True,
            "notes": "Activation requires CAP_SYS_ADMIN (dmsetup/loop) and possibly device-unique secrets; do this on the target device.",
        },
    }
    if integrity is not None:
        manifest["integrity"] = integrity
    if crypt is not None:
        manifest["crypt"] = crypt

    if args.verity_hash:
        if not args.verity_root_hash_hex:
            raise SystemExit("--verity-root-hash-hex is required when --verity-hash is provided")
        manifest["verity"] = {
            "hash_alg": args.verity_hash_alg,
            "data_block_size": args.verity_data_block_size,
            "hash_block_size": args.verity_hash_block_size,
            "salt_hex": args.verity_salt_hex,
            "root_hash_hex": args.verity_root_hash_hex,
        }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
