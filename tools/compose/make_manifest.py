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

    ap.add_argument(
        "--direction",
        required=True,
        choices=["integrity-then-crypt", "crypt-then-integrity"],
        help="Stack order from bottom to top",
    )

    # dm-integrity parameters (optional, but recommended when integrity-meta is present)
    ap.add_argument("--integrity-tag-size", type=int, default=32)
    ap.add_argument("--integrity-block-size", type=int, default=512)
    ap.add_argument("--integrity-mode", choices=["J", "B", "D", "R"], default="J")
    ap.add_argument("--integrity-buffer-sectors", type=int, default=128)
    ap.add_argument("--integrity-compat", choices=["v1"], default="v1")

    ap.add_argument("--out", default="manifest.json")

    args = ap.parse_args()

    images: Dict[str, Any] = {
        "data": image_entry(args.data),
    }
    if args.integrity_meta:
        images["integrity_meta"] = image_entry(args.integrity_meta)
    if args.crypt_header:
        images["crypt_header"] = image_entry(args.crypt_header)

    integrity = None
    if args.integrity_meta:
        integrity = {
            "compat": args.integrity_compat,
            "tag_size": args.integrity_tag_size,
            "block_size": args.integrity_block_size,
            "mode": args.integrity_mode,
            "buffer_sectors": args.integrity_buffer_sectors,
        }

    # Describe stack bottom-to-top.
    stack = [{"type": "raw", "name": "data", "params": {"image": "images.data"}}]

    if args.direction == "integrity-then-crypt":
        if args.integrity_meta:
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
        stack.append({"type": "dm-crypt", "name": "crypt", "params": {"header": "images.crypt_header"}})
    else:
        stack.append({"type": "dm-crypt", "name": "crypt", "params": {"header": "images.crypt_header"}})
        if args.integrity_meta:
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

    manifest: Dict[str, Any] = {
        "manifest_version": 1,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "images": images,
        "stack": stack,
        "firstboot": {
            "required": True,
            "notes": "Activation requires CAP_SYS_ADMIN (dmsetup/loop) and possibly device-unique secrets; do this on the target device.",
        },
    }
    if integrity is not None:
        manifest["integrity"] = integrity

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
