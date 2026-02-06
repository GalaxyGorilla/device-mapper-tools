#!/usr/bin/env python3
"""Build dm-verity hash tree offline (unprivileged).

This tool creates the Merkle hash tree used by the Linux dm-verity target.
It does *not* activate device-mapper mappings (that requires privileges);
it only produces artifacts that can be carried to an embedded target.

High-level algorithm
--------------------
- Split the data device into data blocks (data_block_size).
- Hash each data block with the selected algorithm (+ optional salt).
- Pack hashes into hash blocks (hash_block_size).
- Hash each hash block to create the next level.
- Repeat until a single hash remains: the root hash.

The resulting hash tree is written as a flat file containing all hash blocks
(level 0, then level 1, ...). This matches how verity metadata is commonly
stored when using a separate hash device/file.

Notes
-----
- This implementation aims to be compatible with common dm-verity usage.
- Defaults are conservative: sha256, 4096/4096 block sizes.

References
----------
- Linux kernel documentation: Documentation/admin-guide/device-mapper/verity.rst
- veritysetup(8) from cryptsetup (authoritative tooling)
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
from dataclasses import dataclass
from typing import BinaryIO, Iterable, List, Optional, Tuple


@dataclass
class VerityResult:
    root_hash_hex: str
    salt_hex: str
    data_bytes: int
    tree_bytes: int
    levels: int
    digest_size: int
    hashes_per_block: int


def _hash_alg(name: str) -> "hashlib._Hash":
    try:
        return hashlib.new(name)
    except Exception as e:
        raise ValueError(f"Unsupported hash algorithm: {name}") from e


def _digest_size(alg: str) -> int:
    return _hash_alg(alg).digest_size


def _iter_blocks(fin: BinaryIO, block_size: int, total_bytes: int) -> Iterable[bytes]:
    remaining = total_bytes
    while remaining > 0:
        chunk = fin.read(min(block_size, remaining))
        if not chunk:
            raise RuntimeError("Unexpected EOF")
        if len(chunk) < block_size:
            chunk = chunk + b"\x00" * (block_size - len(chunk))
        yield chunk
        remaining -= len(chunk) if remaining >= block_size else remaining


def _hash_block(alg: str, data: bytes, salt: bytes) -> bytes:
    h = _hash_alg(alg)
    h.update(data)
    if salt:
        h.update(salt)
    return h.digest()


def build_hash_tree(
    data_path: str,
    out_hash_path: str,
    alg: str = "sha256",
    data_block_size: int = 4096,
    hash_block_size: int = 4096,
    salt: bytes = b"",
) -> VerityResult:
    if data_block_size <= 0 or hash_block_size <= 0:
        raise ValueError("block sizes must be > 0")
    if data_block_size & (data_block_size - 1):
        raise ValueError("data_block_size must be power of two")
    if hash_block_size & (hash_block_size - 1):
        raise ValueError("hash_block_size must be power of two")

    digest_size = _digest_size(alg)
    hashes_per_block = hash_block_size // digest_size
    if hashes_per_block <= 0:
        raise ValueError("hash_block_size too small for digest")

    st = os.stat(data_path)
    data_bytes = st.st_size

    # dm-verity typically requires the data size to be a multiple of data_block_size.
    # We'll allow non-multiple and zero-pad the last block, but record padded hash tree.
    data_blocks = (data_bytes + data_block_size - 1) // data_block_size

    # Level 0: hashes of data blocks.
    level_hashes: List[bytes] = []
    with open(data_path, "rb") as fin:
        # Read exact file bytes but pad last block.
        remaining = data_bytes
        for _ in range(data_blocks):
            to_read = min(data_block_size, remaining) if remaining > 0 else 0
            buf = fin.read(to_read) if to_read else b""
            if len(buf) < data_block_size:
                buf = buf + b"\x00" * (data_block_size - len(buf))
            level_hashes.append(_hash_block(alg, buf, salt))
            remaining -= to_read

    # Now build upper levels; simultaneously write blocks for each level.
    tree_bytes = 0
    levels = 0
    with open(out_hash_path, "wb") as hout:
        current = level_hashes
        while True:
            levels += 1
            # Pack hashes into hash blocks.
            blocks = (len(current) + hashes_per_block - 1) // hashes_per_block
            for b in range(blocks):
                start = b * hashes_per_block
                end = min((b + 1) * hashes_per_block, len(current))
                block = b"".join(current[start:end])
                if len(block) < hash_block_size:
                    block += b"\x00" * (hash_block_size - len(block))
                hout.write(block)
                tree_bytes += len(block)

            if len(current) <= 1:
                # Root hash is the single digest at this level.
                root = current[0]
                break

            # Next level: hash each hash block.
            next_level: List[bytes] = []
            # Rewind over just-written blocks for this level isn't cheap; re-hash from assembled blocks.
            # We can re-assemble blocks again from current list (deterministic).
            for b in range(blocks):
                start = b * hashes_per_block
                end = min((b + 1) * hashes_per_block, len(current))
                block = b"".join(current[start:end])
                if len(block) < hash_block_size:
                    block += b"\x00" * (hash_block_size - len(block))
                next_level.append(_hash_block(alg, block, salt))
            current = next_level

    return VerityResult(
        root_hash_hex=root.hex(),
        salt_hex=salt.hex(),
        data_bytes=data_bytes,
        tree_bytes=tree_bytes,
        levels=levels,
        digest_size=digest_size,
        hashes_per_block=hashes_per_block,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Build dm-verity hash tree offline")
    ap.add_argument("--data-image", required=True)
    ap.add_argument("--hash-image", required=True, help="Output hash tree file")
    ap.add_argument("--hash", dest="alg", default="sha256")
    ap.add_argument("--data-block-size", type=int, default=4096)
    ap.add_argument("--hash-block-size", type=int, default=4096)
    ap.add_argument("--salt-hex", default="", help="Optional salt as hex")
    ap.add_argument("--print", action="store_true", help="Print root hash and parameters")

    args = ap.parse_args()

    salt = bytes.fromhex(args.salt_hex) if args.salt_hex else b""

    res = build_hash_tree(
        data_path=args.data_image,
        out_hash_path=args.hash_image,
        alg=args.alg,
        data_block_size=args.data_block_size,
        hash_block_size=args.hash_block_size,
        salt=salt,
    )

    if args.print:
        print(f"root_hash={res.root_hash_hex}")
        print(f"salt={res.salt_hex}")
        print(f"data_bytes={res.data_bytes}")
        print(f"tree_bytes={res.tree_bytes}")
        print(f"levels={res.levels}")
        print(f"digest_size={res.digest_size}")
        print(f"hashes_per_block={res.hashes_per_block}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
