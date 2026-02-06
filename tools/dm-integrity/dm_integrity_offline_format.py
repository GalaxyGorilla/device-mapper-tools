#!/usr/bin/env python3
"""Offline formatter for dm-integrity metadata images.

Goal
----
Create/initialize a dm-integrity *meta_device* image file without needing
CAP_SYS_ADMIN (no dmsetup/loop/devmapper ioctls). This is useful for CI where
runners are unprivileged.

This script writes:
- dm-integrity superblock (first 8 sectors = 4096 bytes)
- an initialized journal region
- (optionally) initialized integrity tags for a data image assumed to be all-zero

It targets the dm-integrity configuration where a separate meta device is used
(i.e. dm-integrity table parameter: meta_device:<path>). In this mode, the
metadata layout is linear and easiest to reproduce offline.

Compatibility
-------------
Based on Linux 6.8 dm-integrity on-disk structures (drivers/md/dm-integrity.c).
It intentionally avoids SB_FLAG_FIXED_PADDING / SB_FLAG_FIXED_HMAC.

NOTE: This does not create an actual dm mapping; it only prepares images.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import struct
from dataclasses import dataclass

SECTOR_SIZE = 512
SB_SECTORS = 8
SB_BYTES = SB_SECTORS * SECTOR_SIZE
SB_MAGIC = b"integrt\x00"  # 8 bytes (kernel memcpy(..., 8))

JOURNAL_BLOCK_SECTORS = 8
JOURNAL_MAC_PER_SECTOR = 8
JOURNAL_SECTOR_DATA = SECTOR_SIZE - 8  # commit_id_t at end
JOURNAL_ENTRY_ROUNDUP = 8

# Constants used by the kernel in create_journal()
COMMIT_IDS = (
    0x1111111111111111,
    0x2222222222222222,
    0x3333333333333333,
    0x4444444444444444,
)


def roundup(x: int, a: int) -> int:
    return (x + a - 1) // a * a


def u8(x: int) -> int:
    return x & 0xFF


def le16(x: int) -> bytes:
    return struct.pack("<H", x)


def le32(x: int) -> bytes:
    return struct.pack("<I", x)


def le64(x: int) -> bytes:
    return struct.pack("<Q", x)


@dataclass
class JournalLayout:
    entry_size: int
    entries_per_sector: int
    section_entries: int
    section_sectors: int


def journal_layout(tag_size: int, sectors_per_block: int, have_journal_mac: bool = False) -> JournalLayout:
    # C: offsetof(struct journal_entry, last_bytes[sectors_per_block]) + tag_size
    # struct journal_entry { union { __le64 sector; ... } u; commit_id_t last_bytes[]; /* __u8 tag[0] */ }
    # union u is 8 bytes; commit_id_t is 8 bytes.
    base = 8 + 8 * sectors_per_block
    entry_size = roundup(base + tag_size, JOURNAL_ENTRY_ROUNDUP)

    sector_space = JOURNAL_SECTOR_DATA
    if have_journal_mac:
        sector_space -= JOURNAL_MAC_PER_SECTOR

    entries_per_sector = sector_space // entry_size
    if entries_per_sector <= 0:
        raise ValueError(f"tag_size={tag_size} too large for journal sector")

    section_entries = entries_per_sector * JOURNAL_BLOCK_SECTORS
    # C: (section_entries << log2_sectors_per_block) + JOURNAL_BLOCK_SECTORS
    # Here log2_sectors_per_block == log2(sectors_per_block)
    section_sectors = section_entries * sectors_per_block + JOURNAL_BLOCK_SECTORS

    return JournalLayout(
        entry_size=entry_size,
        entries_per_sector=entries_per_sector,
        section_entries=section_entries,
        section_sectors=section_sectors,
    )


def dm_integrity_commit_id(section_idx: int, sector_in_section: int, seq: int) -> int:
    # Kernel: commit_ids[seq] ^ cpu_to_le64(((__u64)i << 32) ^ j)
    return COMMIT_IDS[seq] ^ (((section_idx & 0xFFFFFFFF) << 32) ^ (sector_in_section & 0xFFFFFFFF))


def parse_size_to_sectors(s: str) -> int:
    s = s.strip().lower()
    mult = 1
    if s.endswith("k"):
        mult = 1024
        s = s[:-1]
    elif s.endswith("m"):
        mult = 1024**2
        s = s[:-1]
    elif s.endswith("g"):
        mult = 1024**3
        s = s[:-1]
    elif s.endswith("t"):
        mult = 1024**4
        s = s[:-1]

    b = int(float(s) * mult)
    if b % SECTOR_SIZE:
        raise ValueError(f"size must be multiple of {SECTOR_SIZE} bytes (got {b})")
    return b // SECTOR_SIZE


def ensure_file_size(path: str, size_bytes: int) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "ab") as f:
        pass
    st = os.stat(path)
    if st.st_size != size_bytes:
        with open(path, "r+b") as f:
            f.truncate(size_bytes)


def write_at(f, off: int, data: bytes) -> None:
    f.seek(off)
    f.write(data)


def compute_tag(alg: str, sector: int, block: bytes, tag_size: int, salt: bytes = b"") -> bytes:
    h = hashlib.new(alg)
    if salt:
        h.update(salt)
    h.update(struct.pack("<Q", sector))  # sector_le
    h.update(block)
    d = h.digest()
    if len(d) < tag_size:
        d = d + b"\x00" * (tag_size - len(d))
    return d[:tag_size]


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline dm-integrity meta_device image formatter")
    ap.add_argument("--data-image", required=False, help="Path to data image (optional; for sizing / tag init)")
    ap.add_argument("--data-sectors", required=False, help="Data size in sectors, or bytes with suffix (e.g. 64M)")
    ap.add_argument("--meta-image", required=True, help="Path to meta image to create/overwrite")

    ap.add_argument("--tag-size", type=int, default=32, help="Integrity tag size in bytes (default: 32)")
    ap.add_argument("--block-size", type=int, default=512, help="Block size in bytes (must be multiple of 512; default: 512)")

    ap.add_argument("--journal-sectors", type=int, default=None, help="Requested journal size in 512B sectors (default: 0.7%% of data, min 1 section)")
    ap.add_argument("--buffer-sectors", type=int, default=128, help="dm-integrity buffer_sectors (must be power of two; default: 128)")

    ap.add_argument("--compat", choices=["v1"], default="v1",
                    help="On-disk format compatibility profile. Currently only v1 (max compatibility) is implemented.")

    ap.add_argument("--init-tags", action="store_true", help="Initialize tag area for an all-zero data image")
    ap.add_argument("--hash", default="sha256", help="Hash for --init-tags (default: sha256)")

    args = ap.parse_args()

    if args.block_size % SECTOR_SIZE:
        raise SystemExit("--block-size must be a multiple of 512")
    sectors_per_block = args.block_size // SECTOR_SIZE
    if sectors_per_block & (sectors_per_block - 1):
        raise SystemExit("--block-size/512 must be a power of two")

    if args.tag_size <= 0 or args.tag_size > 4096:
        raise SystemExit("--tag-size looks invalid")

    if args.buffer_sectors & (args.buffer_sectors - 1):
        raise SystemExit("--buffer-sectors must be a power of two")
    log2_buffer_sectors = int(math.log2(args.buffer_sectors))

    # Determine data size.
    if args.data_sectors:
        if any(args.data_sectors.lower().endswith(suf) for suf in ("k", "m", "g", "t")):
            data_sectors = parse_size_to_sectors(args.data_sectors)
        else:
            data_sectors = int(args.data_sectors)
    elif args.data_image:
        st = os.stat(args.data_image)
        if st.st_size % SECTOR_SIZE:
            raise SystemExit("data image size must be multiple of 512 bytes")
        data_sectors = st.st_size // SECTOR_SIZE
    else:
        raise SystemExit("need --data-sectors or --data-image")

    # Align provided_data_sectors down to block.
    data_sectors &= ~(sectors_per_block - 1)
    if data_sectors <= 0:
        raise SystemExit("data size too small")

    jl = journal_layout(args.tag_size, sectors_per_block, have_journal_mac=False)

    if args.journal_sectors is None:
        # Kernel default factor is ~7; integritysetup traditionally uses ~1/7-ish.
        # We'll choose 0.7% of data, but at least one section.
        req_journal_sectors = max(jl.section_sectors, data_sectors // 128)
    else:
        req_journal_sectors = int(args.journal_sectors)

    journal_sections = max(1, req_journal_sectors // jl.section_sectors)

    initial_sectors = SB_SECTORS + jl.section_sectors * journal_sections

    # Tag area size (linear for meta_device): one tag per data block.
    data_blocks = data_sectors // sectors_per_block
    tag_bytes = data_blocks * args.tag_size

    # Round tag area up to buffer size in bytes.
    buf_bytes = args.buffer_sectors * SECTOR_SIZE
    tag_bytes_rounded = roundup(tag_bytes, buf_bytes)

    meta_bytes = initial_sectors * SECTOR_SIZE + tag_bytes_rounded

    ensure_file_size(args.meta_image, meta_bytes)

    # Build superblock (struct superblock) at start of first 4096 bytes.
    # Fields (see dm-integrity.c):
    # magic[8], version(u8), log2_interleave_sectors(u8), integrity_tag_size(le16),
    # journal_sections(le32), provided_data_sectors(le64), flags(le32),
    # log2_sectors_per_block(u8), log2_blocks_per_bitmap_bit(u8), pad[2],
    # recalc_sector(le64), pad2[8], salt[16]
    version = 1  # SB_VERSION_1
    log2_interleave_sectors = 0  # required for meta_device mode
    flags = 0
    log2_sectors_per_block = int(math.log2(sectors_per_block))

    # A reasonable default; mostly used for bitmap mode, but stored in SB.
    # DEFAULT_SECTORS_PER_BITMAP_BIT=32768 => log2=15.
    log2_blocks_per_bitmap_bit = max(0, 15 - log2_sectors_per_block)

    sb = bytearray(SB_BYTES)
    off = 0
    sb[off : off + 8] = SB_MAGIC
    off += 8
    sb[off] = u8(version)
    off += 1
    sb[off] = u8(log2_interleave_sectors)
    off += 1
    sb[off : off + 2] = le16(args.tag_size)
    off += 2
    sb[off : off + 4] = le32(journal_sections)
    off += 4
    sb[off : off + 8] = le64(data_sectors)
    off += 8
    sb[off : off + 4] = le32(flags)
    off += 4
    sb[off] = u8(log2_sectors_per_block)
    off += 1
    sb[off] = u8(log2_blocks_per_bitmap_bit)
    off += 1
    sb[off : off + 2] = b"\x00\x00"
    off += 2
    sb[off : off + 8] = le64(0)  # recalc_sector
    off += 8
    sb[off : off + 8] = b"\x00" * 8
    off += 8
    sb[off : off + 16] = b"\x00" * 16  # salt

    assert off <= 64

    # Write SB + journal + tag area.
    with open(args.meta_image, "r+b", buffering=0) as mf:
        write_at(mf, 0, sb)

        # Initialize journal.
        # We follow init_journal(..., commit_seq=0):
        # - Each of the jl.section_sectors sectors in a section gets commit_id.
        # - All journal entries are marked unused (sector_hi = 0xffffffff).
        commit_seq = 0
        journal_off = SB_BYTES
        for sec in range(jl.section_sectors * journal_sections):
            section_idx = sec // jl.section_sectors
            sector_in_section = sec % jl.section_sectors
            # A journal sector is 512 bytes, last 8 bytes are commit_id.
            js = bytearray(SECTOR_SIZE)
            commit_id = dm_integrity_commit_id(section_idx, sector_in_section, commit_seq)
            js[-8:] = le64(commit_id)
            write_at(mf, journal_off + sec * SECTOR_SIZE, js)

        # Now write unused markers into the entry area.
        # Journal entry array starts at the beginning of each section, packed into the
        # first (section_entries * sectors_per_block) sectors. The last 8 sectors of a
        # section are the commit-id trailer sectors.
        entry_region_sectors_per_section = jl.section_entries * sectors_per_block
        for sidx in range(journal_sections):
            section_base = journal_off + sidx * jl.section_sectors * SECTOR_SIZE
            # Iterate entries and set sector_hi = 0xffffffff.
            for eidx in range(jl.section_entries):
                # Entry byte offset within entry region:
                e_off = eidx * jl.entry_size
                # Locate within the linear entry region bytes.
                abs_off = section_base + e_off
                # journal_entry_set_unused(je) sets sector_hi = le32(-1) at offset 4 within union.
                # union layout: sector_lo (0..3), sector_hi (4..7)
                write_at(mf, abs_off + 4, le32(0xFFFFFFFF))

        # Optionally initialize tags (assumes all-zero data blocks).
        if args.init_tags:
            # If a data image path is provided, we can sanity-check size, but we don't need to write it.
            if args.data_image:
                st = os.stat(args.data_image)
                if st.st_size // SECTOR_SIZE < data_sectors:
                    raise SystemExit("data-image is smaller than provided data_sectors")

            meta_tag_base = initial_sectors * SECTOR_SIZE
            zero_block = b"\x00" * (sectors_per_block * SECTOR_SIZE)

            # One tag per block, sector number is the *logical sector* of the first sector in the block.
            for b in range(data_blocks):
                logical_sector = b * sectors_per_block
                tag = compute_tag(args.hash, logical_sector, zero_block, args.tag_size)
                write_at(mf, meta_tag_base + b * args.tag_size, tag)

    print("OK")
    print(f"data_sectors={data_sectors} (bytes={data_sectors * SECTOR_SIZE})")
    print(f"meta_image={args.meta_image} (bytes={meta_bytes})")
    print(f"journal_sections={journal_sections} section_sectors={jl.section_sectors} entry_size={jl.entry_size}")
    print(f"initial_sectors={initial_sectors} tag_bytes={tag_bytes} tag_bytes_rounded={tag_bytes_rounded}")
    print(f"buffer_sectors={args.buffer_sectors} (log2={log2_buffer_sectors})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
