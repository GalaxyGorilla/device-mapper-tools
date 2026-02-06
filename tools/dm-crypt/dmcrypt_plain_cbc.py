#!/usr/bin/env python3

"""
Encrypt/decrypt a raw image file using dm-crypt compatible settings:
  - AES-CBC
  - IV mode: plain (IV = LE32(sector_number) + zero padding to 16 bytes)
  - Default encryption sector size: 512 bytes

This matches dm-crypt:
  crypt capi:tk(cbc(aes))-plain ... sector_size:512

Key handling:
  - --key-hex      : AES key as hex (e.g. output of `openssl rand -hex 32`)
  - --key-file-hex : File containing an ASCII hex-encoded AES key
                     (32/48/64 hex characters)
  - --key-file-bin : File containing raw AES key bytes
                     (exactly 16/24/32 bytes, no encoding)

Examples (minimal):

  Encrypt with hex key:
    ./dmcrypt_plain_cbc.py enc \
      --key-hex "$(openssl rand -hex 32)" \
      --in rootfs.squashfs \
      --out rootfs.squashfs.enc

  Encrypt with key file:
    openssl rand -hex 32 > diskkey.hex
    ./dmcrypt_plain_cbc.py enc \
      --key-file-hex diskkey.hex \
      --in rootfs.squashfs \
      --out rootfs.squashfs.enc

  Decrypt and verify:
    ./dmcrypt_plain_cbc.py dec \
      --key-file-hex diskkey.hex \
      --in rootfs.squashfs.enc \
      --out rootfs.squashfs.dec
    sha256sum rootfs.squashfs rootfs.squashfs.dec


Mount encrypted image on a development machine (no CAAM):

  IMG=rootfs.squashfs.enc
  KEYHEX=$(cat rootfs.squashfs.password)
  SIZE=$(stat -c%s "$IMG")
  SECTORS=$((SIZE / 512))

  # Attach encrypted image as a loop device
  LOOP=$(sudo losetup --find --read-only --show "$IMG")

  # Load raw 32-byte key into kernel keyring (type=user, desc=dm-key)
  KEYID=$(echo -n "$KEYHEX" | xxd -r -p | sudo keyctl padd user dm-key @s)

  # Create dm-crypt mapping using keyring key
  sudo dmsetup create crypt_test --table \
    "0 ${SECTORS} crypt capi:cbc(aes)-plain :32:user:dm-key 0 ${LOOP} 0 1 sector_size:512"

  # Mount decrypted squashfs
  sudo mount -t squashfs -o ro /dev/mapper/crypt_test /mnt/test
  ls /mnt/test


Cleanup:

  sudo umount /mnt/test
  sudo dmsetup remove crypt_test
  sudo keyctl revoke "$KEYID"
  sudo losetup -d "$LOOP"


Notes:
  - Default sector size (512) matches dm-crypt unless overridden.
  - Input size must be a multiple of sector size unless --pad-on-encrypt is used.
  - The same plaintext AES key must be wrapped/imported into CAAM on the device
    when using capi:tk(cbc(aes)).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from typing import BinaryIO, Optional

# --- Crypto backend selection -------------------------------------------------
class AesCbcBackend:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt_sector(self, iv16: bytes, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def decrypt_sector(self, iv16: bytes, ciphertext: bytes) -> bytes:
        raise NotImplementedError


def _load_backend(key: bytes) -> AesCbcBackend:
    # Try cryptography first
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        class _CryptographyBackend(AesCbcBackend):
            def encrypt_sector(self, iv16: bytes, plaintext: bytes) -> bytes:
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv16), backend=default_backend())
                enc = cipher.encryptor()
                return enc.update(plaintext) + enc.finalize()

            def decrypt_sector(self, iv16: bytes, ciphertext: bytes) -> bytes:
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv16), backend=default_backend())
                dec = cipher.decryptor()
                return dec.update(ciphertext) + dec.finalize()

        return _CryptographyBackend(key)
    except Exception:
        pass

    # Fallback to pycryptodome
    try:
        from Crypto.Cipher import AES  # type: ignore

        class _PyCryptoDomeBackend(AesCbcBackend):
            def encrypt_sector(self, iv16: bytes, plaintext: bytes) -> bytes:
                return AES.new(self.key, AES.MODE_CBC, iv=iv16).encrypt(plaintext)

            def decrypt_sector(self, iv16: bytes, ciphertext: bytes) -> bytes:
                return AES.new(self.key, AES.MODE_CBC, iv=iv16).decrypt(ciphertext)

        return _PyCryptoDomeBackend(key)
    except Exception as e:
        raise RuntimeError(
            "No crypto backend available. Install 'cryptography' or 'pycryptodome'."
        ) from e


# --- dm-crypt "plain" IV ------------------------------------------------------
def iv_plain(sector_number: int, iv_offset: int = 0) -> bytes:
    """
    dm-crypt IV mode 'plain':
      IV = LE32(sector_number + iv_offset) + 12*0x00
    (NXP describes it as 32-bit little-endian sector number padded with zeros)
    """
    v = (sector_number + iv_offset) & 0xFFFFFFFF
    return v.to_bytes(4, "little") + b"\x00" * 12


# --- File processing ----------------------------------------------------------
def _parse_key(args: argparse.Namespace) -> bytes:
    # --- key provided directly as hex on CLI ---
    if args.key_hex:
        kh = args.key_hex.strip().lower()
        if kh.startswith("0x"):
            kh = kh[2:]
        if len(kh) not in (32, 48, 64):
            raise ValueError(
                "Invalid --key-hex (expected 32/48/64 hex characters for AES-128/192/256)."
            )
        try:
            return bytes.fromhex(kh)
        except ValueError:
            raise ValueError("Invalid --key-hex (must be a hex string).")

    # --- key provided via file (hex) ---
    if args.key_file_hex:
        with open(args.key_file_hex, "rt", encoding="ascii") as f:
            s = f.read().strip()
        s = s.lower()
        if s.startswith("0x"):
            s = s[2:]
        if len(s) not in (32, 48, 64):
            raise ValueError(
                "Invalid --key-file-hex (expected 32/48/64 hex characters for AES-128/192/256)."
            )
        try:
            return bytes.fromhex(s)
        except ValueError:
            raise ValueError(
                "Invalid --key-file-hex (file must contain only hex characters)."
            )

    # --- key provided via file (binary) ---
    if args.key_file_bin:
        with open(args.key_file_bin, "rb") as f:
            key = f.read()
        if len(key) not in (16, 24, 32):
            raise ValueError(
                "Invalid --key-file-bin (expected 16/24/32 raw bytes for AES-128/192/256)."
            )
        return key

    raise ValueError(
        "Provide exactly one of --key-hex, --key-file-hex, or --key-file-bin."
    )


def transform_file(
    mode: str,
    in_path: str,
    out_path: str,
    key: bytes,
    sector_size: int,
    iv_offset: int,
    start_sector: int,
    pad: bool,
) -> None:
    if sector_size <= 0 or (sector_size & (sector_size - 1)) != 0:
        raise ValueError("--sector-size must be a power of two (e.g. 512, 1024, 4096).")
    if sector_size % 16 != 0:
        raise ValueError("--sector-size must be a multiple of AES block size (16).")

    backend = _load_backend(key)

    in_size = os.path.getsize(in_path)
    if in_size % sector_size != 0:
        if mode == "enc" and pad:
            padded_size = ((in_size + sector_size - 1) // sector_size) * sector_size
        else:
            raise ValueError(
                f"Input size ({in_size}) is not a multiple of sector size ({sector_size}). "
                f"Use --pad-on-encrypt to zero-pad on encryption."
            )
    else:
        padded_size = in_size

    # Stream transform
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        sector_index = 0
        written = 0

        while True:
            chunk = fin.read(sector_size)
            if not chunk:
                break
            if len(chunk) < sector_size:
                if mode == "enc" and pad:
                    chunk = chunk + b"\x00" * (sector_size - len(chunk))
                else:
                    raise RuntimeError("Short read without padding enabled.")

            sector_no = start_sector + sector_index
            iv = iv_plain(sector_no, iv_offset)

            if mode == "enc":
                out = backend.encrypt_sector(iv, chunk)
            else:
                out = backend.decrypt_sector(iv, chunk)

            fout.write(out)
            written += len(out)
            sector_index += 1

        # If we padded beyond EOF, add extra zero sectors (rare unless using a custom reader)
        while written < padded_size:
            sector_no = start_sector + sector_index
            iv = iv_plain(sector_no, iv_offset)
            zeros = b"\x00" * sector_size
            out = backend.encrypt_sector(iv, zeros) if mode == "enc" else backend.decrypt_sector(iv, zeros)
            fout.write(out)
            written += len(out)
            sector_index += 1


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["enc", "dec"], help="Encrypt or decrypt")
    ap.add_argument("--in", dest="in_path", required=True, help="Input file")
    ap.add_argument("--out", dest="out_path", required=True, help="Output file")

    k = ap.add_mutually_exclusive_group(required=True)
    k.add_argument("--key-hex", help="AES key as hex (32/48/64 hex chars => 16/24/32 bytes)")
    k.add_argument("--key-file-hex", help="File containing ASCII hex key")
    k.add_argument("--key-file-bin", help="File containing raw key bytes")

    ap.add_argument("--sector-size", type=int, default=512, help="Encryption sector size (default: 512)")
    ap.add_argument("--iv-offset", type=int, default=0, help="IV offset (dm-crypt table field, default: 0)")
    ap.add_argument("--start-sector", type=int, default=0, help="Start sector number (default: 0)")
    ap.add_argument(
        "--pad-on-encrypt",
        action="store_true",
        help="If input size isn't multiple of sector size, zero-pad on encryption",
    )
    ap.add_argument(
        "--print-sha256",
        action="store_true",
        help="Print SHA256 of input and output (useful to verify enc/dec roundtrip)",
    )

    args = ap.parse_args()

    key = _parse_key(args)

    if args.print_sha256:
        print(f"sha256(in):  {sha256_file(args.in_path)}")

    transform_file(
        mode=args.mode,
        in_path=args.in_path,
        out_path=args.out_path,
        key=key,
        sector_size=args.sector_size,
        iv_offset=args.iv_offset,
        start_sector=args.start_sector,
        pad=args.pad_on_encrypt,
    )

    if args.print_sha256:
        print(f"sha256(out): {sha256_file(args.out_path)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
