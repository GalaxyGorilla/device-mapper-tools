import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
BUILD_STACK = REPO / "tools" / "compose" / "build_stack.py"


def run(cmd, cwd=None):
    subprocess.check_call(cmd, cwd=cwd)


def read_manifest(path: Path):
    return json.loads(path.read_text("utf-8"))


class TestStacks(unittest.TestCase):
    def test_build_plain_crypt_only(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            fs = td / "fs.img"
            fs.write_bytes(b"A" * (1024 * 1024))

            outdir = td / "out"
            run(
                [
                    "python3",
                    str(BUILD_STACK),
                    "--in",
                    str(fs),
                    "--outdir",
                    str(outdir),
                    "--stack",
                    "crypt-only",
                    "--profile",
                    "plain-crypt",
                    "--key-hex",
                    "00" * 32,
                ]
            )

            mf = read_manifest(outdir / "manifest.json")
            self.assertEqual(mf["manifest_version"], 1)
            self.assertEqual([x["type"] for x in mf["stack"]], ["raw", "dm-crypt"])
            self.assertIn("data", mf["images"])
            self.assertIn("crypt", mf)
            self.assertEqual(mf["crypt"]["mode"], "plain")

    def test_build_integrity_then_crypt_aead_intent(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            fs = td / "fs.img"
            fs.write_bytes(b"B" * (1024 * 1024))

            outdir = td / "out"
            run(
                [
                    "python3",
                    str(BUILD_STACK),
                    "--in",
                    str(fs),
                    "--outdir",
                    str(outdir),
                    "--stack",
                    "integrity-then-crypt",
                    "--profile",
                    "aead",
                    "--integrity-tag-size",
                    "16",
                ]
            )

            mf = read_manifest(outdir / "manifest.json")
            self.assertEqual([x["type"] for x in mf["stack"]], ["raw", "dm-integrity", "dm-crypt"])
            self.assertIn("integrity_meta", mf["images"])
            self.assertEqual(mf["integrity"]["tag_size"], 16)
            self.assertEqual(mf["crypt"]["mode"], "aead")
            self.assertEqual(mf["crypt"]["aead"]["tag_size"], 16)

    def test_build_verity_only(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            fs = td / "fs.img"
            fs.write_bytes(b"C" * (1024 * 1024 + 123))

            outdir = td / "out"
            run(
                [
                    "python3",
                    str(BUILD_STACK),
                    "--in",
                    str(fs),
                    "--outdir",
                    str(outdir),
                    "--stack",
                    "verity-only",
                    "--profile",
                    "aead",
                ]
            )

            mf = read_manifest(outdir / "manifest.json")
            self.assertEqual([x["type"] for x in mf["stack"]], ["raw", "dm-verity"])
            self.assertIn("verity_hash", mf["images"])
            self.assertIn("verity", mf)
            self.assertTrue(len(mf["verity"]["root_hash_hex"]) >= 32)


if __name__ == "__main__":
    unittest.main()
