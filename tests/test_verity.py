import tempfile
import unittest
from pathlib import Path

from tools.dm_verity.dm_verity_build import build_hash_tree


class TestVerity(unittest.TestCase):
    def test_verity_build_roundtrip_size(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            data = td / "data.img"
            # 3 blocks + a bit
            data.write_bytes(b"X" * (4096 * 3 + 123))

            out = td / "hash.img"
            res = build_hash_tree(
                str(data),
                str(out),
                alg="sha256",
                data_block_size=4096,
                hash_block_size=4096,
                salt=b"",
            )

            self.assertEqual(len(res.root_hash_hex), 64)
            self.assertTrue(out.exists())
            self.assertEqual(out.stat().st_size, res.tree_bytes)
            self.assertGreaterEqual(res.levels, 1)


if __name__ == "__main__":
    unittest.main()
