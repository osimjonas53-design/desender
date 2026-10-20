import os
import tempfile
import unittest
from pathlib import Path

from airbridge.pairing import PairingError, PairingManager
from airbridge.protocol import (
    MAX_NAME_LEN,
    resolve_destination,
    sanitize_filename,
    unique_path,
)


class SanitizeFilenameTests(unittest.TestCase):
    def test_strips_traversal_components(self):
        self.assertEqual(sanitize_filename("../../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("..\\..\\evil.exe"), "evil.exe")
        self.assertEqual(sanitize_filename("/abs/path/file.pdf"), "file.pdf")

    def test_removes_control_and_windows_forbidden_characters(self):
        self.assertEqual(sanitize_filename("a\x00b<>.pdf"), "ab.pdf")
        self.assertEqual(sanitize_filename('report: "final"?.docx'), "report final.docx")

    def test_reserved_device_names_are_prefixed(self):
        self.assertEqual(sanitize_filename("CON.txt"), "_CON.txt")
        self.assertEqual(sanitize_filename("lpt1"), "_lpt1")

    def test_dot_only_and_empty_names_are_rejected(self):
        for bad in ("", "..", ".", "...", "   ", None, 42):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sanitize_filename(bad)

    def test_long_names_are_capped_and_keep_extension(self):
        out = sanitize_filename("a" * 300 + ".pdf")
        self.assertLessEqual(len(out), MAX_NAME_LEN)
        self.assertTrue(out.endswith(".pdf"))

    def test_leading_dots_are_stripped_so_no_hidden_files_are_created(self):
        self.assertEqual(sanitize_filename(".bashrc"), "bashrc")


class DestinationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.dst = root / "dst"
        self.outside = root / "outside"
        self.dst.mkdir()
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("keep out")

    def tearDown(self):
        self._tmp.cleanup()

    def test_traversal_lands_inside_save_dir(self):
        target = resolve_destination(self.dst, "../../escape.txt")
        self.assertEqual(target.parent, self.dst.resolve())
        self.assertEqual(target.name, "escape.txt")

    def test_symlink_pointing_outside_is_refused(self):
        link = self.dst / "evil.txt"
        os.symlink(self.outside / "secret.txt", link)
        with self.assertRaises(ValueError):
            resolve_destination(self.dst, "evil.txt")

    def test_unique_path_renames_on_collision(self):
        (self.dst / "notes.txt").write_text("old")
        (self.dst / "notes (1).txt").write_text("older")
        self.assertEqual(unique_path(self.dst / "notes.txt").name, "notes (2).txt")
        self.assertEqual(unique_path(self.dst / "fresh.txt").name, "fresh.txt")


class PairingTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.pm = PairingManager(code_ttl=300, max_attempts=3, session_ttl=600,
                                 clock=lambda: self.now)

    def test_correct_code_yields_token_once(self):
        code = self.pm.new_code()
        token = self.pm.redeem(code)
        self.assertTrue(self.pm.is_valid(token))
        with self.assertRaises(PairingError):
            self.pm.redeem(code)  # single use

    def test_wrong_codes_lock_out_even_the_right_one(self):
        code = self.pm.new_code()
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(3):
            with self.assertRaises(PairingError):
                self.pm.redeem(wrong)
        with self.assertRaises(PairingError):
            self.pm.redeem(code)

    def test_code_expires(self):
        code = self.pm.new_code()
        self.now = 301.0
        with self.assertRaises(PairingError):
            self.pm.redeem(code)

    def test_token_expires_and_can_be_revoked(self):
        token = self.pm.redeem(self.pm.new_code())
        self.now = 599.0
        self.assertTrue(self.pm.is_valid(token))
        self.now = 600.0
        self.assertFalse(self.pm.is_valid(token))

        token2 = self.pm.redeem(self.pm.new_code())
        self.pm.revoke_all()
        self.assertFalse(self.pm.is_valid(token2))

    def test_empty_and_unknown_tokens_are_invalid(self):
        self.assertFalse(self.pm.is_valid(""))
        self.assertFalse(self.pm.is_valid("not-a-token"))
        self.assertFalse(self.pm.is_valid(None))


if __name__ == "__main__":
    unittest.main()
