import unittest

from airbridge.qr import QRTooLong, encode, to_svg, to_text

try:
    import cv2
    import numpy as np
    HAVE_DECODER = True
except ImportError:  # the decoder is a test-only dependency
    HAVE_DECODER = False


def render(matrix, scale=8, quiet=4):
    n = len(matrix) + 2 * quiet
    img = np.full((n, n), 255, np.uint8)
    for r, row in enumerate(matrix):
        for c, on in enumerate(row):
            if on:
                img[r + quiet, c + quiet] = 0
    return cv2.resize(img, (n * scale, n * scale), interpolation=cv2.INTER_NEAREST)


PAYLOADS = [
    "hi",
    "https://192.168.1.20:8765/send#c=784471&f=ba7520c559439499",
    "https://10.0.0.7:8765/send#c=000123&f=0123456789abcdef",
    "x" * 14,    # fills version 1 exactly
    "A" * 26,    # fills version 2 exactly
    "y" * 42,    # fills version 3 exactly
    "z" * 84,    # fills version 5 exactly
]


@unittest.skipUnless(HAVE_DECODER, "opencv-python is needed to decode test codes")
class QRRoundTripTests(unittest.TestCase):
    def test_independent_decoder_reads_every_payload(self):
        detector = cv2.QRCodeDetector()
        for payload in PAYLOADS:
            with self.subTest(length=len(payload)):
                text, _, _ = detector.detectAndDecode(render(encode(payload)))
                self.assertEqual(text, payload)


class QREncoderTests(unittest.TestCase):
    def test_matrix_sizes_follow_the_version_formula(self):
        self.assertEqual(len(encode("hi")), 21)                   # version 1
        self.assertEqual(len(encode("A" * 26)), 25)               # version 2
        self.assertEqual(len(encode("z" * 84)), 37)               # version 5

    def test_payloads_beyond_version_five_are_refused(self):
        with self.assertRaises(QRTooLong):
            encode("q" * 85)

    def test_finder_patterns_are_present_in_three_corners(self):
        m = encode("hi")
        for r0, c0 in ((0, 0), (0, 14), (14, 0)):
            self.assertTrue(all(m[r0][c0 + i] for i in range(7)))       # top edge dark
            self.assertTrue(all(m[r0 + 6][c0 + i] for i in range(7)))   # bottom edge dark
            self.assertTrue(m[r0 + 3][c0 + 3])                          # centre dark

    def test_svg_output_is_well_formed_and_scalable(self):
        svg = to_svg(encode("hi"))
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn('viewBox="0 0 29 29"', svg)
        self.assertNotIn("<script", svg)

    def test_terminal_output_has_expected_height(self):
        text = to_text(encode("hi"))
        self.assertEqual(len(text.splitlines()), (21 + 4 + 1) // 2)


if __name__ == "__main__":
    unittest.main()
