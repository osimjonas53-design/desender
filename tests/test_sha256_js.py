import hashlib
import json
import os
import shutil
import subprocess
import unittest

WEB = os.path.join(os.path.dirname(__file__), "..", "src", "airbridge", "web", "sha256.js")

NODE_SCRIPT = r"""
const { Sha256 } = require(process.argv[1]);
const inputs = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = inputs.map((hex) => {
  const bytes = Buffer.from(hex, 'hex');
  const whole = new Sha256().update(new Uint8Array(bytes)).hex();
  // Feed the same bytes in uneven pieces to exercise the internal buffer.
  const h = new Sha256();
  let i = 0, step = 3;
  while (i < bytes.length) {
    const k = Math.min(step, bytes.length - i);
    h.update(new Uint8Array(bytes.subarray(i, i + k)));
    i += k;
    step = (step * 5 + 1) % 97 + 1;
  }
  return [whole, h.hex()];
});
process.stdout.write(JSON.stringify(out));
"""


@unittest.skipUnless(shutil.which("node"), "node is needed to run the browser hash code")
class BrowserSha256Tests(unittest.TestCase):
    def test_matches_hashlib_across_padding_boundaries(self):
        sizes = [0, 1, 2, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 1000, 4096, 70001]
        inputs = [os.urandom(n).hex() for n in sizes]
        result = subprocess.run(
            ["node", "-e", NODE_SCRIPT, os.path.abspath(WEB)],
            input=json.dumps(inputs), capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        digests = json.loads(result.stdout)
        for size, hex_in, (whole, pieces) in zip(sizes, inputs, digests):
            want = hashlib.sha256(bytes.fromhex(hex_in)).hexdigest()
            with self.subTest(size=size):
                self.assertEqual(whole, want)
                self.assertEqual(pieces, want)

    def test_known_vectors(self):
        vectors = {
            b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        }
        result = subprocess.run(
            ["node", "-e", NODE_SCRIPT, os.path.abspath(WEB)],
            input=json.dumps([k.hex() for k in vectors]), capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for (msg, want), (whole, _) in zip(vectors.items(), json.loads(result.stdout)):
            self.assertEqual(whole, want)


if __name__ == "__main__":
    unittest.main()
