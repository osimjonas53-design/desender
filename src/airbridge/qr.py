"""Minimal QR code encoder for pairing links.

Scope: byte mode, error-correction level M, versions 1 to 5 (up to 84 bytes),
mask pattern 0. That covers an address-plus-fingerprint pairing link. The
encoder is checked against an independent decoder in tests/test_qr.py, so a
mistake in the tables would fail there rather than on a user's screen.
"""
from __future__ import annotations

# version -> (total codewords, EC codewords per block, [(block count, data codewords per block)])
_EC_M = {
    1: (26, 10, [(1, 16)]),
    2: (44, 16, [(1, 28)]),
    3: (70, 26, [(1, 44)]),
    4: (100, 18, [(2, 32)]),
    5: (134, 24, [(2, 43)]),
}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30]}
_FORMAT_MASK = 0x5412
_FORMAT_GEN = 0x537  # BCH(15,5) generator for format information


class QRTooLong(ValueError):
    pass


# ----- Reed-Solomon over GF(256) with primitive polynomial 0x11D ------------
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _poly_mul(p: list[int], q: list[int]) -> list[int]:
    out = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            out[i + j] ^= _gf_mul(a, b)
    return out


def _rs_generator(n: int) -> list[int]:
    gen = [1]
    for i in range(n):
        gen = _poly_mul(gen, [1, _EXP[i]])
    return gen


def _rs_encode(data: list[int], n: int) -> list[int]:
    gen = _rs_generator(n)
    rem = list(data) + [0] * n
    for i in range(len(data)):
        coef = rem[i]
        if coef:
            for j in range(1, len(gen)):
                rem[i + j] ^= _gf_mul(gen[j], coef)
    return rem[len(data):]


# ----- codeword construction -------------------------------------------------
def _capacity_bytes(version: int) -> int:
    data_cw = sum(count * dn for count, dn in _EC_M[version][2])
    return (data_cw * 8 - 12) // 8   # 4 mode bits + 8 count bits


def _data_codewords(data: bytes, version: int) -> list[int]:
    total_data = sum(count * dn for count, dn in _EC_M[version][2])
    bits = "0100" + format(len(data), "08b") + "".join(format(b, "08b") for b in data)
    capacity_bits = total_data * 8
    bits += "0" * min(4, capacity_bits - len(bits))
    bits += "0" * ((8 - len(bits) % 8) % 8)
    out = [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]
    pad = (0xEC, 0x11)
    i = 0
    while len(out) < total_data:
        out.append(pad[i % 2])
        i += 1
    return out


def _interleave(data: list[int], version: int) -> list[int]:
    _, ec_n, groups = _EC_M[version]
    blocks: list[list[int]] = []
    pos = 0
    for count, dn in groups:
        for _ in range(count):
            blocks.append(data[pos:pos + dn])
            pos += dn
    ec_blocks = [_rs_encode(b, ec_n) for b in blocks]
    out: list[int] = []
    for i in range(max(len(b) for b in blocks)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec_n):
        for e in ec_blocks:
            out.append(e[i])
    return out


# ----- matrix construction ---------------------------------------------------
def _format_bits(ec_bits: int, mask: int) -> int:
    data = (ec_bits << 3) | mask
    rem = data << 10
    for i in range(14, 9, -1):
        if rem >> i & 1:
            rem ^= _FORMAT_GEN << (i - 10)
    return ((data << 10) | rem) ^ _FORMAT_MASK


def _build(version: int, codewords: list[int]) -> list[list[bool]]:
    size = 17 + 4 * version
    dark = [[False] * size for _ in range(size)]
    reserved = [[False] * size for _ in range(size)]

    def put(r: int, c: int, value: bool) -> None:
        dark[r][c] = value
        reserved[r][c] = True

    # Finder patterns with separators.
    for r0, c0 in ((0, 0), (0, size - 7), (size - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = r0 + dr, c0 + dc
                if 0 <= r < size and 0 <= c < size:
                    inside = 0 <= dr <= 6 and 0 <= dc <= 6
                    on_ring = inside and (dr in (0, 6) or dc in (0, 6))
                    centre = inside and 2 <= dr <= 4 and 2 <= dc <= 4
                    put(r, c, on_ring or centre)

    # Timing patterns.
    for i in range(8, size - 8):
        if not reserved[6][i]:
            put(6, i, i % 2 == 0)
        if not reserved[i][6]:
            put(i, 6, i % 2 == 0)

    # Alignment patterns.
    centres = _ALIGN[version]
    for r in centres:
        for c in centres:
            if (r == 6 and c == 6) or (r == 6 and c == centres[-1]) or (r == centres[-1] and c == 6):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    put(r + dr, c + dc, max(abs(dr), abs(dc)) != 1)

    # Dark module and reserved format-information areas.
    put(size - 8, 8, True)
    for i in range(9):
        if not reserved[8][i]:
            put(8, i, False)
        if not reserved[i][8]:
            put(i, 8, False)
    for i in range(8):
        if not reserved[8][size - 1 - i]:
            put(8, size - 1 - i, False)
    for i in range(7):
        if not reserved[size - 1 - i][8]:
            put(size - 1 - i, 8, False)

    # Data placement, zigzag from the bottom-right corner.
    bits = [(cw >> (7 - b)) & 1 for cw in codewords for b in range(8)]
    idx = 0
    col = size - 1
    upward = True
    while col >= 1:
        if col == 6:
            col = 5
        rows = range(size - 1, -1, -1) if upward else range(size)
        for r in rows:
            for c in (col, col - 1):
                if not reserved[r][c]:
                    dark[r][c] = bool(bits[idx]) if idx < len(bits) else False
                    idx += 1
        col -= 2
        upward = not upward

    # Mask pattern 0: flip data modules where (row + column) is even.
    for r in range(size):
        for c in range(size):
            if not reserved_data(reserved, r, c) and (r + c) % 2 == 0:
                dark[r][c] = not dark[r][c]

    # Format information (EC level M = 0b00, mask 0).
    fmt = _format_bits(0b00, 0)
    first = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
             (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    second = [(size - 1, 8), (size - 2, 8), (size - 3, 8), (size - 4, 8), (size - 5, 8),
              (size - 6, 8), (size - 7, 8), (8, size - 8), (8, size - 7), (8, size - 6),
              (8, size - 5), (8, size - 4), (8, size - 3), (8, size - 2), (8, size - 1)]
    for coords in (first, second):
        for idx_f, (r, c) in enumerate(coords):
            dark[r][c] = bool((fmt >> (14 - idx_f)) & 1)
    return dark


def reserved_data(reserved: list[list[bool]], r: int, c: int) -> bool:
    return reserved[r][c]


def encode(payload: str | bytes) -> list[list[bool]]:
    """Return the QR matrix (True = dark) for ``payload``."""
    data = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    for version in sorted(_EC_M):
        if len(data) <= _capacity_bytes(version):
            break
    else:
        raise QRTooLong(f"payload of {len(data)} bytes is longer than this encoder supports")
    codewords = _interleave(_data_codewords(data, version), version)
    return _build(version, codewords)


def to_svg(matrix: list[list[bool]], quiet_zone: int = 4) -> str:
    n = len(matrix) + 2 * quiet_zone
    cells = []
    for r, row in enumerate(matrix):
        for c, on in enumerate(row):
            if on:
                cells.append(f"M{c + quiet_zone} {r + quiet_zone}h1v1h-1z")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" '
            f'width="{n * 6}" height="{n * 6}" shape-rendering="crispEdges">'
            f'<rect width="{n}" height="{n}" fill="#ffffff"/>'
            f'<path fill="#000000" d="{"".join(cells)}"/></svg>')


def to_text(matrix: list[list[bool]], quiet_zone: int = 2) -> str:
    """Terminal rendering using half-block characters (two rows per line)."""
    size = len(matrix)
    total = size + 2 * quiet_zone

    def dark(r: int, c: int) -> bool:
        if 0 <= r - quiet_zone < size and 0 <= c - quiet_zone < size:
            return matrix[r - quiet_zone][c - quiet_zone]
        return False

    lines = []
    for r in range(0, total, 2):
        line = []
        for c in range(total):
            top, bottom = dark(r, c), dark(r + 1, c)
            line.append("█" if top and bottom else "▀" if top else "▄" if bottom else " ")
        lines.append("".join(line))
    return "\n".join(lines)
