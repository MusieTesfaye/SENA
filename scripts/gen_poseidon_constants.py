#!/usr/bin/env python3
"""Regenerates crates/sena-stf/src/poseidon_constants.bin.

Input: aptos-core `crates/aptos-crypto/src/poseidon_bn254/constants.rs`, which
carries the circomlib Poseidon-BN254 constants (from arnaucube/poseidon-rs) that
the Aptos Keyless circuit uses. Output layout, for t = 2..=17 in order:

    u16 LE  t
    u16 LE  partial rounds
    (8 + P) * t   round constants, 32-byte little-endian field elements
    t * t         MDS entries, row-major, 32-byte little-endian

Usage: gen_poseidon_constants.py <path to constants.rs> <output .bin>
"""
import re
import sys

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
PARTIAL = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]


def parse(src):
    body = src[src.index("pub fn constants()"):]
    c_part = body[body.index("let c_str"):body.index("let m_str")]
    m_part = body[body.index("let m_str"):]

    def nums(text):
        return [int(x) for x in re.findall(r'"(\d+)"', text)]

    # Split C into one list per width by the top-level `vec![` blocks.
    c_blocks = re.split(r"\n        vec!\[", c_part)[1:]
    cs = [nums(b) for b in c_blocks]
    m_blocks = re.split(r"\n        vec!\[", m_part)[1:]
    ms = [nums(b) for b in m_blocks]
    return cs, ms


def main():
    src = open(sys.argv[1]).read()
    cs, ms = parse(src)
    assert len(cs) == 16 and len(ms) == 16, (len(cs), len(ms))
    out = bytearray()
    for i in range(16):
        t = i + 2
        p = PARTIAL[i]
        assert len(cs[i]) == (8 + p) * t, (t, len(cs[i]))
        assert len(ms[i]) == t * t, (t, len(ms[i]))
        out += t.to_bytes(2, "little") + p.to_bytes(2, "little")
        for v in cs[i] + ms[i]:
            assert 0 <= v < P
            out += v.to_bytes(32, "little")
    open(sys.argv[2], "wb").write(out)
    print(f"wrote {len(out)} bytes")


if __name__ == "__main__":
    main()
