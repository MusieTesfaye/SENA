#!/usr/bin/env python3
"""Generates the Aptos L1 Poseidon modules.

Aptos L1 needs Poseidon only at state width 15 (14 inputs): the Aptos Keyless
circuit's public-input hash. The textbook permutation allocates ~33k field
elements, which exceeds `crypto_algebra`'s 1 MiB per-transaction element
budget, so L1 uses circomlib's *optimised* form (`poseidon_opt`, after
filecoin's neptune): identical outputs, sparse matrices in the partial rounds.

Inputs:
  1. crates/sena-stf/src/poseidon_constants.bin (the pinned plain constants)
  2. circomlibjs src/poseidon_constants_opt.js (the published optimised ones)

Before writing anything this script implements both forms in Python and checks
they agree on several inputs, so the optimised constants are validated against
the same plain constants the Rust implementation pins.

Outputs: move/sena/sources/poseidon.move and poseidon_sparse.move
"""
import json
import re
import sys

P_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
WIDTH = 15
N = WIDTH - 1


def plain_constants(path):
    data = open(path, "rb").read()
    at = 0
    while True:
        t = int.from_bytes(data[at:at + 2], "little")
        p = int.from_bytes(data[at + 2:at + 4], "little")
        at += 4
        n_rc, n_m = (8 + p) * t, t * t
        vals = [int.from_bytes(data[at + 32 * i:at + 32 * (i + 1)], "little") for i in range(n_rc + n_m)]
        at += 32 * (n_rc + n_m)
        if t == WIDTH:
            return p, vals[:n_rc], vals[n_rc:]


def opt_constants(path):
    src = open(path).read()
    body = src[src.index("{"):src.rindex("}") + 1]
    obj = json.loads(body)
    t = WIDTH
    conv = lambda x: int(x, 16) if isinstance(x, str) else x
    C = [conv(x) for x in obj["C"][t - 2]]
    S = [conv(x) for x in obj["S"][t - 2]]
    M = [[conv(x) for x in row] for row in obj["M"][t - 2]]
    P = [[conv(x) for x in row] for row in obj["P"][t - 2]]
    return C, S, M, P


def pow5(a):
    return pow(a, 5, P_MOD)


def plain_hash(inputs, partial, rc, mds):
    t = len(inputs) + 1
    state = [0] + list(inputs)
    for r in range(8 + partial):
        state = [(s + rc[r * t + i]) % P_MOD for i, s in enumerate(state)]
        if r < 4 or r >= 4 + partial:
            state = [pow5(s) for s in state]
        else:
            state[0] = pow5(state[0])
        state = [sum(mds[i * t + j] * state[j] for j in range(t)) % P_MOD for i in range(t)]
    return state[0]


def opt_hash(inputs, partial, C, S, M, P):
    t = len(inputs) + 1
    nf = 8
    state = [0] + list(inputs)
    state = [(a + C[i]) % P_MOD for i, a in enumerate(state)]
    for r in range(nf // 2 - 1):
        state = [pow5(a) for a in state]
        state = [(a + C[(r + 1) * t + i]) % P_MOD for i, a in enumerate(state)]
        state = [sum(M[j][i] * state[j] for j in range(t)) % P_MOD for i in range(t)]
    state = [pow5(a) for a in state]
    state = [(a + C[(nf // 2 - 1 + 1) * t + i]) % P_MOD for i, a in enumerate(state)]
    state = [sum(P[j][i] * state[j] for j in range(t)) % P_MOD for i in range(t)]
    for r in range(partial):
        state[0] = pow5(state[0])
        state[0] = (state[0] + C[(nf // 2 + 1) * t + r]) % P_MOD
        s0 = sum(S[(t * 2 - 1) * r + j] * state[j] for j in range(t)) % P_MOD
        for k in range(1, t):
            state[k] = (state[k] + state[0] * S[(t * 2 - 1) * r + t + k - 1]) % P_MOD
        state[0] = s0
    for r in range(nf // 2 - 1):
        state = [pow5(a) for a in state]
        state = [(a + C[(nf // 2 + 1) * t + partial + r * t + i]) % P_MOD for i, a in enumerate(state)]
        state = [sum(M[j][i] * state[j] for j in range(t)) % P_MOD for i in range(t)]
    state = [pow5(a) for a in state]
    state = [sum(M[j][i] * state[j] for j in range(t)) % P_MOD for i in range(t)]
    return state[0]


def le(v):
    return v.to_bytes(32, "little").hex()


def vec(items):
    return "vector[\n" + ",\n".join(f'        x"{le(v)}"' for v in items) + "\n    ]"


def main():
    partial, rc, mds = plain_constants(sys.argv[1])
    C, S, M, P = opt_constants(sys.argv[2])
    assert len(C) == 5 * WIDTH + partial + 3 * WIDTH, len(C)
    assert len(S) == (2 * WIDTH - 1) * partial
    for v in C + S + sum(M, []) + sum(P, []):
        assert 0 <= v < P_MOD

    vectors = [list(range(1, N + 1)), [0] * N, [P_MOD - 1 - i for i in range(N)],
               [(i * 0x9e3779b97f4a7c15) % P_MOD for i in range(N)]]
    for inputs in vectors:
        a = plain_hash(inputs, partial, rc, mds)
        b = opt_hash(inputs, partial, C, S, M, P)
        assert a == b, (inputs, a, b)
    expected_1_to_14 = plain_hash(list(range(1, N + 1)), partial, rc, mds)
    assert expected_1_to_14 == 8354478399926161176778659061636406690034081872658507739535256090879947077494

    # M and P are used transposed (M[j][i]); flatten them that way, so the Move
    # code reads row-major: entry (i, j) of the flattened matrix is M[j][i].
    Mt = [M[j][i] for i in range(WIDTH) for j in range(WIDTH)]
    Pt = [P[j][i] for i in range(WIDTH) for j in range(WIDTH)]

    header = "// GENERATED by scripts/gen_poseidon_move.py. Do not edit by hand.\n"
    sparse = header + f'''
/// The sparse partial-round matrices of width-15 optimised Poseidon, split out
/// of `sena::poseidon` only to keep each module under the 64 KiB payload limit.
module sena::poseidon_sparse {{
    /// (2T - 1) * PARTIAL_ROUNDS entries, little-endian.
    const S: vector<vector<u8>> = {vec(S)};

    public fun constants(): vector<vector<u8>> {{ S }}
}}
'''
    main_mod = header + f'''
/// Poseidon over BN254 at state width {WIDTH} (14 inputs), with outputs
/// identical to circomlib's `Poseidon(14)`.
///
/// The one Poseidon instance Aptos L1 needs: the Aptos Keyless circuit's
/// public-input hash (`sena::keyless`). It is circomlib's optimised form
/// (`poseidon_opt`): the textbook permutation allocates more field elements
/// than `crypto_algebra` allows in one transaction. The generator checks the
/// optimised constants against the plain ones `sena_stf::poseidon` pins, and
/// the test below pins the output to aptos-core's.
module sena::poseidon {{
    use std::option;
    use std::vector;
    use aptos_std::crypto_algebra::{{Self, Element}};
    use aptos_std::bn254_algebra::{{Fr, FormatFrLsb}};
    use sena::poseidon_sparse;

    /// Exactly 14 inputs are accepted.
    const E_WRONG_ARITY: u64 = 1;

    const T: u64 = {WIDTH};
    const HALF_FULL: u64 = 4;
    const PARTIAL_ROUNDS: u64 = {partial};

    /// Optimised round constants, little-endian.
    const C: vector<vector<u8>> = {vec(C)};

    /// The MDS matrix, transposed, row-major, little-endian.
    const M: vector<vector<u8>> = {vec(Mt)};

    /// The pre-sparse matrix, transposed, row-major, little-endian.
    const P: vector<vector<u8>> = {vec(Pt)};

    fun fr(bytes: &vector<u8>): Element<Fr> {{
        option::extract(&mut crypto_algebra::deserialize<Fr, FormatFrLsb>(bytes))
    }}

    fun pow5(x: &Element<Fr>): Element<Fr> {{
        let x2 = crypto_algebra::sqr(x);
        let x4 = crypto_algebra::sqr(&x2);
        crypto_algebra::mul(&x4, x)
    }}

    fun pow5_all(state: &mut vector<Element<Fr>>) {{
        let i = 0;
        while (i < T) {{
            let s = vector::borrow_mut(state, i);
            *s = pow5(s);
            i = i + 1;
        }};
    }}

    fun add_constants(state: &mut vector<Element<Fr>>, c: &vector<vector<u8>>, offset: u64) {{
        let i = 0;
        while (i < T) {{
            let s = vector::borrow_mut(state, i);
            *s = crypto_algebra::add(s, &fr(vector::borrow(c, offset + i)));
            i = i + 1;
        }};
    }}

    /// state := matrix * state, for a row-major T x T matrix.
    fun mix(state: &vector<Element<Fr>>, matrix: &vector<Element<Fr>>): vector<Element<Fr>> {{
        let out = vector::empty<Element<Fr>>();
        let row = 0;
        while (row < T) {{
            let acc = crypto_algebra::zero<Fr>();
            let col = 0;
            while (col < T) {{
                let term = crypto_algebra::mul(vector::borrow(matrix, row * T + col), vector::borrow(state, col));
                acc = crypto_algebra::add(&acc, &term);
                col = col + 1;
            }};
            vector::push_back(&mut out, acc);
            row = row + 1;
        }};
        out
    }}

    fun load(bytes: &vector<vector<u8>>): vector<Element<Fr>> {{
        let out = vector::empty<Element<Fr>>();
        let i = 0;
        let n = vector::length(bytes);
        while (i < n) {{
            vector::push_back(&mut out, fr(vector::borrow(bytes, i)));
            i = i + 1;
        }};
        out
    }}

    /// Hashes exactly 14 field elements.
    public fun hash14(inputs: &vector<Element<Fr>>): Element<Fr> {{
        assert!(vector::length(inputs) == T - 1, E_WRONG_ARITY);
        let c = C;
        let m = load(&M);
        let p = load(&P);
        let s_bytes = poseidon_sparse::constants();

        let state = vector::singleton(crypto_algebra::zero<Fr>());
        vector::append(&mut state, *inputs);
        add_constants(&mut state, &c, 0);

        let r = 0;
        while (r < HALF_FULL - 1) {{
            pow5_all(&mut state);
            add_constants(&mut state, &c, (r + 1) * T);
            state = mix(&state, &m);
            r = r + 1;
        }};
        pow5_all(&mut state);
        add_constants(&mut state, &c, HALF_FULL * T);
        state = mix(&state, &p);

        let r = 0;
        while (r < PARTIAL_ROUNDS) {{
            let s0 = vector::borrow_mut(&mut state, 0);
            *s0 = pow5(s0);
            *s0 = crypto_algebra::add(s0, &fr(vector::borrow(&c, (HALF_FULL + 1) * T + r)));
            let base = (2 * T - 1) * r;
            let acc = crypto_algebra::zero<Fr>();
            let j = 0;
            while (j < T) {{
                let term = crypto_algebra::mul(&fr(vector::borrow(&s_bytes, base + j)), vector::borrow(&state, j));
                acc = crypto_algebra::add(&acc, &term);
                j = j + 1;
            }};
            let first = *vector::borrow(&state, 0);
            let k = 1;
            while (k < T) {{
                let term = crypto_algebra::mul(&first, &fr(vector::borrow(&s_bytes, base + T + k - 1)));
                let sk = vector::borrow_mut(&mut state, k);
                *sk = crypto_algebra::add(sk, &term);
                k = k + 1;
            }};
            *vector::borrow_mut(&mut state, 0) = acc;
            r = r + 1;
        }};

        let r = 0;
        while (r < HALF_FULL - 1) {{
            pow5_all(&mut state);
            add_constants(&mut state, &c, (HALF_FULL + 1) * T + PARTIAL_ROUNDS + r * T);
            state = mix(&state, &m);
            r = r + 1;
        }};
        pow5_all(&mut state);
        state = mix(&state, &m);
        *vector::borrow(&state, 0)
    }}

    #[test]
    /// Poseidon(1, 2, ..., 14), as aptos-core's `poseidon_bn254::hash_scalars`
    /// and `sena_stf::poseidon` both compute it.
    fun matches_aptos_at_arity_14() {{
        let inputs = vector::empty<Element<Fr>>();
        let i = 1;
        while (i <= 14) {{
            vector::push_back(&mut inputs, crypto_algebra::from_u64<Fr>(i));
            i = i + 1;
        }};
        let expected = fr(&x"{le(expected_1_to_14)}");
        assert!(crypto_algebra::eq(&hash14(&inputs), &expected), 0);
    }}
}}
'''
    out_dir = sys.argv[3]
    open(f"{out_dir}/poseidon.move", "w").write(main_mod)
    open(f"{out_dir}/poseidon_sparse.move", "w").write(sparse)
    print(f"ok: optimised constants agree with the plain ones on {len(vectors)} vectors; "
          f"C={len(C)} S={len(S)} M,P={WIDTH}x{WIDTH}")


if __name__ == "__main__":
    main()
