#!/usr/bin/env bash
#
# Builds sena-wasm into a JavaScript package for browsers and Bun.
#
# Prerequisites: `rustup target add wasm32-unknown-unknown` and
# `cargo install wasm-bindgen-cli --version 0.2.100` (must match the crate's
# wasm-bindgen version).
#
# Usage: scripts/build-wasm.sh [out-dir]   (default: target/sena-wasm)

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$REPO/target/sena-wasm}

cargo build --manifest-path "$REPO/Cargo.toml" -p sena-wasm \
  --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir "$OUT" \
  "$REPO/target/wasm32-unknown-unknown/release/sena_wasm.wasm"
echo "sena-wasm written to $OUT"
