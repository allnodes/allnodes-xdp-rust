#!/usr/bin/env bash
# Rebuilds objects/allnodes-xdp-{classifier,dispatcher} from ebpf/ and reports whether a hash
# changed (exit 1 if so).
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
rust_nightly=nightly-2025-12-05
BINS=(allnodes-xdp-classifier allnodes-xdp-dispatcher)

echo "Using nightly toolchain: $rust_nightly"
if ! command -v bpf-linker &> /dev/null; then
    echo "Installing bpf-linker..."
    cargo install bpf-linker --version 0.9.15 --locked
fi
rustup component add rust-src --toolchain "$rust_nightly"

export RUSTFLAGS="--remap-path-prefix=$CRATE_DIR=/src \
--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo \
--remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"

changed=0
for bin in "${BINS[@]}"; do
    out="$CRATE_DIR/objects/$bin"
    before=$(sha256sum "$out" 2>/dev/null | awk '{print $1}')
    cargo +"$rust_nightly" rustc --manifest-path "$CRATE_DIR/ebpf/Cargo.toml" \
        --bin "$bin" --target bpfel-unknown-none --release \
        -Z build-std=core -- -C debuginfo=2 -C link-arg=--btf
    llvm-objcopy --strip-unneeded "$CRATE_DIR/ebpf/target/bpfel-unknown-none/release/$bin" "$out"
    after=$(sha256sum "$out" | awk '{print $1}')
    echo "$bin: ${before:-<missing>} -> $after"
    [ "$before" = "$after" ] || changed=1
done
if [ "$changed" = 1 ]; then
    echo "Hash changed"
    exit 1
fi
echo "Hashes unchanged"
