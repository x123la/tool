#!/bin/bash
set -e

# Build script for ghostshm releases
# Cross-compiles to x86_64 and aarch64 musl for static binaries.

VERSION="0.1.0"
DIST_DIR="dist"
ZIG_BIN="zig"

# Check if zig is in PATH, otherwise try to find it in tools/
if ! command -v zig &> /dev/null; then
    ZIG_CANDIDATE=$(find "$(pwd)/tools" -name zig -type f -executable | head -n 1)
    if [ -n "$ZIG_CANDIDATE" ]; then
        ZIG_BIN="$ZIG_CANDIDATE"
    else
        echo "Error: zig not found in PATH or tools/ directory."
        exit 1
    fi
fi

echo "Using zig: $($ZIG_BIN version)"

mkdir -p "$DIST_DIR"

targets=(
    "x86_64-linux-musl"
    "aarch64-linux-musl"
)

for target in "${targets[@]}"; do
    echo "--- Building for $target ---"
    $ZIG_BIN build -Doptimize=ReleaseSafe -Dtarget="$target"
    
    OUT_NAME="ghostshm-$VERSION-$target"
    cp zig-out/bin/ghostshm "$DIST_DIR/$OUT_NAME"
    
    (
        cd "$DIST_DIR"
        sha256sum "$OUT_NAME" > "$OUT_NAME.sha256"
    )
done

echo "--- Distribution artifacts ---"
ls -lh "$DIST_DIR"
