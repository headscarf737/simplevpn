#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
    echo "SimpleVPN requires Apple Silicon macOS." >&2
    exit 1
fi

cargo_target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
mkdir -p "$cargo_target_dir"
cargo_target_dir="$(cd "$cargo_target_dir" && pwd)"
cargo build --manifest-path "$project_dir/Cargo.toml" --locked --release \
    --target aarch64-apple-darwin --target-dir "$cargo_target_dir"
export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-$project_dir/target/macos/module-cache}"
export SWIFTPM_MODULECACHE_OVERRIDE="${SWIFTPM_MODULECACHE_OVERRIDE:-$project_dir/target/macos/module-cache}"
swift_options=(--package-path "$project_dir/macos"
    --scratch-path "$project_dir/target/macos/swift" --configuration release --arch arm64
    --cache-path "$project_dir/target/macos/cache"
    --config-path "$project_dir/target/macos/config"
    --security-path "$project_dir/target/macos/security" "$@")
swift build "${swift_options[@]}"
swift_bin="$(swift build "${swift_options[@]}" --show-bin-path)"

app_dir="${SIMPLEVPN_APP_DIR:-$project_dir/target/macos/SimpleVPN.app}"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Helpers"
cp "$project_dir/macos/Info.plist" "$app_dir/Contents/Info.plist"
cp "$swift_bin/SimpleVPNMenuBar" "$app_dir/Contents/MacOS/SimpleVPNMenuBar"
cp "$cargo_target_dir/aarch64-apple-darwin/release/simplevpn" "$app_dir/Contents/Helpers/simplevpn"
codesign --force --sign - "$app_dir/Contents/Helpers/simplevpn"
codesign --force --sign - "$app_dir"
echo "Built $app_dir"
