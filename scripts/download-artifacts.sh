#!/usr/bin/env bash
# download-artifacts.sh — download the official Agent Games circuit artifacts
# into circuits/artifacts/ and verify their SHA-256 checksums.
#
# Idempotent: files that already exist with a matching checksum are skipped.
# Artifacts are NOT committed to git (see .gitignore); run this script after
# cloning, and in the Dockerfile build.
#
# Source: the official circuit-info API (https://agentgames.zkverify.io/api/circuit-info).
# Checksums below were verified against the official downloads on 2026-11-21
# and cross-checked against the public reference repo xomplex/muse-agent
# (circuits/artifacts/CHECKSUMS.txt) — all five match.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACTS_DIR="${CIRCUIT_DIR:-$SCRIPT_DIR/../circuits/artifacts}"
BASE_URL="https://agentgames.zkverify.io/circuits"
INFO_URL="https://agentgames.zkverify.io/api/circuit-info"

mkdir -p "$ARTIFACTS_DIR"

declare -A EXPECTED=(
  ["gatekeeper.wasm"]="be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f"
  ["gatekeeper_final.zkey"]="adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d"
  ["vfy-policy.wasm"]="bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2"
  ["vfy-policy_final.zkey"]="f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41"
  ["circuit-info.json"]="978b40df96f9ce48fb157f259753bd64fa4565b6a8dee9ddc88b56f7733b1f30"
)

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

download_one() {
  local name="$1" url="$2"
  local dest="$ARTIFACTS_DIR/$name"
  if [ -f "$dest" ] && [ "$(sha256_of "$dest")" = "${EXPECTED[$name]}" ]; then
    echo "OK (cached, checksum matches): $name"
    return 0
  fi
  echo "Downloading $name ..."
  curl -fsSL --max-time 300 -o "$dest.tmp" "$url"
  mv "$dest.tmp" "$dest"
  if [ "$(sha256_of "$dest")" != "${EXPECTED[$name]}" ]; then
    echo "ERROR: checksum mismatch for $name" >&2
    echo "  expected: ${EXPECTED[$name]}" >&2
    echo "  actual:   $(sha256_of "$dest")" >&2
    rm -f "$dest"
    exit 1
  fi
  echo "OK (verified): $name"
}

download_one "gatekeeper.wasm"         "$BASE_URL/gatekeeper.wasm"
download_one "gatekeeper_final.zkey"   "$BASE_URL/gatekeeper_final.zkey"
download_one "vfy-policy.wasm"         "$BASE_URL/vfy-policy.wasm"
download_one "vfy-policy_final.zkey"   "$BASE_URL/vfy-policy_final.zkey"
download_one "circuit-info.json"       "$INFO_URL"

# Regenerate CHECKSUMS.txt from the verified files.
( cd "$ARTIFACTS_DIR" && sha256sum gatekeeper.wasm gatekeeper_final.zkey vfy-policy.wasm vfy-policy_final.zkey circuit-info.json > CHECKSUMS.txt )
cp "$ARTIFACTS_DIR/CHECKSUMS.txt" "$SCRIPT_DIR/../circuits/CHECKSUMS.txt"

echo "All artifacts verified in $ARTIFACTS_DIR"
