#!/bin/sh
# zeno installer for Linux / macOS.
# Usage:  curl -fsSL https://raw.githubusercontent.com/rival-afk/zeno/main/install.sh | sh
set -eu

REPO_URL="https://github.com/rival-afk/zeno"

ensure_cargo() {
    if command -v cargo >/dev/null 2>&1; then
        return 0
    fi
    echo "[zeno] rust is not installed - installing toolchain via rustup (minimal profile)"
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    else
        echo "[zeno] error: need curl or wget to bootstrap rust" >&2
        exit 1
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
}

fetch_sources() {
    tmp="$(mktemp -d /tmp/zeno-setup.XXXXXX)"
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 "$REPO_URL.git" "$tmp"
    else
        echo "[zeno] git not found, falling back to tarball"
        curl -sSL "$REPO_URL/tarball/main" | tar -xz -C "$tmp" --strip-components=1
    fi
}

ensure_cargo
echo "[zeno] fetching sources..."
fetch_sources
echo "[zeno] building (this takes a few minutes on first run)..."
cargo install --path "$tmp" --locked 2>/dev/null || cargo install --path "$tmp"
rm -rf "$tmp"

echo ""
echo "[zeno] done! Binary: $(command -v zeno)"
echo "[zeno] quick start:"
echo "       zeno scan /path/to/file-or-folder"
echo "       zeno check   # availability of open databases"
echo "       zeno engines # list configured engines"
echo "[zeno] optional config: ~/.zeno/config.toml (see zeno.toml.example in repo)"
