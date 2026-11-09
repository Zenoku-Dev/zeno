#!/bin/sh
# zeno installer for Linux / macOS - downloads the latest release binary.
# Usage:  curl -fsSL https://raw.githubusercontent.com/rival-afk/zeno/main/install.sh | sh
set -eu

REPO="rival-afk/zeno"
API="https://api.github.com/repos/$REPO/releases/latest"

# --- detect platform ---
case "$(uname -s)" in
    Linux*)  os=unknown-linux;;
    Darwin*) os=unknown-darwin;;
    *)       echo "[zeno] error: unsupported OS: $(uname -s)" >&2; exit 1;;
esac
case "$(uname -m)" in
    x86_64)               arch=x86_64;;
    aarch64|arm64)        arch=aarch64;;
    *)                    echo "[zeno] error: unsupported arch: $(uname -m)" >&2; exit 1;;
esac

echo "[zeno] fetching latest release info..."
rel_json=$(curl -fsSL "$API") || { echo "[zeno] error: cannot reach GitHub" >&2; exit 1; }
tag=$(printf '%s' "$rel_json" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
[ -n "$tag" ] || { echo "[zeno] error: no releases yet. Run these first (on a fixed tree):" >&2; echo "  git tag v0.2.1 && git push origin v0.2.1" >&2; exit 1; }

asset="zeno-${arch}-${os}-musl.tar.gz"
url=$(printf '%s' "$rel_json" | grep -o "https://[^\"']*${asset}" | head -n 1)
[ -n "$url" ] || {
    echo "[zeno] error: asset '$asset' not found in release $tag" >&2
    echo "[zeno] available assets:" >&2
    printf '%s' "$rel_json" | grep -o '"browser_download_url":[[:space:]]*"[^"]*"' >&2 || true
    exit 1
}

echo "[zeno] downloading $url ..."
tmp=$(mktemp -d /tmp/zeno-setup.XXXXXX)
curl -fsSL "$url" | tar -xz -C "$tmp" --strip-components=1

bindir="$HOME/.local/bin"
mkdir -p "$bindir"
install -m 0755 "$tmp/zeno" "$bindir/zeno"
cp "$tmp/zeno.toml.example" "$tmp/README.md" "$HOME" 2>/dev/null || true
rm -rf "$tmp"

case ":$PATH:" in
    *:"$bindir":*) ;;
    *) echo "[zeno] NOTE: add $bindir to PATH (e.g. add to ~/.profile): export PATH=\"$bindir:\$PATH\"";;
esac

echo ""
echo "[zeno] done! installed $tag -> $bindir/zeno" 
echo "[zeno] quick start:"
echo "       zeno scan /path/to/file-or-folder"
echo "       zeno check    # availability of open databases"
echo "       zeno engines  # list configured engines"
echo "[zeno] optional config: ~/.zeno/config.toml (see ~/zeno.toml.example)"
