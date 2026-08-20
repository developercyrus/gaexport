#!/usr/bin/env bash
# Builds the static site: the Rust decoder as WebAssembly plus the same UI the
# local server serves. The result is a plain directory of files — no backend, so
# it can be hosted on GitHub Pages (or any static host) without ever receiving
# anyone's secrets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${1:-$ROOT/dist}"

command -v wasm-pack >/dev/null || {
  echo "wasm-pack is required: cargo install wasm-pack (or brew install wasm-pack)" >&2
  exit 1
}

echo "▸ building WebAssembly → $DIST/pkg"
rm -rf "$DIST"
mkdir -p "$DIST"
wasm-pack build "$ROOT" \
  --release --target web --no-typescript --no-pack \
  --out-dir "$DIST/pkg" \
  -- --no-default-features --features wasm

echo "▸ copying UI"
cp "$ROOT/assets/index.html" "$ROOT/assets/app.css" "$ROOT/assets/app.js" \
   "$ROOT/assets/i18n.js" "$ROOT/web/boot.js" "$DIST/"

# A GitHub Pages custom domain, if the deployer wants one. It is deliberately
# not in the source tree: set PAGES_CNAME (the `pages` workflow passes the
# repository variable of the same name), or drop a local, git-ignored
# web/CNAME. Without either, the site lives at <user>.github.io/<repo>.
if [ -n "${PAGES_CNAME:-}" ]; then
  echo "$PAGES_CNAME" > "$DIST/CNAME"
  echo "▸ custom domain: $PAGES_CNAME"
elif [ -f "$ROOT/web/CNAME" ]; then
  cp "$ROOT/web/CNAME" "$DIST/"
  echo "▸ custom domain: $(cat "$ROOT/web/CNAME")"
fi

echo "▸ wiring the WASM loader into index.html"
python3 - "$DIST/index.html" <<'PY'
import sys
path = sys.argv[1]
html = open(path, encoding='utf-8').read()
needle = '<script src="i18n.js" defer></script>'
loader = '<script type="module" src="boot.js"></script>'
if loader in html:
    pass
elif needle in html:
    # Module scripts execute in document order with deferred classic scripts, so
    # placing the loader first lets it set its globals before app.js runs.
    html = html.replace(needle, f'{loader}\n{needle}', 1)
else:
    raise SystemExit('index.html no longer contains the i18n script tag')
open(path, 'w', encoding='utf-8').write(html)
PY

# wasm-bindgen names its internal helpers (decodeText, encodeString, …) in the
# same namespace as our exports, and a clash is a runtime syntax error rather
# than a build failure — so check for it here.
echo "▸ checking the generated glue for name collisions"
python3 "$ROOT/scripts/check-wasm-glue.py" "$DIST/pkg/gaexport.js"

# Pages otherwise runs the output through Jekyll, which drops files it dislikes.
touch "$DIST/.nojekyll"
rm -f "$DIST/pkg/.gitignore"

echo "▸ done: $(du -sh "$DIST" | cut -f1) in $DIST"
echo "  preview with:  python3 -m http.server -d $DIST 8080"
