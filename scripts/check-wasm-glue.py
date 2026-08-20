import re, sys
source = open(sys.argv[1], encoding='utf-8').read()
exported = set(re.findall(r'^export function (\w+)', source, re.M))
internal = set(re.findall(r'^function (\w+)', source, re.M))
clash = sorted(exported & internal)
if clash:
    raise SystemExit(
        'wasm-bindgen generated internal helpers with the same names as exports: '
        + ', '.join(clash)
        + '\nRename the #[wasm_bindgen(js_name = ...)] exports in src/wasm.rs.'
    )
print(f'  {len(exported)} exports, no collisions')
