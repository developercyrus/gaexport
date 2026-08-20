/* Loads the WebAssembly decoder for the hosted build.
 *
 * `app.js` looks for `window.gaexportWasm` and prefers it over the HTTP API, so
 * this file is the only difference between the static site and `gaexport serve`.
 * The synchronous part runs before app.js touches anything, which lets the UI
 * say "in-browser" from the first paint instead of flipping labels later.
 */
import init, * as wasm from './pkg/gaexport.js';

window.gaexportWasmReady = (async () => {
  await init();
  window.gaexportWasm = {
    decodeText: (text) => JSON.parse(wasm.readText(text)),
    decodeImage: (bytes) => JSON.parse(wasm.readImage(bytes)),
    decodeRgba: (pixels, width, height) => JSON.parse(wasm.readFrame(pixels, width, height)),
    qrSvg: (data) => wasm.renderQrSvg(data),
    encodeMigration: (uris) => wasm.packMigration(uris.join('\n')).split('\n').filter(Boolean),
    version: () => wasm.buildVersion(),
  };
  window.dispatchEvent(new Event('gaexport:wasm-ready'));
  return window.gaexportWasm;
})();

window.gaexportWasmReady.catch((error) => {
  console.error('gaexport: WebAssembly failed to load', error);
});
