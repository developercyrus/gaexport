/* gaexport UI.
 *
 * Secrets live in this tab's memory and nowhere else: no localStorage, no
 * cookies, no analytics. OTP codes are computed here with WebCrypto so the
 * backend stays stateless. When a WASM build is present (the hosted, fully
 * client-side deployment) decoding happens in-page too and no byte of your
 * export ever leaves the device.
 */
'use strict';

/* ── i18n ──────────────────────────────────────────────────────── */
const I18N = window.GAEXPORT_I18N;
const storedLang = localStorage.getItem('gaexport.lang');
/* Default to the browser's own language list; only a manual pick is persisted. */
let lang = (storedLang && I18N.locales[storedLang])
  ? storedLang
  : I18N.resolve(navigator.languages && navigator.languages.length
    ? navigator.languages
    : [navigator.language]);

function t(key, ...args) {
  const table = I18N.locales[lang] || I18N.fallback;
  const value = table[key] !== undefined ? table[key] : I18N.fallback[key];
  if (value === undefined) return key;
  return typeof value === 'function' ? value(...args) : value;
}

function buildLanguagePicker() {
  const list = $('#lang-list');
  list.replaceChildren(...I18N.list().map(({ tag, name }) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.setAttribute('role', 'menuitemradio');
    item.dataset.lang = tag;
    const label = document.createElement('span');
    label.textContent = name;
    const tick = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    tick.setAttribute('class', 'ic tick');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '#i-check');
    tick.append(use);
    item.append(label, tick);
    return item;
  }));
  markLanguage();
}

function markLanguage() {
  const current = I18N.locales[lang] ? lang : 'en';
  $('#lang-current').textContent = I18N.locales[current]._name;
  $$('#lang-list [data-lang]').forEach((item) => {
    item.setAttribute('aria-checked', String(item.dataset.lang === current));
  });
}

function toggleLanguageMenu(open) {
  const list = $('#lang-list');
  const shouldOpen = open ?? list.hidden;
  list.hidden = !shouldOpen;
  $('#lang-btn').setAttribute('aria-expanded', String(shouldOpen));
  if (shouldOpen) list.querySelector('[aria-checked="true"]')?.focus();
}

function applyLanguage() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-ph]').forEach((el) => {
    el.placeholder = t(el.dataset.i18nPh);
  });
  markLanguage();
  labelTheme();
  updatePrivacyCopy();
  state.entries.forEach(decorateCardTitles);
}

/* ── tiny helpers ──────────────────────────────────────────────── */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function toast(message, kind = 'ok') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  $('#toasts').append(el);
  setTimeout(() => {
    el.style.transition = 'opacity .25s, transform .25s';
    el.style.opacity = '0';
    el.style.transform = 'translateY(6px)';
    setTimeout(() => el.remove(), 260);
  }, 2600);
}

async function copy(text, okMessage) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'offscreen';
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.append(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      if (!ok) throw new Error('execCommand failed');
    }
    toast(okMessage, 'ok');
    return true;
  } catch (_e) {
    toast(t('toast.copyFailed'), 'bad');
    return false;
  }
}

function hashString(text) {
  let h = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h);
}

function groupDigits(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

function groupSecret(secret) {
  return (secret.match(/.{1,4}/g) || [secret]).join(' ');
}

function stamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

/* ── URI building ──────────────────────────────────────────────── */
/* Mirrors `OtpEntry::to_uri` in src/otp.rs: everything except
   [A-Za-z0-9-._~@] is percent-encoded, and the label keeps a literal `:`
   between issuer and account because that is what Google Authenticator emits.
   The result is always handed back to the Rust core for validation, so this
   only has to produce a *candidate*. */
function pctEncode(text) {
  return String(text).replace(/[^A-Za-z0-9\-._~@]/g, (ch) => {
    const bytes = new TextEncoder().encode(ch);
    return Array.from(bytes, (b) => `%${b.toString(16).toUpperCase().padStart(2, '0')}`).join('');
  });
}

function buildUri(draft) {
  const issuer = (draft.issuer || '').trim();
  const name = (draft.name || '').trim();
  const label = issuer && name
    ? `${pctEncode(issuer)}:${pctEncode(name)}`
    : pctEncode(issuer || name);
  const secret = (draft.secret || '').replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
  let uri = `otpauth://${draft.type}/${label}?secret=${secret}`;
  if (issuer) uri += `&issuer=${pctEncode(issuer)}`;
  if (draft.algorithm && draft.algorithm !== 'SHA1') uri += `&algorithm=${draft.algorithm}`;
  if (Number(draft.digits) !== 6) uri += `&digits=${Number(draft.digits)}`;
  if (draft.type === 'hotp') uri += `&counter=${Number(draft.counter) || 0}`;
  else if (Number(draft.period) !== 30) uri += `&period=${Number(draft.period)}`;
  return uri;
}

/* ── state ─────────────────────────────────────────────────────── */
const state = {
  entries: [],       // { issuer, name, type, secret, algorithm, digits, period, counter, uri, ... }
  revealAll: false,
  filter: '',
  sort: 'original',
  clockSkew: 0,      // seconds to add to the local clock
  modal: null,
  editing: null,     // the entry currently open in the edit dialog
};

/* ── backend: WASM when available, otherwise the local HTTP API ── */
const token = new URLSearchParams(location.search).get('token') || '';
if (token) {
  // Keep the token out of the address bar (and out of screenshots).
  history.replaceState(null, '', location.pathname);
}

const Backend = {
  get wasm() {
    return window.gaexportWasm || null;
  },
  /* 'browser' as soon as a WASM build is *loading*, so the privacy copy never
     starts out wrong on the hosted static site. */
  get mode() {
    return (window.gaexportWasm || window.gaexportWasmReady) ? 'browser' : 'server';
  },
  /** Waits for a pending WASM load; falls through to HTTP if it failed. */
  async ensure() {
    if (!window.gaexportWasm && window.gaexportWasmReady) {
      try {
        await window.gaexportWasmReady;
      } catch (_e) {
        // Broken/blocked wasm: the HTTP API is the fallback when one exists.
      }
    }
  },
  headers(extra = {}) {
    return token ? { ...extra, 'x-gaexport-token': token } : extra;
  },
  async decodeText(text) {
    await this.ensure();
    if (this.wasm) return this.wasm.decodeText(text);
    const res = await fetch('/api/decode', {
      method: 'POST',
      headers: this.headers({ 'content-type': 'application/json' }),
      body: JSON.stringify({ text }),
    });
    return unwrap(res);
  },
  async decodeFiles(files) {
    await this.ensure();
    if (this.wasm) {
      const results = [];
      for (const file of files) {
        results.push(await this.wasm.decodeImage(new Uint8Array(await file.arrayBuffer())));
      }
      return mergeResults(results);
    }
    const form = new FormData();
    files.forEach((file, i) => form.append(`file${i}`, file, file.name || `upload-${i}.png`));
    const res = await fetch('/api/decode/upload', {
      method: 'POST', headers: this.headers(), body: form,
    });
    return unwrap(res);
  },
  /* One camera frame. Returns null instead of throwing: most frames simply
     contain no QR code, and that is not an error worth surfacing. */
  async decodeFrame(canvas) {
    await this.ensure();
    if (this.wasm) {
      const pixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
      try {
        return this.wasm.decodeRgba(new Uint8Array(pixels.data), canvas.width, canvas.height);
      } catch (_e) {
        return null;
      }
    }
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.85));
    if (!blob) return null;
    const form = new FormData();
    form.append('frame', blob, 'frame.jpg');
    const res = await fetch('/api/decode/upload', {
      method: 'POST', headers: this.headers(), body: form,
    });
    return res.ok ? res.json() : null;
  },
  async qrSvg(data) {
    await this.ensure();
    if (this.wasm) return this.wasm.qrSvg(data);
    const res = await fetch('/api/qr', {
      method: 'POST',
      headers: this.headers({ 'content-type': 'application/json' }),
      body: JSON.stringify({ data, svg: true }),
    });
    if (!res.ok) throw new Error(await errorText(res));
    return res.text();
  },
  async qrPngBlob(data) {
    await this.ensure();
    if (this.wasm) return svgToPng(await this.wasm.qrSvg(data));
    const res = await fetch('/api/qr', {
      method: 'POST',
      headers: this.headers({ 'content-type': 'application/json' }),
      body: JSON.stringify({ data, svg: false, scale: 10 }),
    });
    if (!res.ok) throw new Error(await errorText(res));
    return res.blob();
  },
  async encodeMigration(uris) {
    await this.ensure();
    if (this.wasm) return this.wasm.encodeMigration(uris);
    const res = await fetch('/api/encode', {
      method: 'POST',
      headers: this.headers({ 'content-type': 'application/json' }),
      body: JSON.stringify({ uris }),
    });
    const data = await unwrap(res);
    return data.uris;
  },
};

async function errorText(res) {
  try {
    const data = await res.json();
    return data.error || res.statusText;
  } catch (_e) {
    return `${res.status} ${res.statusText}`;
  }
}

async function unwrap(res) {
  if (!res.ok) throw new Error(await errorText(res));
  return res.json();
}

function mergeResults(results) {
  return {
    entries: results.flatMap((r) => r.entries || []),
    warnings: results.flatMap((r) => r.warnings || []),
    sources: results.reduce((sum, r) => sum + (r.sources || 0), 0),
    duplicates: results.reduce((sum, r) => sum + (r.duplicates || 0), 0),
  };
}

/* ── OTP in the browser (RFC 4226 / 6238) ──────────────────────── */
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/[^A-Z2-7]/g, '');
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

async function otpCode(entry, counter) {
  const hash = HASHES[entry.algorithm];
  if (!hash || !window.crypto?.subtle) return null;
  if (!entry._key) {
    entry._key = await crypto.subtle.importKey(
      'raw', base32Decode(entry.secret), { name: 'HMAC', hash }, false, ['sign'],
    );
  }
  const message = new ArrayBuffer(8);
  const view = new DataView(message);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', entry._key, message));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24)
    | (mac[offset + 1] << 16)
    | (mac[offset + 2] << 8)
    | mac[offset + 3];
  return String(binary % 10 ** entry.digits).padStart(entry.digits, '0');
}

function nowSeconds() {
  return Date.now() / 1000 + state.clockSkew;
}

/* ── selection ─────────────────────────────────────────────────── */
/* Entries start selected; exports and the printable sheet act on the
   selection, so trimming an export is just unticking a few cards. */
function pickedEntries() {
  const picked = state.entries.filter((entry) => entry._picked !== false);
  return picked.length ? picked : state.entries;
}

function refreshSelectionUi() {
  const total = state.entries.length;
  const picked = state.entries.filter((entry) => entry._picked !== false).length;
  $('#count-chip').textContent = picked === total ? String(total) : `${picked}/${total}`;
  const box = $('#select-all');
  box.checked = picked === total && total > 0;
  box.indeterminate = picked > 0 && picked < total;
  $('#select-all-box').title = t('toolbar.selectAll');
  state.entries.forEach((entry) => {
    entry._dom?.root.classList.toggle('unpicked', entry._picked === false);
    const pick = entry._dom?.root.querySelector('[data-action="pick"]');
    if (pick) pick.checked = entry._picked !== false;
  });
}

function setAllPicked(picked) {
  state.entries.forEach((entry) => { entry._picked = picked; });
  refreshSelectionUi();
}

/* ── card rendering ────────────────────────────────────────────── */
function decorateCardTitles(entry) {
  if (!entry._dom) return;
  const { root } = entry._dom;
  root.querySelector('[data-action="copy-code"]').title = t('toast.codeCopied');
  root.querySelector('[data-action="toggle-secret"]').title = t('toolbar.reveal');
  root.querySelector('[data-action="copy-secret"]').title = t('toast.secretCopied');
  root.querySelector('[data-action="show-qr"]').title = t('modal.hint');
  root.querySelector('[data-action="edit"]').title = t('edit.title');
}

function buildCard(entry) {
  const node = $('#card-tpl').content.firstElementChild.cloneNode(true);
  const dom = {
    root: node,
    code: node.querySelector('[data-role="code-text"]'),
    codeBtn: node.querySelector('[data-action="copy-code"]'),
    ring: node.querySelector('[data-role="ring"]'),
    ttl: node.querySelector('[data-role="ttl"]'),
    ttlNum: node.querySelector('[data-role="ttl-num"]'),
    secret: node.querySelector('[data-role="secret"]'),
  };
  entry._dom = dom;
  entry._revealed = false;

  const issuer = entry.issuer || entry.name || '—';
  const account = entry.issuer ? entry.name : '';
  node.querySelector('[data-role="issuer"]').textContent = issuer;
  const accountEl = node.querySelector('[data-role="account"]');
  accountEl.textContent = account || (entry.type === 'hotp' ? 'HOTP' : '');
  accountEl.title = account;
  node.querySelector('[data-role="issuer"]').title = issuer;

  const avatar = node.querySelector('[data-role="avatar"]');
  const hue = hashString(issuer) % 360;
  avatar.style.setProperty('--av-a', `hsl(${hue} 62% 52%)`);
  avatar.style.setProperty('--av-b', `hsl(${(hue + 38) % 360} 58% 38%)`);
  avatar.textContent = [...issuer][0]?.toUpperCase() || '?';

  const badges = node.querySelector('[data-role="badges"]');
  const chips = [];
  if (entry.type === 'hotp') chips.push(['HOTP', 'badge-hotp']);
  if (entry.algorithm !== 'SHA1') chips.push([entry.algorithm, '']);
  if (entry.digits !== 6) chips.push([`${entry.digits}d`, '']);
  if (entry.type === 'totp' && entry.period !== 30) chips.push([`${entry.period}s`, '']);
  chips.forEach(([text, extra]) => {
    const chip = document.createElement('span');
    chip.className = `badge ${extra}`.trim();
    chip.textContent = text;
    badges.append(chip);
  });

  renderSecret(entry);
  decorateCardTitles(entry);

  node.addEventListener('click', (event) => {
    const target = event.target.closest('[data-action]');
    if (!target) return;
    const action = target.dataset.action;
    if (action === 'copy-code') {
      const code = entry._code;
      if (code) copy(code, t('toast.codeCopied'));
      dom.codeBtn.classList.add('copied');
      setTimeout(() => dom.codeBtn.classList.remove('copied'), 900);
    } else if (action === 'toggle-secret') {
      entry._revealed = !entry._revealed;
      renderSecret(entry);
    } else if (action === 'copy-secret') {
      copy(entry.secret, t('toast.secretCopied'));
    } else if (action === 'show-qr') {
      showAccountQr(entry);
    } else if (action === 'edit') {
      openEditor(entry);
    }
  });

  node.querySelector('[data-action="pick"]').addEventListener('change', (event) => {
    entry._picked = event.target.checked;
    refreshSelectionUi();
  });

  if (entry.type === 'hotp') {
    dom.ttl.classList.add('counter');
    dom.ttlNum.textContent = `c=${entry.counter ?? 0}`;
  }
  return node;
}

function renderSecret(entry) {
  const { secret, root } = entry._dom;
  const revealed = entry._revealed || state.revealAll;
  root.classList.toggle('revealed', revealed);
  secret.classList.toggle('masked', !revealed);
  secret.textContent = revealed ? groupSecret(entry.secret) : '•••• •••• •••• ••••';
}

function renderGrid() {
  const grid = $('#grid');
  const order = [...state.entries];
  if (state.sort === 'issuer') {
    order.sort((a, b) => (a.issuer || '').localeCompare(b.issuer || '')
      || (a.name || '').localeCompare(b.name || ''));
  } else if (state.sort === 'name') {
    order.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
  }
  grid.replaceChildren(...order.map((entry) => entry._dom?.root || buildCard(entry)));
  applyFilter();
  refreshSelectionUi();
  $('#results').hidden = state.entries.length === 0;
  $('#intake').hidden = state.entries.length > 0;
  refreshCodes(true);
}

function applyFilter() {
  const needle = state.filter.trim().toLowerCase();
  let visible = 0;
  state.entries.forEach((entry) => {
    const haystack = `${entry.issuer} ${entry.name} ${entry.type}`.toLowerCase();
    const show = !needle || haystack.includes(needle);
    entry._dom?.root.classList.toggle('hidden', !show);
    if (show) visible += 1;
  });
  $('#empty-filter').hidden = visible !== 0 || state.entries.length === 0;
}

/* ── live codes ────────────────────────────────────────────────── */
const RING_CIRCUMFERENCE = 100.53;

async function refreshCodes(force = false) {
  const now = nowSeconds();
  await Promise.all(state.entries.map(async (entry) => {
    if (!entry._dom) return;
    const period = entry.type === 'totp' ? (entry.period || 30) : 0;
    const counter = entry.type === 'totp' ? Math.floor(now / period) : (entry.counter ?? 0);

    if (force || entry._counter !== counter) {
      const wrapped = entry._counter !== undefined && entry._counter !== counter;
      entry._counter = counter;
      const code = await otpCode(entry, counter);
      entry._code = code;
      entry._dom.code.textContent = code ? groupDigits(code) : '—';
      entry._dom.codeBtn.classList.toggle('stale', !code);
      if (!code) entry._dom.codeBtn.title = `${entry.algorithm} is not available in this browser`;
      if (wrapped) {
        // Snap the ring back to full without animating backwards.
        entry._dom.ttl.classList.add('fresh');
        entry._dom.ring.style.strokeDashoffset = '0';
        requestAnimationFrame(() => entry._dom.ttl.classList.remove('fresh'));
      }
    }
    if (entry.type !== 'totp') return;
    const remaining = period - (now % period);
    const fraction = Math.max(0, Math.min(1, remaining / period));
    entry._dom.ring.style.strokeDashoffset = String(RING_CIRCUMFERENCE * (1 - fraction));
    entry._dom.ttlNum.textContent = String(Math.ceil(remaining));
    entry._dom.ttl.classList.toggle('urgent', remaining <= 5);
  }));
}

/* ── decoding ──────────────────────────────────────────────────── */
function setBusy(busy) {
  $('#busy').hidden = !busy;
  $('#dropzone').classList.toggle('busy', busy);
}

function showProblems(warnings) {
  const list = $('#problems-list');
  if (!warnings.length) {
    $('#problems').hidden = true;
    list.replaceChildren();
    return;
  }
  list.replaceChildren(...warnings.map((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    return li;
  }));
  $('#problems').hidden = false;
}

function fingerprint(entry) {
  return [entry.type, entry.secret, (entry.issuer || '').toLowerCase(),
    (entry.name || '').toLowerCase(), entry.algorithm, entry.digits, entry.period].join('|');
}

function ingest(result, quiet = false) {
  const seen = new Set(state.entries.map(fingerprint));
  const fresh = (result.entries || []).filter((entry) => {
    const key = fingerprint(entry);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const had = state.entries.length;
  state.entries.push(...fresh);
  if (!quiet) showProblems(result.warnings || []);
  renderGrid();
  if (!fresh.length) {
    if (!quiet) toast(t('toast.noNew'), 'bad');
  } else if (had) {
    toast(t('toast.merged', fresh.length));
  } else {
    toast(t('toast.found', fresh.length));
  }
  return fresh.length;
}

async function decodeFiles(files) {
  const images = Array.from(files).filter((f) => f.size > 0);
  if (!images.length) return;
  setBusy(true);
  try {
    ingest(await Backend.decodeFiles(images));
  } catch (err) {
    showProblems([String(err.message || err)]);
    toast(String(err.message || err), 'bad');
  } finally {
    setBusy(false);
  }
}

async function decodeText(text) {
  if (!text.trim()) return;
  setBusy(true);
  try {
    ingest(await Backend.decodeText(text));
    $('#paste-text').value = '';
  } catch (err) {
    showProblems([String(err.message || err)]);
    toast(String(err.message || err), 'bad');
  } finally {
    setBusy(false);
  }
}

/* ── camera scanning ───────────────────────────────────────────── */
const scanner = {
  stream: null, timer: 0, detector: null, canvas: null,
  facing: 'environment', stopped: true, seen: new Set(), cooldown: 0,
};

function cameraAvailable() {
  return Boolean(navigator.mediaDevices?.getUserMedia) && window.isSecureContext;
}

async function makeDetector() {
  if (!('BarcodeDetector' in window)) return null;
  try {
    const formats = await window.BarcodeDetector.getSupportedFormats();
    if (!formats.includes('qr_code')) return null;
    return new window.BarcodeDetector({ formats: ['qr_code'] });
  } catch (_e) {
    return null;   // Safari/Firefox: fall back to decoding frames ourselves.
  }
}

async function startScan() {
  if (!navigator.mediaDevices?.getUserMedia) return toast(t('scan.denied'), 'bad');
  if (!window.isSecureContext) return toast(t('scan.insecure'), 'bad');
  const overlay = $('#scanner');
  overlay.hidden = false;
  scanner.stopped = false;
  $('#scanner-hint').textContent = t('scan.starting');
  try {
    scanner.stream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: { ideal: scanner.facing },
        width: { ideal: 1280 },
        height: { ideal: 1280 },
      },
      audio: false,
    });
  } catch (_err) {
    stopScan();
    return toast(t('scan.denied'), 'bad');
  }
  const video = $('#scanner-video');
  video.srcObject = scanner.stream;
  try { await video.play(); } catch (_e) { /* autoplay policies */ }
  scanner.detector = await makeDetector();
  $('#scanner-hint').textContent = `${t('scan.hint')} · ${t('scan.tip')}`;
  scanLoop();
  return undefined;
}

function stopScan() {
  scanner.stopped = true;
  clearTimeout(scanner.timer);
  scanner.stream?.getTracks().forEach((track) => track.stop());
  scanner.stream = null;
  scanner.seen.clear();
  $('#scanner-video').srcObject = null;
  $('#scanner').hidden = true;
  $('#scanner').classList.remove('found');
}

async function flipCamera() {
  scanner.facing = scanner.facing === 'environment' ? 'user' : 'environment';
  const wasRunning = !scanner.stopped;
  stopScan();
  if (wasRunning) await startScan();
}

function flashFound() {
  const overlay = $('#scanner');
  overlay.classList.add('found');
  setTimeout(() => overlay.classList.remove('found'), 350);
}

/* Keeps the camera open after a hit: Google Authenticator splits big exports
   across several codes, and swapping between app and camera for each one is
   exactly the annoying part. */
async function scanLoop() {
  if (scanner.stopped) return;
  const video = $('#scanner-video');
  let delay = 150;
  try {
    if (video.readyState >= 2 && Date.now() > scanner.cooldown) {
      if (scanner.detector) {
        const hits = await scanner.detector.detect(video);
        const payload = hits.map((h) => h.rawValue).find((v) => /otpauth/i.test(v || ''));
        if (payload && !scanner.seen.has(payload)) {
          scanner.seen.add(payload);
          flashFound();
          await handleScanned(await Backend.decodeText(payload));
        }
      } else {
        delay = 400;
        const result = await Backend.decodeFrame(frameCanvas(video));
        if (result?.entries?.length) {
          flashFound();
          await handleScanned(result);
        }
      }
    }
  } catch (_e) {
    // A frame without a readable code is the common case; keep going.
  }
  scanner.timer = setTimeout(scanLoop, delay);
}

async function handleScanned(result) {
  ingest(result, true);
  scanner.cooldown = Date.now() + 900;
  $('#scanner-hint').textContent = t('scan.progress', state.entries.length);
}

function frameCanvas(video) {
  scanner.canvas = scanner.canvas || document.createElement('canvas');
  const canvas = scanner.canvas;
  const width = video.videoWidth || 720;
  const height = video.videoHeight || 720;
  const scale = Math.min(1, 1100 / Math.max(width, height));
  canvas.width = Math.round(width * scale);
  canvas.height = Math.round(height * scale);
  canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
  return canvas;
}

/* ── editing ───────────────────────────────────────────────────── */
/* The form only builds a candidate URI; the Rust core (in-process or WASM)
   validates and normalises it, so what a card shows is exactly what an export
   will contain. */
function openEditor(entry) {
  state.editing = entry || null;
  const draft = entry || {
    issuer: '', name: '', type: 'totp', secret: '',
    algorithm: 'SHA1', digits: 6, period: 30, counter: 0,
  };
  $('#edit-title').textContent = entry ? t('edit.title') : t('toolbar.add');
  $('#edit-issuer').value = draft.issuer || '';
  $('#edit-name').value = draft.name || '';
  $('#edit-secret').value = entry ? draft.secret : '';
  $('#edit-type').value = draft.type;
  $('#edit-algorithm').value = draft.algorithm;
  $('#edit-digits').value = draft.digits;
  $('#edit-period').value = draft.period || 30;
  $('#edit-counter').value = draft.counter ?? 0;
  $('#edit-delete').hidden = !entry;
  syncEditorType();
  showEditError('');
  $('#edit-modal').hidden = false;
  $('#edit-issuer').focus();
}

function closeEditor() {
  $('#edit-modal').hidden = true;
  state.editing = null;
}

function syncEditorType() {
  const isHotp = $('#edit-type').value === 'hotp';
  $('#edit-period-field').hidden = isHotp;
  $('#edit-counter-field').hidden = !isHotp;
}

/* The core reports errors for a whole batch of input; inside the editor only
   the specific reason is useful. */
function friendlyEditError(raw) {
  if (/base32/i.test(raw)) return t('edit.invalidSecret');
  const detail = raw.split('\n').map((line) => line.replace(/^\s*-\s*/, '').trim())
    .filter((line) => line && !/^no OTP keys found/i.test(line) && !/no otpauth:\/\//i.test(line));
  const line = detail[0] || raw.split('\n')[0];
  return line.replace(/^argument:\s*/, '').replace(/^skipping `[^`]*`:\s*/, '');
}

function showEditError(message) {
  const box = $('#edit-error');
  box.textContent = message;
  box.hidden = !message;
}

async function saveEditor() {
  const draft = {
    issuer: $('#edit-issuer').value,
    name: $('#edit-name').value,
    type: $('#edit-type').value,
    secret: $('#edit-secret').value,
    algorithm: $('#edit-algorithm').value,
    digits: Number($('#edit-digits').value),
    period: Number($('#edit-period').value),
    counter: Number($('#edit-counter').value),
  };
  if (!draft.secret.trim()) return showEditError(t('edit.invalidSecret'));
  if (!draft.issuer.trim() && !draft.name.trim()) return showEditError(t('edit.needName'));

  let normalised;
  try {
    const result = await Backend.decodeText(buildUri(draft));
    normalised = result.entries?.[0];
    if (!normalised) throw new Error(t('edit.invalidSecret'));
  } catch (err) {
    return showEditError(friendlyEditError(String(err.message || err)));
  }

  const target = state.editing;
  if (target) {
    Object.assign(target, normalised);
    target._key = null;          // the HMAC key was derived from the old secret
    target._counter = undefined; // force a code recompute
    delete target._dom;          // rebuild the card from the new values
  } else {
    normalised._picked = true;
    state.entries.push(normalised);
  }
  closeEditor();
  renderGrid();
  toast(target ? t('edit.saved') : t('edit.added'));
  return undefined;
}

function deleteEditing() {
  const target = state.editing;
  if (!target) return;
  if (!window.confirm(t('edit.confirmDelete'))) return;
  target.secret = '';
  target._key = null;
  state.entries = state.entries.filter((entry) => entry !== target);
  closeEditor();
  renderGrid();
  if (!state.entries.length) {
    $('#results').hidden = true;
    $('#intake').hidden = false;
  }
  toast(t('edit.deleted'));
}

/* ── QR modal ──────────────────────────────────────────────────── */
async function showQr({ title, sub, items }) {
  const holder = $('#modal-qr');
  $('#modal-title').textContent = title;
  $('#modal-sub').textContent = sub;
  holder.replaceChildren();
  $('#modal').hidden = false;
  state.modal = { items };

  for (const item of items) {
    const box = document.createElement('div');
    box.className = 'modal-qr-item';
    try {
      box.innerHTML = await Backend.qrSvg(item.data);
    } catch (err) {
      box.textContent = String(err.message || err);
    }
    if (item.caption) {
      const caption = document.createElement('p');
      caption.className = 'modal-sub';
      caption.textContent = item.caption;
      box.append(caption);
    }
    holder.append(box);
  }
}

function showAccountQr(entry) {
  showQr({
    title: entry.issuer || entry.name,
    sub: entry.issuer ? entry.name : '',
    items: [{ data: entry.uri, name: `${entry.issuer || 'account'}-${entry.name || ''}` }],
  });
}

async function showMigrationQr() {
  setBusy(true);
  try {
    const uris = await Backend.encodeMigration(pickedEntries().map((e) => e.uri));
    await showQr({
      title: t('modal.gaTitle'),
      sub: t('modal.gaSub', 1, uris.length),
      items: uris.map((data, i) => ({
        data,
        name: `ga-export-${i + 1}`,
        caption: uris.length > 1 ? t('modal.gaSub', i + 1, uris.length) : '',
      })),
    });
  } catch (err) {
    toast(String(err.message || err), 'bad');
  } finally {
    setBusy(false);
  }
}

function closeModal() {
  $('#modal').hidden = true;
  $('#modal-qr').replaceChildren();
  state.modal = null;
}

/* ── SVG → PNG (WASM mode has no server-side renderer) ─────────── */
function svgToPng(svgText, size = 640) {
  return new Promise((resolve, reject) => {
    const url = `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svgText)))}`;
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#fff';
      ctx.fillRect(0, 0, size, size);
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(img, 0, 0, size, size);
      canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error('canvas encode failed'))), 'image/png');
    };
    img.onerror = () => reject(new Error('cannot rasterise QR'));
    img.src = url;
  });
}

/* ── downloads ─────────────────────────────────────────────────── */
function download(filename, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
  toast(t('toast.exported', filename));
}

function csvCell(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function exportAs(kind) {
  const entries = pickedEntries();
  const base = `gaexport-${stamp()}`;
  if (kind === 'uri') {
    download(`${base}.txt`, new Blob([`${entries.map((e) => e.uri).join('\n')}\n`], { type: 'text/plain' }));
  } else if (kind === 'json') {
    const doc = {
      generator: 'gaexport (web)',
      count: entries.length,
      entries: entries.map(({ issuer, name, type, secret, algorithm, digits, period, counter, uri }) => ({
        issuer, name, type, secret, algorithm, digits, period, counter, uri,
      })),
    };
    download(`${base}.json`, new Blob([`${JSON.stringify(doc, null, 2)}\n`], { type: 'application/json' }));
  } else if (kind === 'csv') {
    const head = ['issuer', 'name', 'type', 'secret', 'algorithm', 'digits', 'period', 'counter', 'uri'];
    const rows = entries.map((e) => head.map((k) => csvCell(e[k])).join(','));
    download(`${base}.csv`, new Blob([`${[head.join(','), ...rows].join('\n')}\n`], { type: 'text/csv' }));
  } else if (kind === 'aegis') {
    const doc = {
      version: 1,
      header: { slots: null, params: null },
      db: {
        version: 3,
        entries: entries.map((e) => ({
          type: e.type,
          uuid: crypto.randomUUID ? crypto.randomUUID() : String(hashString(e.uri)),
          name: e.name,
          issuer: e.issuer,
          note: '',
          favorite: false,
          icon: null,
          info: e.type === 'hotp'
            ? { secret: e.secret, algo: e.algorithm, digits: e.digits, counter: e.counter ?? 0 }
            : { secret: e.secret, algo: e.algorithm, digits: e.digits, period: e.period || 30 },
        })),
      },
    };
    download(`${base}-aegis.json`, new Blob([`${JSON.stringify(doc, null, 2)}\n`], { type: 'application/json' }));
  } else if (kind === 'ga') {
    showMigrationQr();
  }
}

/* ── print backup sheet ────────────────────────────────────────── */
async function printBackup() {
  setBusy(true);
  const sheet = $('#print-sheet');
  try {
    const head = document.createElement('div');
    head.className = 'print-head';
    const h2 = document.createElement('h2');
    h2.textContent = t('print.title');
    const p = document.createElement('p');
    const printable = pickedEntries();
    p.textContent = t('print.sub', printable.length, new Date().toLocaleString());
    head.append(h2, p);
    sheet.replaceChildren(head);

    for (const entry of printable) {
      const item = document.createElement('div');
      item.className = 'print-item';
      const img = document.createElement('img');
      img.alt = '';
      img.src = URL.createObjectURL(await Backend.qrPngBlob(entry.uri));
      const meta = document.createElement('div');
      meta.className = 'print-meta';
      const title = document.createElement('b');
      title.textContent = entry.issuer ? `${entry.issuer} · ${entry.name}` : entry.name;
      const spec = document.createElement('div');
      spec.textContent = `${entry.type.toUpperCase()} · ${entry.algorithm} · ${entry.digits} digits`
        + (entry.type === 'totp' ? ` · ${entry.period}s` : ` · counter ${entry.counter ?? 0}`);
      const secret = document.createElement('div');
      secret.className = 'print-secret';
      secret.textContent = groupSecret(entry.secret);
      meta.append(title, spec, secret);
      item.append(img, meta);
      sheet.append(item);
    }
    setBusy(false);
    window.print();
  } catch (err) {
    setBusy(false);
    toast(String(err.message || err), 'bad');
  }
}

/* ── clock skew check (server mode only) ───────────────────────── */
async function checkClock() {
  if (Backend.mode !== 'server') return;
  try {
    const res = await fetch('/healthz', { cache: 'no-store' });
    const serverDate = res.headers.get('date');
    if (!serverDate) return;
    const skew = (new Date(serverDate).getTime() - Date.now()) / 1000;
    if (Math.abs(skew) > 5) {
      state.clockSkew = skew;
      toast(t('toast.clockSkew', Math.round(skew)), 'bad');
    }
  } catch (_e) { /* offline is fine */ }
}

function updatePrivacyCopy() {
  const browserMode = Backend.mode === 'browser';
  $('#privacy-pill').lastElementChild.textContent = browserMode ? t('pill.browser') : t('pill.local');
  $('#privacy-note').textContent = browserMode ? t('note.browser') : t('note.local');
}

/* ── theme ─────────────────────────────────────────────────────── */
/* Three settings, cycled by the button: follow the system, force light, force
   dark. "auto" is the default and is what a fresh browser gets. */
const THEMES = ['auto', 'light', 'dark'];

function storedTheme() {
  const value = localStorage.getItem('gaexport.theme');
  return THEMES.includes(value) ? value : 'auto';
}

function applyTheme(theme) {
  const value = THEMES.includes(theme) ? theme : 'auto';
  document.documentElement.dataset.theme = value;
  if (value === 'auto') localStorage.removeItem('gaexport.theme');
  else localStorage.setItem('gaexport.theme', value);
  labelTheme();
}

function labelTheme() {
  const button = $('#theme-toggle');
  if (!button) return;
  const current = storedTheme();
  const next = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length];
  const name = (mode) => t(`theme.${mode === 'auto' ? 'system' : mode}`);
  button.title = `${name(current)} → ${name(next)}`;
  button.setAttribute('aria-label', name(current));
}

function cycleTheme() {
  applyTheme(THEMES[(THEMES.indexOf(storedTheme()) + 1) % THEMES.length]);
}

/* ── wiring ────────────────────────────────────────────────────── */
function wire() {
  applyTheme(storedTheme());
  buildLanguagePicker();
  applyLanguage();

  $('#theme-toggle').addEventListener('click', cycleTheme);
  $('#lang-btn').addEventListener('click', () => toggleLanguageMenu());
  $('#lang-list').addEventListener('click', (e) => {
    const item = e.target.closest('[data-lang]');
    if (!item) return;
    lang = item.dataset.lang;
    localStorage.setItem('gaexport.lang', lang);
    toggleLanguageMenu(false);
    applyLanguage();
    $('#lang-btn').focus();
  });
  $('#lang-list').addEventListener('keydown', (e) => {
    const items = $$('#lang-list [data-lang]');
    const index = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const step = e.key === 'ArrowDown' ? 1 : -1;
      items[(index + step + items.length) % items.length]?.focus();
    }
  });

  const dropzone = $('#dropzone');
  const fileInput = $('#file-input');
  dropzone.addEventListener('click', (e) => {
    if (!e.target.closest('button')) fileInput.click();
  });
  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });
  $('#pick-file').addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
  $('#pick-camera').addEventListener('click', (e) => { e.stopPropagation(); $('#camera-input').click(); });
  $('#scan-btn').hidden = !cameraAvailable();
  $('#scan-btn').addEventListener('click', (e) => { e.stopPropagation(); startScan(); });
  $('#scanner-stop').addEventListener('click', stopScan);
  $('#scanner-flip').addEventListener('click', flipCamera);
  [fileInput, $('#camera-input')].forEach((input) => {
    input.addEventListener('change', () => {
      decodeFiles(input.files);
      input.value = '';
    });
  });

  ['dragenter', 'dragover'].forEach((type) => {
    document.addEventListener(type, (e) => {
      e.preventDefault();
      dropzone.classList.add('dragging');
    });
  });
  ['dragleave', 'drop'].forEach((type) => {
    document.addEventListener(type, (e) => {
      e.preventDefault();
      if (type === 'drop' || e.relatedTarget === null) dropzone.classList.remove('dragging');
    });
  });
  document.addEventListener('drop', (e) => {
    const files = Array.from(e.dataTransfer?.files || []);
    if (files.length) {
      decodeFiles(files);
      return;
    }
    const text = e.dataTransfer?.getData('text');
    if (text) decodeText(text);
  });

  document.addEventListener('paste', (e) => {
    const items = Array.from(e.clipboardData?.items || []);
    const images = items.filter((i) => i.type.startsWith('image/')).map((i) => i.getAsFile()).filter(Boolean);
    if (images.length) {
      e.preventDefault();
      decodeFiles(images);
      return;
    }
    if (document.activeElement === $('#paste-text') || document.activeElement === $('#search')) return;
    const text = e.clipboardData?.getData('text');
    if (text && /otpauth/i.test(text)) {
      e.preventDefault();
      decodeText(text);
    }
  });

  $('#paste-go').addEventListener('click', () => decodeText($('#paste-text').value));
  $('#paste-text').addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') decodeText($('#paste-text').value);
  });

  $('#search').addEventListener('input', (e) => {
    state.filter = e.target.value;
    applyFilter();
  });
  $('#sort').addEventListener('change', (e) => {
    state.sort = e.target.value;
    renderGrid();
  });
  $('#reveal-all').addEventListener('click', (e) => {
    state.revealAll = !state.revealAll;
    e.currentTarget.setAttribute('aria-pressed', String(state.revealAll));
    state.entries.forEach(renderSecret);
  });
  $('#add-more').addEventListener('click', () => fileInput.click());
  $('#add-entry').addEventListener('click', () => openEditor(null));
  $('#select-all').addEventListener('change', (e) => setAllPicked(e.target.checked));
  $('#edit-type').addEventListener('change', syncEditorType);
  $('#edit-form').addEventListener('submit', (e) => { e.preventDefault(); saveEditor(); });
  $('#edit-cancel').addEventListener('click', closeEditor);
  $('#edit-close').addEventListener('click', closeEditor);
  $('#edit-delete').addEventListener('click', deleteEditing);
  $('#edit-modal').addEventListener('click', (e) => {
    if (e.target === $('#edit-modal')) closeEditor();
  });
  $('#print-btn').addEventListener('click', printBackup);
  $('#clear-btn').addEventListener('click', () => {
    if (state.entries.length && !window.confirm(t('confirm.clear'))) return;
    state.entries.forEach((entry) => { entry.secret = ''; entry._key = null; });
    state.entries = [];
    $('#grid').replaceChildren();
    $('#results').hidden = true;
    $('#intake').hidden = false;
    showProblems([]);
    toast(t('toast.cleared'));
  });

  const menu = $('#export-menu');
  const menuList = menu.querySelector('.menu-list');
  $('#export-btn').addEventListener('click', () => {
    const open = menuList.hidden;
    menuList.hidden = !open;
    $('#export-btn').setAttribute('aria-expanded', String(open));
  });
  menuList.addEventListener('click', (e) => {
    const button = e.target.closest('[data-export]');
    if (!button) return;
    menuList.hidden = true;
    exportAs(button.dataset.export);
  });
  document.addEventListener('click', (e) => {
    if (!menu.contains(e.target)) menuList.hidden = true;
    if (!$('#lang-menu').contains(e.target)) toggleLanguageMenu(false);
  });

  $('#modal-close').addEventListener('click', closeModal);
  $('#modal').addEventListener('click', (e) => {
    if (e.target === $('#modal')) closeModal();
  });
  $('#modal-download').addEventListener('click', async () => {
    const items = state.modal?.items || [];
    for (const [i, item] of items.entries()) {
      try {
        download(`${(item.name || `qr-${i + 1}`).replace(/[^\w.-]+/g, '-')}.png`,
          await Backend.qrPngBlob(item.data));
      } catch (err) {
        toast(String(err.message || err), 'bad');
      }
    }
  });
  $('#modal-copy-uri').addEventListener('click', () => {
    const item = state.modal?.items?.[0];
    if (item) copy(item.data, t('toast.uriCopied'));
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!scanner.stopped) stopScan();
      toggleLanguageMenu(false);
      closeEditor();
      closeModal();
    }
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || '');
    if (e.key === '/' && !typing && state.entries.length) {
      e.preventDefault();
      $('#search').focus();
    }
  });

  window.addEventListener('gaexport:wasm-ready', updatePrivacyCopy);
  if (!window.crypto?.subtle) toast(t('toast.noCrypto'), 'bad');
  updatePrivacyCopy();
  checkClock();
  setInterval(() => refreshCodes(false), 500);
}

document.addEventListener('DOMContentLoaded', wire);
