/* firering shared download — SPDX-License-Identifier: GPL-3.0-only */
(() => {
  'use strict';
  const download = document.getElementById('download');
  const details = document.getElementById('release-details');
  const note = document.getElementById('link-note');
  const status = document.getElementById('status');
  const progress = document.getElementById('progress');
  const retry = document.getElementById('retry');
  const MAX_APK_BYTES = 256 * 1024 * 1024;
  let release = null;
  let linkKey = null;
  let busy = false;

  function message(text, kind = '') { status.textContent = text; status.className = `status${kind ? ` ${kind}` : ''}`; }
  function hasCrypto() { return window.isSecureContext && window.crypto && window.crypto.subtle; }
  function updateButton() { download.disabled = busy || !release || !linkKey || !hasCrypto(); }

  function readLinkKey() {
    linkKey = null;
    try {
      const parts = new URLSearchParams(window.location.hash.slice(1));
      const encoded = parts.get('k');
      if (parts.getAll('k').length !== 1 || !encoded || !/^[A-Za-z0-9_-]{43}$/.test(encoded)) throw new Error();
      const decoded = atob(encoded.replace(/-/g, '+').replace(/_/g, '/') + '=');
      if (decoded.length !== 32) throw new Error();
      linkKey = Uint8Array.from(decoded, character => character.charCodeAt(0));
    } catch (_) { /* An incomplete link never enables the download. */ }
    note.hidden = Boolean(linkKey);
    if (!busy && release) {
      if (!hasCrypto()) message('Open this complete link in an up-to-date browser using its secure HTTPS address.', 'error');
      else message(linkKey ? 'Ready when you are.' : 'Use the complete link shared with you to unlock the download.');
    }
    updateButton();
  }

  function validateRelease(value) {
    if (!value || typeof value.version !== 'string' || !value.version.trim() || value.version.length > 128 ||
        typeof value.filename !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.apk$/.test(value.filename) ||
        value.mime !== 'application/vnd.android.package-archive' ||
        typeof value.sha256 !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value.sha256) ||
        !Number.isSafeInteger(value.bytes) || value.bytes <= 0 || value.bytes > MAX_APK_BYTES ||
        typeof value.payload !== 'string' || !value.payload || value.payload.length > 256) throw new Error('Release details are unavailable. Try again shortly.');
    const base = new URL('./', window.location.href);
    const payload = new URL(value.payload, base);
    if (payload.origin !== base.origin || !payload.pathname.startsWith(base.pathname) || payload.search || payload.hash ||
        !/^[A-Za-z0-9._/-]+$/.test(value.payload) || value.payload.includes('..') || value.payload.startsWith('/')) {
      throw new Error('Release details are unavailable. Try again shortly.');
    }
    return { ...value, payloadUrl: payload.href, sha256: value.sha256.toLowerCase() };
  }

  async function fetchRelease(signal) {
    const response = await fetch('./release.json?t=' + Date.now(), {
      cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal
    });
    if (!response.ok) throw new Error('The download is unavailable. Please try again shortly.');
    const latest = validateRelease(await response.json());
    details.textContent = `Version ${latest.version} · Android 8.0 or later · ${(latest.bytes / (1024 * 1024)).toFixed(1)} MB`;
    return latest;
  }

  async function loadRelease() {
    retry.hidden = true; release = null; updateButton();
    message('Loading download details…');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 15000);
    try {
      release = await fetchRelease(controller.signal);
      readLinkKey();
    } catch (error) {
      message(error?.name === 'AbortError' ? 'The page took too long to load. Check your connection and try again.' : 'Download details could not be loaded. Please try again.', 'error');
      retry.hidden = false;
    } finally { clearTimeout(timer); updateButton(); }
  }

  async function readPayload(response, expected, controller) {
    if (!response.body || typeof response.body.getReader !== 'function') return response.arrayBuffer();
    const reader = response.body.getReader(); const chunks = []; let received = 0;
    try {
      while (true) {
        const item = await reader.read(); if (item.done) break;
        received += item.value.byteLength;
        if (received > expected) { controller.abort(); throw new Error('The download file was not the expected size. Please try again.'); }
        chunks.push(item.value);
        const percent = Math.min(100, Math.floor(received * 100 / expected));
        progress.value = percent; message(`Downloading… ${percent}%`);
      }
    } finally { reader.releaseLock(); }
    const complete = new Uint8Array(received); let offset = 0;
    for (const chunk of chunks) { complete.set(chunk, offset); offset += chunk.byteLength; }
    return complete.buffer;
  }

  async function downloadApk() {
    if (busy || !release || !linkKey || !hasCrypto()) return;
    const keyBytes = linkKey;
    busy = true; download.setAttribute('aria-busy', 'true'); updateButton(); retry.hidden = true;
    progress.hidden = false; progress.value = 0; message('Starting download…');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 180000);
    let phase = 'download';
    try {
      const selected = await fetchRelease(controller.signal);
      release = selected;
      const response = await fetch(selected.payloadUrl, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: controller.signal });
      if (!response.ok) throw new Error('The download is unavailable. Please try again shortly.');
      const encrypted = await readPayload(response, selected.bytes + 32, controller);
      const bytes = new Uint8Array(encrypted);
      if (bytes.byteLength !== selected.bytes + 32 || bytes[0] !== 70 || bytes[1] !== 82 || bytes[2] !== 71 || bytes[3] !== 49) {
        throw new Error('The download file looks incomplete. Please try again.');
      }
      phase = 'unlock'; progress.removeAttribute('value'); message('Unlocking your app…');
      const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(4, 16), additionalData: new TextEncoder().encode(`firering-apk:${selected.version}`), tagLength: 128 }, key, bytes.slice(16));
      phase = 'verify'; message('Checking your download…');
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', plaintext));
      const checksum = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
      if (plaintext.byteLength !== selected.bytes || checksum !== selected.sha256) throw new Error('The app did not pass its integrity check. Try again, or ask for an updated link.');
      const url = URL.createObjectURL(new Blob([plaintext], { type: selected.mime }));
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = selected.filename; anchor.rel = 'noreferrer';
      document.body.append(anchor); anchor.click(); anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      progress.value = 100; message('Your APK is ready. Open it from your browser’s Downloads to install.', 'success');
    } catch (error) {
      if (phase === 'unlock') message('This link could not unlock the download. Ask for the complete link and open it again.', 'error');
      else if (error?.name === 'AbortError') message('The download took too long. Check your connection and try again.', 'error');
      else if (phase === 'verify') message('The app did not pass its integrity check. Try again, or ask for an updated link.', 'error');
      else message(error instanceof TypeError ? 'Could not reach the download. Check your connection and try again.' : error.message || 'The download could not finish. Please try again.', 'error');
      progress.hidden = true;
    } finally {
      clearTimeout(timer); busy = false; download.removeAttribute('aria-busy'); updateButton();
    }
  }

  download.addEventListener('click', downloadApk);
  retry.addEventListener('click', loadRelease);
  window.addEventListener('hashchange', readLinkKey);
  readLinkKey(); loadRelease();
})();
