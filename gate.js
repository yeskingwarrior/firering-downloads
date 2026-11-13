/* firering shared page — SPDX-License-Identifier: GPL-3.0-only */
(() => {
  'use strict';
  const status = document.getElementById('gate-status');
  const retry = document.getElementById('gate-retry');
  const MAX_PAGE_BYTES = 64 * 1024;
  let attempt = 0;
  let pending = null;
  let booted = false;

  function message(text, error = false) {
    status.textContent = text;
    status.className = error ? 'status error' : 'status';
  }

  function fragmentKey() {
    try {
      const parts = new URLSearchParams(window.location.hash.slice(1));
      const encoded = parts.get('k');
      if (parts.getAll('k').length !== 1 || !encoded || !/^[A-Za-z0-9_-]{43}$/.test(encoded)) return null;
      const decoded = atob(encoded.replace(/-/g, '+').replace(/_/g, '/') + '=');
      return decoded.length === 32 ? Uint8Array.from(decoded, character => character.charCodeAt(0)) : null;
    } catch (_) { return null; }
  }

  function validateGate(value) {
    if (!value || typeof value.version !== 'string' || !value.version.trim() || value.version.length > 128 ||
        !Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > MAX_PAGE_BYTES ||
        typeof value.sha256 !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value.sha256) ||
        typeof value.payload !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value.payload) ||
        value.payload.includes('..')) throw new Error('metadata');
    const base = new URL('./', window.location.href);
    const payload = new URL(value.payload, base);
    if (payload.origin !== base.origin || !payload.pathname.startsWith(base.pathname) || payload.search || payload.hash) throw new Error('metadata');
    return { ...value, sha256: value.sha256.toLowerCase(), payloadUrl: payload.href };
  }

  async function boundedPayload(response, expected, controller) {
    // Browsers decode Content-Encoding before exposing the response body.
    // Bound decoded bytes; Content-Length may describe a larger gzip envelope.
    if (!response.body || typeof response.body.getReader !== 'function') return response.arrayBuffer();
    const reader = response.body.getReader();
    const output = new Uint8Array(expected);
    let offset = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        if (offset + part.value.byteLength > expected) { controller.abort(); throw new Error('size'); }
        output.set(part.value, offset); offset += part.value.byteLength;
      }
    } finally { reader.releaseLock(); }
    if (offset !== expected) throw new Error('size');
    return output.buffer;
  }

  async function openPage() {
    if (booted) return;
    const current = ++attempt;
    if (pending) pending.abort();
    pending = null; retry.hidden = true;
    const keyBytes = fragmentKey();
    if (!keyBytes) { message('Use the complete link shared with you.'); return; }
    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
      message('Open this complete link in an up-to-date browser using its secure HTTPS address.', true); return;
    }
    const controller = new AbortController(); pending = controller;
    const timer = setTimeout(() => controller.abort(), 20000);
    const options = { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: controller.signal };
    let phase = 'network';
    message('Opening your link…');
    try {
      const metadata = await fetch('./gate.json?t=' + Date.now(), options);
      if (!metadata.ok) throw new Error('unavailable');
      const gate = validateGate(await metadata.json());
      if (current !== attempt) return;
      const response = await fetch(gate.payloadUrl, options);
      if (!response.ok) throw new Error('unavailable');
      const encrypted = new Uint8Array(await boundedPayload(response, gate.bytes + 32, controller));
      if (current !== attempt) return;
      if (encrypted.byteLength !== gate.bytes + 32 || encrypted[0] !== 70 || encrypted[1] !== 82 || encrypted[2] !== 71 || encrypted[3] !== 49) throw new Error('container');
      phase = 'unlock';
      const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: encrypted.slice(4, 16), additionalData: new TextEncoder().encode(`firering-page:${gate.version}`), tagLength: 128 }, key, encrypted.slice(16));
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', plaintext));
      const checksum = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
      if (plaintext.byteLength !== gate.bytes || checksum !== gate.sha256) throw new Error('integrity');
      const html = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
      if (current !== attempt || controller.signal.aborted || booted) return;
      booted = true;
      window.removeEventListener('hashchange', openPage);
      document.body.innerHTML = html;
      const script = document.createElement('script');
      script.src = 'app.js?v=3';
      script.addEventListener('error', () => {
        const pageStatus = document.getElementById('status');
        if (pageStatus) { pageStatus.textContent = 'The page could not finish loading. Refresh to try again.'; pageStatus.className = 'status error'; }
      }, { once: true });
      document.head.append(script);
    } catch (error) {
      if (current !== attempt || booted) return;
      if (error?.name === 'AbortError') message('The page took too long to open. Check your connection and try again.', true);
      else if (phase === 'unlock') message('This link could not open the page. Ask for the complete link and try again.', true);
      else message('The page could not be opened. Check your connection and try again.', true);
      retry.hidden = false;
    } finally {
      clearTimeout(timer);
      if (current === attempt) pending = null;
    }
  }

  retry.addEventListener('click', openPage);
  window.addEventListener('hashchange', openPage);
  openPage();
})();
