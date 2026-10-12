/**
 * Sign-in gate for the September cheat-app report.
 *
 * Paste the Web client ID into GGX_GOOGLE_CLIENT_ID.
 * Google Cloud → Google Auth Platform → Clients → Web application.
 * User type: Internal (gogox.com).
 * Authorized JavaScript origins:
 *   https://gogovan.github.io
 *   http://127.0.0.1:8765
 *
 * The page stays closed until a @gogox.com Google ID token passes signature,
 * audience, issuer, expiry, email_verified, and hosted-domain checks.
 */
const GGX_GOOGLE_CLIENT_ID = '';

(function () {
  'use strict';

  const STORAGE_KEY = 'ggx-cheatapp-sept-2026-credential';
  const CERTS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
  let certsPromise = null;

  function $(id) {
    return document.getElementById(id);
  }

  function show(el) {
    if (el) el.hidden = false;
  }

  function hide(el) {
    if (el) el.hidden = true;
  }

  function setError(text) {
    const el = $('ggx-gate-error');
    if (!el) return;
    el.textContent = text || '';
    if (text) show(el);
    else hide(el);
  }

  function b64urlToBytes(value) {
    const pad = '='.repeat((4 - (value.length % 4)) % 4);
    const b64 = (value + pad).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64urlToJson(value) {
    return JSON.parse(new TextDecoder().decode(b64urlToBytes(value)));
  }

  function fail(code) {
    const error = new Error(code);
    error.code = code;
    throw error;
  }

  function googleJwks() {
    if (!certsPromise) {
      certsPromise = fetch(CERTS_URL)
        .then((response) => {
          if (!response.ok) fail('certs');
          return response.json();
        })
        .then((body) => {
          const map = {};
          (body.keys || []).forEach((key) => {
            if (key.kid) map[key.kid] = key;
          });
          return map;
        })
        .catch((error) => {
          certsPromise = null;
          throw error;
        });
    }
    return certsPromise;
  }

  function audienceMatches(audience, clientId) {
    if (audience === clientId) return true;
    return Array.isArray(audience) && audience.indexOf(clientId) !== -1;
  }

  async function verifyGoogleIdToken(jwt) {
    if (!GGX_GOOGLE_CLIENT_ID) fail('missing-client');
    const parts = String(jwt || '').split('.');
    if (parts.length !== 3) fail('bad-token');
    const header = b64urlToJson(parts[0]);
    const payload = b64urlToJson(parts[1]);
    if (!header || header.alg !== 'RS256' || !header.kid) fail('bad-token');
    if (!payload) fail('bad-token');
    const issuerOk = payload.iss === 'https://accounts.google.com' || payload.iss === 'accounts.google.com';
    if (!issuerOk) fail('bad-token');
    if (!audienceMatches(payload.aud, GGX_GOOGLE_CLIENT_ID)) fail('bad-token');
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp < now - 60) fail('expired');
    if (payload.email_verified !== true) fail('domain');
    const email = String(payload.email || '').toLowerCase();
    if (!email.endsWith('@gogox.com') || payload.hd !== 'gogox.com') fail('domain');
    const certs = await googleJwks();
    const jwk = certs[header.kid];
    if (!jwk) fail('bad-token');
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const signed = new TextEncoder().encode(parts[0] + '.' + parts[1]);
    const signature = b64urlToBytes(parts[2]);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signed);
    if (!ok) fail('bad-token');
    return payload;
  }

  function messageFor(error) {
    if (error && error.code === 'domain') {
      return 'That Google account is not @gogox.com. Sign in with your GoGoX account.';
    }
    if (error && error.code === 'expired') {
      return 'That sign-in expired. Try again.';
    }
    return 'Sign-in could not be checked. Reload the page and try again.';
  }

  function unlock(email) {
    document.body.classList.remove('ggx-locked');
    const root = document.querySelector('.viz-root');
    if (root) {
      root.removeAttribute('inert');
      root.removeAttribute('aria-hidden');
    }
    const gate = $('ggx-gate');
    if (gate) gate.setAttribute('hidden', '');
    mountSignedIn(email);
    window.dispatchEvent(new Event('scroll'));
  }

  function mountSignedIn(email) {
    const nav = document.querySelector('.nav-in');
    if (!nav) return;
    let chip = $('ggx-signed-in');
    if (!chip) {
      chip = document.createElement('span');
      chip.id = 'ggx-signed-in';
      chip.className = 'ggx-signed-in';
      nav.appendChild(chip);
    }
    chip.replaceChildren();
    const who = document.createElement('span');
    who.textContent = 'Signed in as ' + email;
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'Sign out';
    button.addEventListener('click', signOut);
    chip.append(who, button);
  }

  function signOut() {
    try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
    if (window.google && google.accounts && google.accounts.id) {
      google.accounts.id.disableAutoSelect();
    }
    window.location.reload();
  }

  function whenGoogle(onReady, onFail) {
    let tries = 0;
    const timer = window.setInterval(() => {
      tries += 1;
      if (window.google && google.accounts && google.accounts.id) {
        window.clearInterval(timer);
        onReady();
      } else if (tries > 40) {
        window.clearInterval(timer);
        onFail();
      }
    }, 200);
  }

  function showGoogleButton() {
    const slot = $('ggx-google-btn');
    if (!slot) return;
    whenGoogle(() => {
      google.accounts.id.initialize({
        client_id: GGX_GOOGLE_CLIENT_ID,
        callback: onCredential,
        auto_select: false,
        cancel_on_tap_outside: true,
        hd: 'gogox.com',
        context: 'signin'
      });
      slot.replaceChildren();
      google.accounts.id.renderButton(slot, {
        theme: 'outline',
        size: 'large',
        text: 'signin_with',
        shape: 'pill',
        width: 280
      });
    }, () => {
      setError('Google sign-in did not load. Check the network and reload.');
    });
  }

  async function onCredential(response) {
    setError('');
    try {
      const payload = await verifyGoogleIdToken(response && response.credential);
      sessionStorage.setItem(STORAGE_KEY, response.credential);
      unlock(String(payload.email || '').toLowerCase());
    } catch (error) {
      try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
      setError(messageFor(error));
    }
  }

  async function boot() {
    const setup = $('ggx-gate-setup');
    if (!GGX_GOOGLE_CLIENT_ID) {
      if (setup) show(setup);
      return;
    }
    if (setup) hide(setup);
    let saved = '';
    try { saved = sessionStorage.getItem(STORAGE_KEY) || ''; } catch (e) { saved = ''; }
    if (!saved) {
      showGoogleButton();
      return;
    }
    try {
      const payload = await verifyGoogleIdToken(saved);
      unlock(String(payload.email || '').toLowerCase());
    } catch (error) {
      try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
      showGoogleButton();
      if (error && error.code === 'domain') setError(messageFor(error));
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { boot(); });
  } else {
    boot();
  }
})();
