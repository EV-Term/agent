/* End to end encryption between the car and this machine.
 *
 * The EV Term server relays frames between the two. It must not be able to read
 * them: it is someone else's box, and a terminal session carries whatever you
 * type, including the things you would never send to a third party on purpose.
 *
 * Each session also requires an ECDSA signature from a browser explicitly
 * authorized on the machine. A fresh agent challenge and the complete launch
 * request are signed before any process is started. Transport encryption alone
 * does not authorize a shell.
 *
 * The exchange is Noise_NK in shape. The browser already knows the agent's
 * long-term public key, because it pinned it the first time it connected, the
 * same way this app already handles SSH host keys. So:
 *
 *   dh1 = ECDH(browser ephemeral, agent static)     authenticates the agent
 *   dh2 = ECDH(browser ephemeral, agent ephemeral)  forward secrecy
 *   keys = HKDF(dh1 || dh2)
 *
 * A relay that swaps the agent's static key is a man in the middle, and only
 * the pinned key catches that. dh1 alone would authenticate but let anyone who
 * later steals the agent's static key decrypt recorded traffic; dh2 alone would
 * give forward secrecy against nobody in particular, since an unauthenticated
 * ephemeral is just as easily the relay's. Both are needed and neither is
 * sufficient.
 *
 * P-256 rather than X25519: WebCrypto has shipped P-256 ECDH everywhere for
 * years, and the car's browser is not a place to discover an algorithm gap.
 *
 * This file is duplicated byte for byte in the EV Term server's public
 * directory. Both sides run the same code against the same test vector, which
 * is what keeps them honest; there is no shared package to drift out of step.
 */

const SUBTLE = globalThis.crypto.subtle;
const CURVE = { name: 'ECDH', namedCurve: 'P-256' };
const INFO = new TextEncoder().encode('evterm session v1');

const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

const unb64u = (s) => {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(pad + '='.repeat((4 - (pad.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

export async function generateIdentity() {
  const pair = await SUBTLE.generateKey(CURVE, true, ['deriveBits']);
  return {
    publicKey: b64u(await SUBTLE.exportKey('spki', pair.publicKey)),
    privateKey: b64u(await SUBTLE.exportKey('pkcs8', pair.privateKey)),
  };
}

const importPublic = (spki) => SUBTLE.importKey('spki', unb64u(spki), CURVE, true, []);
const importPrivate = (pkcs8) =>
  SUBTLE.importKey('pkcs8', unb64u(pkcs8), CURVE, false, ['deriveBits']);

/* A short string a person can compare between two screens. Comparing whole
 * public keys is something nobody does twice, so the check has to fit on one
 * line and survive being read aloud. */
export async function fingerprint(publicKey) {
  const digest = await SUBTLE.digest('SHA-256', unb64u(publicKey));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex.slice(0, 16).toUpperCase().match(/.{4}/g).join('-');
}

async function deriveKeys(dh1, dh2, transcript, sid) {
  const ikm = new Uint8Array(dh1.byteLength + dh2.byteLength);
  ikm.set(new Uint8Array(dh1), 0);
  ikm.set(new Uint8Array(dh2), dh1.byteLength);

  // The salt commits to every public key in the exchange, so a relay that
  // substitutes one of them derives different keys and the first frame fails to
  // open rather than quietly succeeding.
  const salt = await SUBTLE.digest('SHA-256', transcript);
  const base = await SUBTLE.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await SUBTLE.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO },
    base,
    512
  );

  const raw = new Uint8Array(bits);
  const key = (bytes) => SUBTLE.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return {
    toAgent: await key(raw.slice(0, 32)),
    toBrowser: await key(raw.slice(32, 64)),
    sid,
  };
}

function joinKeys(...spkis) {
  const parts = spkis.map(unb64u);
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/* The browser side. It holds the agent's static public key already. */
export async function startHandshake(agentStaticPublic, sid) {
  const ephemeral = await SUBTLE.generateKey(CURVE, true, ['deriveBits']);
  const ephemeralPublic = b64u(await SUBTLE.exportKey('spki', ephemeral.publicKey));

  return {
    ephemeralPublic,
    async complete(agentEphemeralPublic) {
      const dh1 = await SUBTLE.deriveBits(
        { name: 'ECDH', public: await importPublic(agentStaticPublic) },
        ephemeral.privateKey,
        256
      );
      const dh2 = await SUBTLE.deriveBits(
        { name: 'ECDH', public: await importPublic(agentEphemeralPublic) },
        ephemeral.privateKey,
        256
      );
      const transcript = joinKeys(ephemeralPublic, agentEphemeralPublic, agentStaticPublic);
      return deriveKeys(dh1, dh2, transcript, sid);
    },
  };
}

/* The agent side. */
export async function acceptHandshake(staticPrivate, staticPublic, browserEphemeralPublic, sid) {
  const ephemeral = await SUBTLE.generateKey(CURVE, true, ['deriveBits']);
  const ephemeralPublic = b64u(await SUBTLE.exportKey('spki', ephemeral.publicKey));
  const browserKey = await importPublic(browserEphemeralPublic);

  const dh1 = await SUBTLE.deriveBits(
    { name: 'ECDH', public: browserKey },
    await importPrivate(staticPrivate),
    256
  );
  const dh2 = await SUBTLE.deriveBits({ name: 'ECDH', public: browserKey }, ephemeral.privateKey, 256);
  const transcript = joinKeys(browserEphemeralPublic, ephemeralPublic, staticPublic);

  return { ephemeralPublic, keys: await deriveKeys(dh1, dh2, transcript, sid) };
}

/* A sealed frame carries its own counter. GCM fails catastrophically if a nonce
 * repeats under one key, so the counter is never reset and each direction has
 * its own key, which is why the two are derived separately above. */
export function sealer(keys, direction) {
  const key = direction === 'toAgent' ? keys.toAgent : keys.toBrowser;
  const aad = new TextEncoder().encode(keys.sid);
  let counter = 0n;

  return async function seal(plaintext) {
    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setBigUint64(4, counter++);
    const box = await SUBTLE.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      plaintext
    );
    return `${counter - 1n}.${b64u(box)}`;
  };
}

export function opener(keys, direction) {
  const key = direction === 'toAgent' ? keys.toAgent : keys.toBrowser;
  const aad = new TextEncoder().encode(keys.sid);
  let expected = 0n;

  return async function open(frame) {
    const dot = String(frame).indexOf('.');
    if (dot < 1) throw new Error('malformed frame');
    const counter = BigInt(String(frame).slice(0, dot));

    // Refusing anything not strictly newer is what stops the relay replaying an
    // old frame, or quietly dropping one and having the rest still decrypt.
    if (counter < expected) throw new Error('replayed or reordered frame');
    expected = counter + 1n;

    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setBigUint64(4, counter);
    const plain = await SUBTLE.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      unb64u(String(frame).slice(dot + 1))
    );
    return new Uint8Array(plain);
  };
}

// Browser authorization is separate from the machine's ECDH identity.
const SIGNING = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256' };

export async function generateBrowserIdentity() {
  const pair = await SUBTLE.generateKey(SIGNING, true, ['sign', 'verify']);
  return {
    publicKey: b64u(await SUBTLE.exportKey('spki', pair.publicKey)),
    privateKey: b64u(await SUBTLE.exportKey('pkcs8', pair.privateKey)),
  };
}

export async function validateBrowserKey(key) {
  if (typeof key !== 'string' || key.length > 200 || !/^[A-Za-z0-9_-]+$/.test(key)) {
    throw new Error('invalid browser public key');
  }
  return SUBTLE.importKey('spki', unb64u(key), SIGNING, false, ['verify']);
}

export function newChallenge() {
  return b64u(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

// An ordered tuple prevents serialization differences. All executable launch
// parameters are bound to the signature, as are the machine and ephemeral key.
function authorizationBytes(challenge, machineKey, request) {
  return new TextEncoder().encode(JSON.stringify([
    'evterm browser authorization v1', challenge, machineKey, request.sid,
    request.kx, request.tmuxSession || 'evterm', request.startCommand || '',
  ]));
}

export async function signAuthorization(identity, challenge, machineKey, request) {
  const key = typeof identity.privateKey === 'string'
    ? await SUBTLE.importKey('pkcs8', unb64u(identity.privateKey), SIGNING, false, ['sign'])
    : identity.privateKey;
  return b64u(await SUBTLE.sign(SIGN_ALGORITHM, key, authorizationBytes(challenge, machineKey, request)));
}

export async function verifyAuthorization(publicKey, signature, challenge, machineKey, request) {
  try {
    if (typeof signature !== 'string' || signature.length > 150) return false;
    return await SUBTLE.verify(SIGN_ALGORITHM, await validateBrowserKey(publicKey),
      unb64u(signature), authorizationBytes(challenge, machineKey, request));
  } catch { return false; }
}

/* --- control operations, outside a session --------------------------------
 *
 * Listing what tmux is holding on a machine, and ending one of those sessions,
 * are things the car has to be able to do without a shell already open. Over
 * SSH the server does it directly, because over there the server is the SSH
 * client anyway. A machine that dialled in is the opposite case: the relay must
 * not be able to run anything on it, which is why the agent refuses an unsigned
 * `kill` frame — and why, before this, there was no way at all to end a session
 * on a linked machine. The product claimed otherwise.
 *
 * So a control request is signed by an authorized browser, exactly as opening a
 * shell is. Its own domain string and its own tuple, separate from the session
 * authorization above: a signature that opens a shell must never be replayable
 * as one that kills something, and vice versa.
 */
function controlBytes(challenge, machineKey, op) {
  return new TextEncoder().encode(JSON.stringify([
    'evterm control v1', challenge, machineKey, op.op || '', op.session || '',
  ]));
}

export async function signControl(identity, challenge, machineKey, op) {
  const key = typeof identity.privateKey === 'string'
    ? await SUBTLE.importKey('pkcs8', unb64u(identity.privateKey), SIGNING, false, ['sign'])
    : identity.privateKey;
  return b64u(await SUBTLE.sign(SIGN_ALGORITHM, key, controlBytes(challenge, machineKey, op)));
}

export async function verifyControl(publicKey, signature, challenge, machineKey, op) {
  try {
    if (typeof signature !== 'string' || signature.length > 150) return false;
    return await SUBTLE.verify(SIGN_ALGORITHM, await validateBrowserKey(publicKey),
      unb64u(signature), controlBytes(challenge, machineKey, op));
  } catch { return false; }
}
