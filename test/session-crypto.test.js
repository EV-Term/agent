/* The exchange has to hold against the relay, which is the party it exists to
 * exclude. So the tests are written from the relay's point of view: what can a
 * server in the middle do with the frames passing through it?
 *
 * Run: node test/session-crypto.test.js
 */
import assert from 'node:assert/strict';
import {
  generateIdentity,
  generateBrowserIdentity,
  fingerprint,
  startHandshake,
  acceptHandshake,
  sealer,
  opener,
  newChallenge,
  signAuthorization,
  verifyAuthorization,
} from '../session-crypto.js';

const SID = 's1';
const text = (s) => new TextEncoder().encode(s);
const str = (b) => new TextDecoder().decode(b);

// --- both ends reach the same keys ------------------------------------------
const agent = await generateIdentity();
const browser = await startHandshake(agent.publicKey, SID);
const accepted = await acceptHandshake(
  agent.privateKey,
  agent.publicKey,
  browser.ephemeralPublic,
  SID
);
const browserKeys = await browser.complete(accepted.ephemeralPublic);

const toAgent = sealer(browserKeys, 'toAgent');
const fromBrowser = opener(accepted.keys, 'toAgent');
const toBrowser = sealer(accepted.keys, 'toBrowser');
const fromAgent = opener(browserKeys, 'toBrowser');

assert.equal(str(await fromBrowser(await toAgent(text('claude --help\n')))), 'claude --help\n');
assert.equal(str(await fromAgent(await toBrowser(text('$ ')))), '$ ');

// Terminal output is not text. A byte sequence that is not valid UTF-8 has to
// survive, or escape sequences split across reads corrupt the screen.
const raw = new Uint8Array([0x1b, 0x5b, 0x32, 0x4a, 0xff, 0xfe, 0x00, 0x80]);
assert.deepEqual(await fromAgent(await toBrowser(raw)), raw);

// --- the relay cannot read -------------------------------------------------
const sealed = await toAgent(text('secret'));
assert.ok(!sealed.includes('secret'), 'plaintext is not in the frame');

// --- the relay cannot substitute the agent ---------------------------------
// A man in the middle swaps the agent's static key for its own. The browser
// pinned the real one, so the keys disagree and the first frame fails to open.
const impostor = await generateIdentity();
const fooled = await startHandshake(impostor.publicKey, SID);
const real = await acceptHandshake(
  agent.privateKey,
  agent.publicKey,
  fooled.ephemeralPublic,
  SID
);
const fooledKeys = await fooled.complete(real.ephemeralPublic);
await assert.rejects(
  opener(real.keys, 'toAgent')(await sealer(fooledKeys, 'toAgent')(text('hello'))),
  'a substituted static key must not produce a working session'
);

/* --- the relay cannot replay, reorder, or quietly drop ---------------------
 *
 * Strictly the next counter, every time. Refusing only *older* frames stops a
 * replay but not a truncation: the relay could drop one — a line of output, a
 * keystroke, a confirmation prompt — and everything after it would still
 * decrypt, so neither end could tell. A gap is not something a working
 * transport produces here (WebSocket over TCP does not lose frames without
 * closing, and the sealing side chains its writes), so a gap means someone in
 * the middle. */
// Its own pair, because the checks above deliberately sealed a frame that was
// never delivered, and under the strict rule that is itself a gap.
const seq = sealer(browserKeys, 'toAgent');
const inSeq = opener(accepted.keys, 'toAgent');
const first = await seq(text('one'));
const second = await seq(text('two'));
const third = await seq(text('three'));

assert.equal(str(await inSeq(first)), 'one');
await assert.rejects(inSeq(third), /out of sequence/, 'a skipped frame ends the session');
await assert.rejects(inSeq(first), /out of sequence/, 'and a replayed one does too');
assert.ok(second, 'the frame the relay would have dropped');

// --- the relay cannot tamper -----------------------------------------------
const frame = await toAgent(text('rm -rf /tmp/safe'));
const [counter, body] = frame.split('.');
const flipped = body.slice(0, -4) + (body.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
await assert.rejects(fromBrowser(`${counter}.${flipped}`));

// --- the relay cannot splice one session into another ----------------------
// The session id is authenticated data, so frames from another session on the
// same socket do not open here even when both keys are legitimate.
const other = await startHandshake(agent.publicKey, 's2');
const otherAccepted = await acceptHandshake(
  agent.privateKey,
  agent.publicKey,
  other.ephemeralPublic,
  's2'
);
const otherKeys = await other.complete(otherAccepted.ephemeralPublic);
await assert.rejects(
  opener(accepted.keys, 'toAgent')(await sealer(otherKeys, 'toAgent')(text('x'))),
  'frames are bound to their session id'
);

// --- fingerprints are comparable by a person -------------------------------
const fp = await fingerprint(agent.publicKey);
assert.match(fp, /^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/, 'reads as four short groups');
assert.equal(fp, await fingerprint(agent.publicKey), 'stable');
assert.notEqual(fp, await fingerprint(impostor.publicKey));

// Encryption confirms the machine, while this signature confirms the browser
// was explicitly authorized by the machine owner before a shell can start.
const authorizedBrowser = await generateBrowserIdentity();
const request = { sid: SID, kx: browser.ephemeralPublic, tmuxSession: 'work', startCommand: 'codex' };
const challenge = newChallenge();
const signature = await signAuthorization(authorizedBrowser, challenge, agent.publicKey, request);
assert.equal(
  await verifyAuthorization(authorizedBrowser.publicKey, signature, challenge, agent.publicKey, request),
  true,
  'authorized browser verifies'
);
assert.equal(
  await verifyAuthorization(authorizedBrowser.publicKey, signature, challenge, agent.publicKey, { ...request, startCommand: 'sh' }),
  false,
  'the signature binds the executable launch request'
);
assert.equal(
  await verifyAuthorization(authorizedBrowser.publicKey, signature, newChallenge(), agent.publicKey, request),
  false,
  'a captured proof cannot be replayed'
);

console.log('session-crypto: ok');
