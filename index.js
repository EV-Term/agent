#!/usr/bin/env node
/* The EV Term agent.
 *
 * Holds one WebSocket open *outwards* to an EV Term server so a browser in a
 * car can reach a shell on this machine. Nothing listens here, no port is
 * forwarded, and the connection is one you started and can end.
 *
 * No dependencies on Node 22+. This is a program that gives a remote screen a
 * shell on your laptop; it should be short enough that you can read all of it
 * before running it. That rules out a native pty module, so the pty comes from
 * tools already on the machine — Python's stdlib pty, or script(1) — and tmux
 * keeps the session alive across the disconnections a moving car guarantees.
 *
 * Requires Node 22+ for the built-in WebSocket client. On Node 20 the `ws`
 * package is used instead, when it is installed alongside.
 */
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/* Node 22 has a WebSocket client built in; Node 20 does not. The `ws` package
 * speaks the same event API, so it is a drop-in when present — it ships as an
 * optional dependency, and Node 22+ never loads it. */
const WebSocket =
  globalThis.WebSocket ?? (await import('ws').catch(() => null))?.default;
if (!WebSocket) {
  console.error('This Node has no built-in WebSocket (needs Node 22+) and `ws` is not installed.');
  process.exit(1);
}

import { install, isInstalledCopy, RUN_AS, serviceStatus, uninstall } from './service.js';
import {
  acceptHandshake,
  fingerprint,
  generateIdentity,
  opener,
  sealer,
  newChallenge,
  validateBrowserKey,
  verifyAuthorization,
  verifyControl,
} from './session-crypto.js';

const CONFIG_DIR = path.join(os.homedir(), '.evterm');
const CONFIG_FILE = path.join(CONFIG_DIR, 'agent.json');
const DEFAULT_SERVER = 'https://app.evterm.com';

const readConfig = () => {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return null;
  }
};

function writeConfig(cfg) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  // The token is a bearer credential for a shell on this machine.
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 });
}

/* --- the pty ------------------------------------------------------------- */

// A tmux session name arrives from the other end, so keep it to characters that
// are both inert in a shell word and legal as a tmux target.
const safeName = (name, fallback) =>
  (String(name || '').trim().replace(/[^\w.-]/g, '').slice(0, 64)) || fallback;

const shellQuote = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

// Same shape the SSH transport uses, so a session started either way behaves
// the same. detach-on-destroy is forced on this session and not globally: a
// host configured with it off would otherwise drop `exit` into unrelated work
// instead of ending the connection.
function buildCommand(name, startCommand) {
  const q = shellQuote(name);
  const inner = startCommand ? ` -- "$SHELL" -lc ${shellQuote(startCommand)}` : '';
  return (
    `if command -v tmux >/dev/null 2>&1; then ` +
    `tmux has-session -t ${q} 2>/dev/null || tmux new-session -d -s ${q}${inner}; ` +
    `tmux set-option -t ${q} detach-on-destroy on >/dev/null 2>&1; ` +
    `exec tmux attach-session -d -t ${q}; ` +
    `fi; ` +
    `echo 'evterm: tmux is not installed - falling back to a plain shell, so this ` +
    `session will not survive a disconnect' >&2; ` +
    `exec "$SHELL" -l`
  );
}

// A pty without a native module, from whatever the machine already has.
//
// Python leads because it is the only one of the two that can be told how big
// the terminal is. BSD script(1) additionally calls tcgetattr on its own stdin,
// and a daemon's stdin is a pipe, so it dies with "Operation not supported on
// socket" before doing anything - it is here for machines with no python3,
// where a fixed 80x24 shell beats no shell.
const PTY_HELPER = path.join(path.dirname(fileURLToPath(import.meta.url)), 'terminal.py');

const PTY_RUNNERS = [
  {
    cmd: 'python3',
    sizeable: true,
    args: (command, cols, rows) => [PTY_HELPER, command, String(cols), String(rows)],
  },
  {
    cmd: 'script',
    sizeable: false,
    args: (command) =>
      process.platform === 'darwin'
        ? ['-q', '/dev/null', 'sh', '-c', command]
        : ['-qfc', command, '/dev/null'],
  },
];

function haveCommand(cmd) {
  try {
    // Run the shell directly rather than passing shell:true, which concatenates
    // arguments instead of escaping them and warns about it on every start.
    execFileSync('/bin/sh', ['-c', `command -v ${cmd}`], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function spawnPty(command, cols, rows) {
  const runner = PTY_RUNNERS.find((r) => haveCommand(r.cmd));
  if (!runner) {
    const err = new Error('no way to open a terminal: install python3, or util-linux for script(1)');
    err.code = 'ENOPTY';
    throw err;
  }
  const child = spawn(runner.cmd, runner.args(command, cols, rows), {
    env: { ...process.env, TERM: 'xterm-256color' },
    // The fourth stream is where later sizes go. Sending them down stdin would
    // put them in the terminal stream, where they are just characters the shell
    // would type out.
    stdio: runner.sizeable ? ['pipe', 'pipe', 'pipe', 'pipe'] : ['pipe', 'pipe', 'pipe'],
  });
  child.sizeable = runner.sizeable;
  return child;
}

// Resizing the pty is the whole of it: tmux sizes its window to the client, and
// the client is this pty. Going through tmux instead does not work - its
// `refresh-client -C` applies only to control mode clients and answers "not a
// control client" for a normal attach.
function resizeSession(session, cols, rows) {
  if (!session.child.sizeable) return;
  const control = session.child.stdio[3];
  if (control && control.writable) control.write(`${cols}x${rows}\n`);
}

/* --- the connection ------------------------------------------------------ */

const sessions = new Map();

/* Module scope, not inside run().
 *
 * It used to be declared in run(), which reconnect() calls afresh — so every
 * attempt started again at one second and the doubling on the line below was
 * dead code. During any outage every agent in the field retried once a second,
 * forever, which is a stampede aimed at the one box they all dial. */
let backoff = 1000;

function run(cfg, opts = {}) {
  const { code } = opts;
  const base = cfg.server.replace(/^http/, 'ws').replace(/\/+$/, '');
  const params = new URLSearchParams({
    label: cfg.label,
    platform: `${process.platform} ${os.release()}`,
  });
  if (code) params.set('code', code);
  else params.set('token', cfg.token);

  const ws = new WebSocket(`${base}/agent?${params}`);

  const send = (frame) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(frame));
  };

  ws.addEventListener('open', () => {
    backoff = 1000; // a connection that opened is a fresh start
    // The server is told the public half so it can hand it to a browser that
    // has not met this machine before. It can lie about it, which is exactly
    // what the fingerprint check in the car is for.
    send({ t: 'hello', publicKey: cfg.publicKey, authorization: 1, capabilities: { tmux: haveCommand('tmux'), python: haveCommand('python3'), tools: ['claude', 'codex', 'gemini', 'cursor-agent'].filter(haveCommand) } });
    console.log(`connected to ${cfg.server} as "${cfg.label}"`);
    if (!code) console.log('waiting for the car. ctrl-c to stop.');
  });

  ws.addEventListener('message', (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }

    if (msg.t === 'paired') {
      writeConfig({ ...cfg, id: msg.id, token: msg.token });
      console.log(`paired. this machine is "${cfg.label}".`);
      console.log(`credentials in ${CONFIG_FILE}`);
      ws.close();

      /* Pairing on its own leaves the car showing this machine as not
       * connected, because nothing is keeping the agent running. That was two
       * commands, and the second one got skipped, which is the same as not
       * having done the first. So linking installs the service too, unless
       * asked not to. */
      if (opts.install === false) {
        console.log('');
        console.log(`not installed, as asked. keep it running with ${RUN_AS} install,`);
        console.log(`or ${RUN_AS} to hold it open in this terminal.`);
        process.exit(0);
      }

      install().then(
        (lines) => {
          console.log('');
          for (const line of lines) console.log(line);
          process.exit(0);
        },
        (err) => {
          console.error('');
          console.error(`paired, but could not install the background service: ${err.message}`);
          console.error(`run ${RUN_AS} to hold it open in this terminal instead.`);
          process.exit(1);
        }
      );
      return;
    }

    if (msg.t === 'error') {
      console.error(`server refused the connection: ${msg.msg}`);
      ws.close();
      process.exit(1);
    }

    if (msg.t === 'revoked') {
      // The server forgot this machine. Reconnecting would only fail, and the
      // token on disk is now worthless, so say so rather than looping quietly.
      console.error('this machine was removed from the account. run `evterm link` again.');
      try {
        fs.rmSync(CONFIG_FILE);
      } catch {}
      process.exit(1);
    }

    if (msg.t === 'open') {
      handleOpen(msg, send, cfg).catch((err) => {
        console.error(`[agent] handleOpen error: ${err.message}`, err);
        send({ t: 'status', sid: msg.sid, s: 'error', msg: err.message, final: true });
      });
    } else if (msg.t === 'data') {
      const s = sessions.get(msg.sid);
      if (!s) return;
      // A frame that will not open is not written to the shell. Decryption
      // failing means the bytes are not the car's, and the only safe thing to
      // do with input of unknown origin is drop the session.
      // Serial processing preserves nonce order even during async verification.
      s.reading = (s.reading || Promise.resolve()).then(async () => {
        const plain = await s.open(msg.d);
        if (!s.authorized) {
          if (sessions.get(msg.sid) !== s) throw new Error('authorization expired');
          const proof = JSON.parse(new TextDecoder().decode(plain));
          const allowed = readConfig()?.authorizedKeys || [];
          if (!allowed.includes(proof.publicKey) || !await verifyAuthorization(
            proof.publicKey, proof.signature, s.challenge, cfg.publicKey, s.request
          )) throw new Error('This browser is not authorized. Run its authorization command on the machine.');
          clearTimeout(s.timer);
          s.authorized = true;
          s.browserKey = proof.publicKey;
          openAuthorizedShell(s, send);
        } else {
          // Local revocation takes effect on existing sessions as well.
          if (!(readConfig()?.authorizedKeys || []).includes(s.browserKey)) throw new Error('browser authorization revoked');
          s.child.stdin.write(plain);
        }
      }).catch((err) => {
        clearTimeout(s.timer);
        if (sessions.get(msg.sid) === s) sessions.delete(msg.sid);
        s.child?.kill();
        send({ t: 'status', sid: msg.sid, s: 'error', msg: err.message, final: true });
      });
    } else if (msg.t === 'resize') {
      const s = sessions.get(msg.sid);
      if (s?.child) resizeSession(s, clamp(msg.cols, 20, 500), clamp(msg.rows, 5, 200));
    } else if (msg.t === 'close') {
      const s = sessions.get(msg.sid);
      // Detaching, not killing: the work in tmux outlives the car losing signal.
      if (s) { clearTimeout(s.timer); sessions.delete(msg.sid); s.child?.kill(); }
    } else if (msg.t === 'kill') {
      // An unsigned relay message must never execute a command on the machine.
      // Signed control requests are the supported way; see below.
      send({ t: 'killed', session: msg.session, ok: false,
        msg: 'Update EV Term on this machine to manage sessions from the car.' });
    } else if (msg.t === 'control') {
      // Step one: a fresh challenge, so a signature cannot be replayed and the
      // relay cannot mint one of its own.
      const challenge = newChallenge();
      control.set(msg.rid, { challenge, op: msg.op, session: msg.session, at: Date.now() });
      send({ t: 'control-challenge', rid: msg.rid, challenge });
    } else if (msg.t === 'control-do') {
      runControl(msg, send, cfg).catch((err) =>
        send({ t: 'control-result', rid: msg.rid, ok: false, msg: err.message })
      );
    }
  });

  const reconnect = () => {
    for (const [sid, s] of sessions) {
      clearTimeout(s.timer);
      s.child?.kill();
      sessions.delete(sid);
    }
    if (code) return; // linking is a one-shot, not a daemon
    console.error(`disconnected, retrying in ${Math.round(backoff / 1000)}s`);
    // Jittered, so N agents that lost the same server do not come back in step.
    const wait = backoff + Math.floor(Math.random() * 1000);
    backoff = Math.min(backoff * 2, 30000);
    setTimeout(() => run(cfg), wait);
  };

  ws.addEventListener('close', reconnect);
  ws.addEventListener('error', () => {});
}

/* Control requests waiting for their signature. Short lived on purpose: a
 * challenge that outlives the moment is a replay window. */
const control = new Map();
const CONTROL_TTL_MS = 60_000;

/* Step two: the browser has signed the challenge together with what it is
 * asking for, so the relay can neither invent a request nor alter this one.
 * Only then does anything run, and only ever one of two fixed commands — there
 * is no path here that takes a string from the wire and executes it. */
async function runControl(msg, send, cfg) {
  for (const [rid, entry] of control) {
    if (Date.now() - entry.at > CONTROL_TTL_MS) control.delete(rid);
  }
  const pending = control.get(msg.rid);
  if (!pending) throw new Error('that request expired, try again');
  control.delete(msg.rid);

  const allowed = readConfig()?.authorizedKeys || [];
  const ok =
    allowed.includes(msg.publicKey) &&
    (await verifyControl(msg.publicKey, msg.signature, pending.challenge, cfg.publicKey, pending));
  if (!ok) throw new Error('This browser is not authorized on this machine.');

  if (!haveCommand('tmux')) throw new Error('tmux is not installed on this machine');

  if (pending.op === 'list') {
    const out = execFileSync(
      '/bin/sh',
      ['-c', "tmux list-sessions -F '#{session_name}|#{session_windows}|#{session_attached}' 2>/dev/null || true"],
      { encoding: 'utf8' }
    );
    const sessions = out
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [name, windows, attached] = line.split('|');
        return { name, windows: Number(windows) || 1, attached: attached === '1' };
      })
      .filter((entry) => entry.name);
    send({ t: 'control-result', rid: msg.rid, ok: true, sessions });
    return;
  }

  if (pending.op === 'kill') {
    const name = safeName(pending.session, '');
    if (!name) throw new Error('invalid session name');
    try {
      execFileSync('/bin/sh', ['-c', `tmux kill-session -t ${shellQuote(name)}`], { stdio: 'pipe' });
    } catch (err) {
      // Already gone is the outcome the caller wanted.
      const said = String(err.stderr || '');
      if (!/can't find session|no server running/i.test(said)) throw new Error(said.trim() || 'could not end it');
    }
    send({ t: 'control-result', rid: msg.rid, ok: true });
    return;
  }

  throw new Error('unknown control operation');
}

const clamp = (n, lo, hi) => Math.min(Math.max(Number(n) || lo, lo), hi);

async function handleOpen(msg, send, cfg) {
  const sid = msg.sid;
  if (typeof sid !== 'string' || sid.length > 100 || sessions.has(sid)) return;
  if (sessions.size >= 16) throw new Error('too many sessions; close a tab and retry');
  if (!(readConfig()?.authorizedKeys || []).length) throw new Error('Authorize a browser on this machine first. Update and run the authorization command shown in EV Term.');

  // No plaintext path. A session that cannot be encrypted does not open, rather
  // than falling back to something the server could read.
  if (!msg.kx) throw new Error('this machine only accepts encrypted sessions; update the car');
  const { ephemeralPublic, keys } = await acceptHandshake(
    cfg.privateKey,
    cfg.publicKey,
    msg.kx,
    sid
  );
  const seal = sealer(keys, 'toBrowser');
  const unseal = opener(keys, 'toAgent');

  const s = { request: { ...msg }, open: unseal, seal, challenge: newChallenge(), authorized: false, child: null };
  sessions.set(sid, s);
  s.timer = setTimeout(() => {
    if (sessions.get(sid) !== s || s.authorized) return;
    sessions.delete(sid);
    send({ t: 'status', sid, s: 'error', msg: 'Browser authorization timed out. Reconnect to try again.', final: true });
  }, 30_000);
  s.timer.unref();
  send({ t: 'status', sid, s: 'challenge', kx: ephemeralPublic, challenge: s.challenge });
}

function openAuthorizedShell(s, send) {
  const msg = s.request;
  const sid = msg.sid;
  const seal = s.seal;
  const name = safeName(msg.tmuxSession, 'evterm');
  const child = spawnPty(buildCommand(name, msg.startCommand), clamp(msg.cols, 20, 500), clamp(msg.rows, 5, 200));
  s.child = child;
  s.name = name;

  // Coalesce before sending. A shell streams in many tiny writes, and one frame
  // per write is mostly framing overhead over a car's mobile connection.
  let pending = [];
  let flushTimer = null;
  const flush = () => {
    flushTimer = null;
    if (!pending.length) return;
    // Revocation was only ever checked on the inbound path, so a browser that
    // stopped typing - watching a build, tailing a log - kept receiving output
    // from a key that had already been removed. Same check, same shutdown as
    // the inbound side, just triggered by output instead of a keystroke.
    if (!(readConfig()?.authorizedKeys || []).includes(s.browserKey)) {
      pending = [];
      if (sessions.get(sid) === s) sessions.delete(sid);
      child.kill();
      send({ t: 'status', sid, s: 'error', msg: 'browser authorization revoked', final: true });
      return;
    }
    const chunk = Buffer.concat(pending);
    pending = [];
    // Sealing is async and the counter inside the sealer is what orders these,
    // so the chain keeps writes in the order they were produced rather than the
    // order their promises happen to settle.
    sealing = sealing
      .then(() => seal(chunk))
      .then((d) => send({ t: 'data', sid, d }))
      .catch((err) => console.error(`dropped an output frame for ${sid}: ${err.message}`));
  };
  let sealing = Promise.resolve();
  const onOut = (chunk) => {
    pending.push(chunk);
    if (!flushTimer) flushTimer = setTimeout(flush, 10);
  };

  child.stdout.on('data', onOut);
  child.stderr.on('data', onOut);

  child.on('error', (err) => {
    sessions.delete(sid);
    send({ t: 'status', sid, s: 'error', msg: err.message, final: true });
  });

  child.on('exit', () => {
    flush();
    sessions.delete(sid);
    // Final: the shell is genuinely done, so the car should let the tab go
    // rather than reopening it and starting something new.
    send({ t: 'status', sid, s: 'closed', msg: 'session ended', final: true });
  });

  send({ t: 'status', sid, s: 'ready', msg: os.hostname(), authorized: true });
}

/* --- cli ----------------------------------------------------------------- */

const argv = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};
const command = argv.find((a) => !a.startsWith('--')) || 'run';

if (command === 'setup') {
  const existing = readConfig();
  const server = flag('server', (existing && existing.server) || DEFAULT_SERVER);
  const label = flag('name', os.hostname());
  const identity = await generateIdentity();
  const fp = await fingerprint(identity.publicKey);

  let startRes;
  try {
    const res = await fetch(`${server}/api/pair/device-start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label,
        platform: `${process.platform} ${os.release()}`,
        publicKey: identity.publicKey,
      }),
    });
    startRes = await res.json();
    if (!res.ok || !startRes?.code || !startRes?.pollToken) {
      throw new Error(startRes?.error || 'Failed to start pairing');
    }
  } catch (err) {
    console.error(`Could not reach ${server}: ${err.message}`);
    process.exit(1);
  }

  const { code, pollToken } = startRes;
  const pairUrl = `${server}/link?pair=${code}`;

  console.log('');
  console.log('  \x1b[1mEV Term Setup\x1b[0m');
  console.log('');
  console.log('  1. Open this link on your phone, laptop, or car:');
  console.log(`     \x1b[36m\x1b[4m${pairUrl}\x1b[0m`);
  console.log('');
  console.log(`  2. Machine:     \x1b[1m${label}\x1b[0m`);
  console.log(`     PIN Code:    \x1b[1m${code}\x1b[0m`);
  console.log(`     Fingerprint: ${fp}`);
  console.log('');
  console.log('  Waiting for approval in browser... (ctrl-c to cancel)');

  let approved = null;
  while (!approved) {
    await new Promise((r) => setTimeout(r, 2000));
    try {
      const pollRes = await fetch(`${server}/api/pair/device-poll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pollToken }),
      });
      const data = await pollRes.json().catch(() => ({}));
      if (data.status === 'ok') {
        approved = data;
        break;
      }
      if (data.status === 'expired') {
        console.error('\nPairing session expired. Run setup again.');
        process.exit(1);
      }
    } catch {
      // Network hiccup, retry
    }
  }

  console.log('\n  \x1b[32mApproved!\x1b[0m Linking machine...');
  const newConfig = {
    server,
    label,
    id: approved.agentId,
    token: approved.token,
    authorizedKeys: approved.allowKey ? [approved.allowKey] : [],
    publicKey: identity.publicKey,
    privateKey: identity.privateKey,
  };
  writeConfig(newConfig);

  console.log(`  Credentials saved to ${CONFIG_FILE}`);

  if (argv.includes('--no-install')) {
    console.log(`\n  Setup complete. Start anytime with: ${RUN_AS}`);
    process.exit(0);
  }

  try {
    console.log('  Installing background service...');
    const lines = await install();
    console.log('');
    for (const line of lines) console.log(`  ${line}`);
    console.log(`\n  \x1b[32mReady!\x1b[0m This machine is now linked to your EV Term account.`);
    process.exit(0);
  } catch (err) {
    console.error(`\n  Paired, but could not install service: ${err.message}`);
    console.error(`  Run "${RUN_AS}" to run in this terminal instead.`);
    process.exit(1);
  }
} else if (command === 'link') {
  const code = argv[argv.indexOf('link') + 1];
  if (!code || code.startsWith('--')) {
    console.error(`usage: ${RUN_AS} link <CODE> [--server https://...] [--name "My laptop"]`);
    process.exit(1);
  }
  const allowKey = flag('allow-key', '');
  try { await validateBrowserKey(allowKey); } catch {
    console.error('Use the complete setup command from EV Term, including --allow-key.');
    process.exit(1);
  }
  const existing = readConfig();
  // The key pair is this machine's identity to the car, and it is made here
  // rather than by the server precisely so the server never holds the private
  // half.
  const identity = await generateIdentity();
  const fp = await fingerprint(identity.publicKey);
  console.log('');
  console.log(`  fingerprint   ${fp}`);
  console.log('');
  console.log('the car shows this the first time it connects, under "Check this fingerprint".');
  console.log('they must match. if they do not, something is between you and this machine.');
  console.log(`you can see it again any time with: ${RUN_AS} status`);
  console.log('');
  run(
    {
      server: flag('server', (existing && existing.server) || DEFAULT_SERVER),
      label: flag('name', os.hostname()),
      authorizedKeys: [allowKey],
      publicKey: identity.publicKey,
      privateKey: identity.privateKey,
    },
    { code: code.toUpperCase(), install: !argv.includes('--no-install') }
  );
} else if (command === 'authorize' || command === 'deauthorize') {
  const cfg = readConfig();
  if (!cfg?.token) { console.error('Link this machine first.'); process.exit(1); }
  const arg = argv[argv.indexOf(command) + 1];
  if (!arg || arg.startsWith('--')) {
    console.error(`usage: ${RUN_AS} ${command} <CODE or PUBLIC-KEY>`);
    process.exit(1);
  }
  let key = arg;
  const pinNorm = key.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (command === 'authorize' && pinNorm.length === 8) {
    const server = cfg.server || DEFAULT_SERVER;
    try {
      const res = await fetch(`${server}/api/auth-code/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: pinNorm }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data?.ok || !data?.publicKey) {
        console.error(`Could not resolve authorization PIN "${key}": ${data?.error || 'Invalid or expired PIN'}`);
        process.exit(1);
      }
      key = data.publicKey;
      console.log('PIN verified.');
    } catch (err) {
      console.error(`Failed to connect to ${server}: ${err.message}`);
      process.exit(1);
    }
  }

  try { await validateBrowserKey(key); } catch {
    console.error('Invalid browser key or authorization PIN.');
    process.exit(1);
  }
  const keys = new Set(cfg.authorizedKeys || []);
  if (command === 'authorize') keys.add(key); else keys.delete(key);
  if (keys.size > 32) { console.error('Remove an old browser before authorizing another.'); process.exit(1); }
  writeConfig({ ...cfg, authorizedKeys: [...keys] });
  console.log(`${command === 'authorize' ? 'Authorized' : 'Revoked'} browser ${await fingerprint(key)}.`);
  console.log('Applies immediately to this agent. Authorize only browsers you own.');
} else if (command === 'unlink') {
  try {
    fs.rmSync(CONFIG_FILE);
    console.log('credentials deleted. remove the machine in the app too, or it can be re-linked.');
  } catch {
    console.log('nothing to unlink.');
  }
} else if (command === 'install') {
  const cfg = readConfig();
  if (!cfg || !cfg.token) {
    console.error('link this machine first, then install:');
    console.error(`  ${RUN_AS} link <CODE>`);
    process.exit(1);
  }
  try {
    for (const line of await install()) console.log(line);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
} else if (command === 'uninstall') {
  for (const line of uninstall()) console.log(line);
} else if (command === 'status') {
  const cfg = readConfig();
  if (!cfg) {
    console.log(`not linked. run: ${RUN_AS} link <CODE>`);
    process.exit(1);
  }
  console.log(`linked to ${cfg.server} as "${cfg.label}" (id ${cfg.id})`);
  if (cfg.publicKey) console.log(`fingerprint  ${await fingerprint(cfg.publicKey)}`);
  else console.log('no key pair: linked by an older version. run `evterm link` again.');
  console.log(`${cfg.authorizedKeys?.length || 0} authorized browser(s)`);
  for (const key of cfg.authorizedKeys || []) console.log(`  ${await fingerprint(key)}  ${key}`);
  console.log(`tmux: ${haveCommand('tmux') ? 'ready' : 'missing; sessions will not survive a disconnect'}`);
  console.log('Keep this computer awake and online while using EV Term.');
  console.log(serviceStatus());
} else {
  const cfg = readConfig();
  if (!cfg || !cfg.token) {
    console.error('not linked yet. To pair this machine with EV Term, run:');
    console.error(`  ${RUN_AS} setup`);
    console.error('');
    console.error('Or link with a code:');
    console.error(`  ${RUN_AS} link <CODE>`);
    process.exit(1);
  }
  if (!cfg.privateKey) {
    console.error('this machine was linked before sessions were encrypted.');
    console.error(`run \`${RUN_AS} link <CODE>\` again to generate a key pair.`);
    process.exit(1);
  }
  // Not when we are the service: it would be warning about itself, in its own
  // log, on every boot.
  if (!isInstalledCopy() && /loaded|active/.test(serviceStatus())) {
    console.log('note: a background service is already running this agent.');
    console.log('      two copies on one machine will take turns; stop one.\n');
  }
  run(cfg);
}
