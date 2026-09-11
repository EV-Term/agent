#!/usr/bin/env node
/* The EV Term agent.
 *
 * Holds one WebSocket open *outwards* to an EV Term server so a browser in a
 * car can reach a shell on this machine. Nothing listens here, no port is
 * forwarded, and the connection is one you started and can end.
 *
 * No dependencies, on purpose. This is a program that gives a remote screen a
 * shell on your laptop; it should be short enough that you can read all of it
 * before running it. That rules out a native pty module, so the pty comes from
 * tools already on the machine — Python's stdlib pty, or script(1) — and tmux
 * keeps the session alive across the disconnections a moving car guarantees.
 *
 * Requires Node 22+ for the built-in WebSocket client.
 */
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

function run(cfg, { code } = {}) {
  const base = cfg.server.replace(/^http/, 'ws').replace(/\/+$/, '');
  const params = new URLSearchParams({
    label: cfg.label,
    platform: `${process.platform} ${os.release()}`,
  });
  if (code) params.set('code', code);
  else params.set('token', cfg.token);

  const ws = new WebSocket(`${base}/agent?${params}`);
  let backoff = 1000;

  const send = (frame) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(frame));
  };

  ws.addEventListener('open', () => {
    backoff = 1000;
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
      console.log('run `evterm` to keep it connected, or `evterm unlink` to undo.');
      ws.close();
      process.exit(0);
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

    if (msg.t === 'open') handleOpen(msg, send);
    else if (msg.t === 'data') {
      const s = sessions.get(msg.sid);
      if (s) s.child.stdin.write(Buffer.from(msg.d, 'base64'));
    } else if (msg.t === 'resize') {
      const s = sessions.get(msg.sid);
      if (s) resizeSession(s, clamp(msg.cols, 20, 500), clamp(msg.rows, 5, 200));
    } else if (msg.t === 'close') {
      const s = sessions.get(msg.sid);
      // Detaching, not killing: the work in tmux outlives the car losing signal.
      if (s) s.child.kill();
    }
  });

  const reconnect = () => {
    for (const [sid, s] of sessions) {
      s.child.kill();
      sessions.delete(sid);
    }
    if (code) return; // linking is a one-shot, not a daemon
    console.error(`disconnected, retrying in ${Math.round(backoff / 1000)}s`);
    setTimeout(() => run(cfg), backoff);
    backoff = Math.min(backoff * 2, 30000);
  };

  ws.addEventListener('close', reconnect);
  ws.addEventListener('error', () => {});
}

const clamp = (n, lo, hi) => Math.min(Math.max(Number(n) || lo, lo), hi);

function handleOpen(msg, send) {
  const sid = msg.sid;
  if (sessions.has(sid)) return;

  const name = safeName(msg.tmuxSession, 'evterm');
  const cols = clamp(msg.cols, 20, 500);
  const rows = clamp(msg.rows, 5, 200);
  let child;
  try {
    child = spawnPty(buildCommand(name, msg.startCommand), cols, rows);
  } catch (err) {
    // Final: no amount of retrying finds a pty that is not installed.
    send({ t: 'status', sid, s: 'error', msg: err.message, final: true });
    return;
  }
  sessions.set(sid, { child, name });

  // Coalesce before sending. A shell streams in many tiny writes, and one frame
  // per write is mostly framing overhead over a car's mobile connection.
  let pending = [];
  let flushTimer = null;
  const flush = () => {
    flushTimer = null;
    if (!pending.length) return;
    send({ t: 'data', sid, d: Buffer.concat(pending).toString('base64') });
    pending = [];
  };
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

  send({ t: 'status', sid, s: 'ready', msg: os.hostname() });
}

/* --- cli ----------------------------------------------------------------- */

const argv = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};
const command = argv.find((a) => !a.startsWith('--')) || 'run';

if (command === 'link') {
  const code = argv[argv.indexOf('link') + 1];
  if (!code || code.startsWith('--')) {
    console.error('usage: evterm link <CODE> [--server https://...] [--name "My laptop"]');
    process.exit(1);
  }
  const existing = readConfig();
  run(
    {
      server: flag('server', (existing && existing.server) || DEFAULT_SERVER),
      label: flag('name', os.hostname()),
    },
    { code: code.toUpperCase() }
  );
} else if (command === 'unlink') {
  try {
    fs.rmSync(CONFIG_FILE);
    console.log('credentials deleted. remove the machine in the app too, or it can be re-linked.');
  } catch {
    console.log('nothing to unlink.');
  }
} else if (command === 'status') {
  const cfg = readConfig();
  if (!cfg) {
    console.log('not linked. run: evterm link <CODE>');
    process.exit(1);
  }
  console.log(`linked to ${cfg.server} as "${cfg.label}" (id ${cfg.id})`);
} else {
  const cfg = readConfig();
  if (!cfg || !cfg.token) {
    console.error('not linked yet. open EV Term in the car, tap Add machine, then run:');
    console.error('  evterm link <CODE>');
    process.exit(1);
  }
  run(cfg);
}
