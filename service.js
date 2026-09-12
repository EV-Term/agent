/* Keeping the agent running.
 *
 * Without this the product forgets your machine every time you close a laptop
 * lid, and step 2 of the setup has to be done again. So `evterm install` hands
 * the job to whatever the operating system already uses for background work:
 * launchd on macOS, systemd --user on Linux. No new daemon of our own, nothing
 * to keep updated, and `launchctl`/`systemctl` remain the way to inspect it.
 *
 * The agent is copied into ~/.evterm/agent first. The usual way in is
 * `npx github:EV-Term/agent`, which runs out of a cache directory npm is free
 * to delete; a service pointed at that path works until it silently does not.
 * A copy under the user's own directory is the only path that stays true.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/* How to say "run this again" in a way that works where you are. The
 * documented way in is `npx github:EV-Term/agent`, which runs the package once
 * and puts nothing on PATH, so telling someone to run `evterm uninstall` names
 * a command they do not have. */
export const RUN_AS = /[/\\](?:_npx|\.npm[/\\]_npx)[/\\]/.test(fileURLToPath(import.meta.url))
  ? 'npx -y github:EV-Term/agent'
  : 'evterm';

const HOME = os.homedir();
const CONFIG_DIR = path.join(HOME, '.evterm');
const INSTALL_DIR = path.join(CONFIG_DIR, 'agent');
const ENTRY = path.join(INSTALL_DIR, 'index.js');
const LOG = path.join(CONFIG_DIR, 'agent.log');

const LABEL = 'com.evterm.agent';
const PLIST = path.join(HOME, 'Library', 'LaunchAgents', `${LABEL}.plist`);
const UNIT_DIR = path.join(HOME, '.config', 'systemd', 'user');
const UNIT = path.join(UNIT_DIR, 'evterm.service');

// launchd and systemd both start with a PATH that has nothing in it a
// developer would recognise, and this agent shells out to tmux and python3.
// Homebrew on both architectures, then the system directories.
const PATH_ENV = [
  '/opt/homebrew/bin',
  '/usr/local/bin',
  path.join(HOME, '.local', 'bin'),
  '/usr/bin',
  '/bin',
  '/usr/sbin',
  '/sbin',
].join(':');

const run = (cmd, args) => execFileSync(cmd, args, { stdio: 'pipe' }).toString().trim();

// Quietly, because "already loaded" and "not loaded" are both fine outcomes
// depending on which way we are going.
function tryRun(cmd, args) {
  try {
    run(cmd, args);
    return true;
  } catch {
    return false;
  }
}

/* process.execPath is whatever ran this command, and on Homebrew that is a
 * versioned Cellar path: /opt/homebrew/Cellar/node/25.9.0_2/bin/node. A service
 * pinned to it keeps working until the next `brew upgrade node` deletes that
 * directory, and then fails at boot, months later, for no visible reason. So
 * prefer a stable path that resolves to a new enough node. */
function resolveNode() {
  const candidates = [
    '/opt/homebrew/bin/node',
    '/usr/local/bin/node',
    path.join(HOME, '.local', 'bin', 'node'),
    '/usr/bin/node',
  ];
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    try {
      const major = Number(run(candidate, ['--version']).replace(/^v/, '').split('.')[0]);
      // 22 is where the WebSocket client arrives. An older one can still work
      // with `ws` carried alongside, which is why this falls through to
      // process.execPath rather than refusing.
      if (major >= 22) return candidate;
    } catch {
      /* not runnable, try the next one */
    }
  }
  // nvm, asdf, volta and friends live at versioned paths too, but theirs stay
  // put until the user removes that version deliberately.
  return process.execPath;
}

/* Node 22 has a WebSocket client; Node 20 does not, and uses the optional `ws`
 * package instead. npx installs that into its own cache, which the copy under
 * ~/.evterm/agent cannot see — so on Node 20 the service would start, fail to
 * find a WebSocket, exit, and be restarted for ever, while `npx ... link` had
 * worked perfectly minutes earlier. Carry it along. */
function copyWs(dest) {
  if (globalThis.WebSocket) return true;
  try {
    const from = path.dirname(createRequire(import.meta.url).resolve('ws/package.json'));
    fs.cpSync(from, path.join(dest, 'node_modules', 'ws'), { recursive: true });
    return true;
  } catch {
    return false;
  }
}

function copyAgent() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  if (path.resolve(here) === path.resolve(INSTALL_DIR)) return; // already installed from here
  fs.mkdirSync(INSTALL_DIR, { recursive: true, mode: 0o700 });
  for (const file of ['index.js', 'session-crypto.js', 'service.js', 'terminal.py']) {
    const from = path.join(here, file);
    if (fs.existsSync(from)) fs.copyFileSync(from, path.join(INSTALL_DIR, file));
  }
  if (!copyWs(INSTALL_DIR)) {
    throw new Error(
      'this Node has no built-in WebSocket and `ws` could not be found to copy alongside.\n' +
        'install Node 22 or newer, then run the install again.'
    );
  }
}

const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function installLaunchd() {
  fs.mkdirSync(path.dirname(PLIST), { recursive: true });
  fs.writeFileSync(
    PLIST,
    `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${xml(resolveNode())}</string>
    <string>${xml(ENTRY)}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>${xml(PATH_ENV)}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>WorkingDirectory</key><string>${xml(HOME)}</string>
  <key>StandardOutPath</key><string>${xml(LOG)}</string>
  <key>StandardErrorPath</key><string>${xml(LOG)}</string>
</dict>
</plist>
`,
    { mode: 0o644 }
  );

  const target = `gui/${process.getuid()}`;
  tryRun('launchctl', ['bootout', `${target}/${LABEL}`]);
  // bootstrap is the supported verb since 10.11; load -w is the fallback for
  // anything older, and for the odd machine where bootstrap refuses a session
  // it does not consider a GUI one.
  if (!tryRun('launchctl', ['bootstrap', target, PLIST])) {
    run('launchctl', ['load', '-w', PLIST]);
  }

  return [
    'installed as a launchd agent. it starts at login and restarts if it dies.',
    '',
    `  logs      tail -f ${LOG}`,
    `  stop      launchctl bootout ${target}/${LABEL}`,
    `  remove    ${RUN_AS} uninstall`,
  ];
}

function installSystemd() {
  fs.mkdirSync(UNIT_DIR, { recursive: true });
  fs.writeFileSync(
    UNIT,
    `[Unit]
Description=EV Term agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${resolveNode()} ${ENTRY}
Environment=PATH=${PATH_ENV}
WorkingDirectory=${HOME}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`,
    { mode: 0o644 }
  );

  run('systemctl', ['--user', 'daemon-reload']);
  run('systemctl', ['--user', 'enable', '--now', 'evterm.service']);

  const out = [
    'installed as a systemd user service. it starts at boot and restarts if it dies.',
    '',
    '  logs      journalctl --user -u evterm -f',
    '  stop      systemctl --user stop evterm',
    `  remove    ${RUN_AS} uninstall`,
  ];

  // Without lingering, a user service stops when the last login session ends,
  // which on a headless box means it dies the moment you close the SSH you
  // installed it from. Worth saying out loud when it cannot be turned on.
  if (!tryRun('loginctl', ['enable-linger', os.userInfo().username])) {
    out.push(
      '',
      'note: could not enable lingering, so this stops when you log out. fix with:',
      `  sudo loginctl enable-linger ${os.userInfo().username}`
    );
  }

  return out;
}

/* Reporting "installed" because the files were written is how a service that
 * cannot start gets called a success. It has to be running a couple of seconds
 * later, and if it is not, the logs it already wrote are the answer. */
async function confirmRunning() {
  await new Promise((r) => setTimeout(r, 2500));

  if (process.platform === 'linux') {
    let state = '';
    try {
      state = run('systemctl', ['--user', 'is-active', 'evterm.service']);
    } catch (err) {
      state = String(err.stdout || '').trim() || 'inactive';
    }
    if (state === 'active') return [];
    let log = '';
    try {
      log = run('journalctl', ['--user', '-u', 'evterm', '-n', '12', '--no-pager']);
    } catch {
      /* no journal, no extra detail */
    }
    return ['', `the service is ${state}, not running. what it logged:`, log || '(nothing logged)'];
  }

  if (process.platform === 'darwin') {
    const printed = tryRun('launchctl', ['print', `gui/${process.getuid()}/${LABEL}`]);
    if (printed) return [];
    let log = '';
    try {
      log = fs.readFileSync(LOG, 'utf8').split('\n').slice(-12).join('\n');
    } catch {
      /* no log yet */
    }
    return ['', 'the service is not loaded. what it logged:', log || '(nothing logged)'];
  }

  return [];
}

/* A real `evterm` on PATH.
 *
 * Everything the product prints talks about `evterm status`, `evterm unlink`,
 * and after installing from npx none of those existed: npx runs the package
 * once out of a cache and puts nothing anywhere. Telling people to type the
 * long npx form for the rest of the machine's life is a worse answer than a
 * three line shim, which is also what every other tool of this shape does. */
function installShim() {
  const dir = path.join(HOME, '.local', 'bin');
  const shim = path.join(dir, 'evterm');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    shim,
    `#!/bin/sh\n# EV Term. Written by \`evterm install\`; remove with \`evterm uninstall\`.\nexec ${resolveNode()} ${ENTRY} "$@"\n`,
    { mode: 0o755 }
  );

  const onPath = (process.env.PATH || '').split(':').includes(dir);
  if (onPath) return ['', 'you can now run `evterm status` from anywhere.'];

  // Not on this shell's PATH, which is not the same as not on PATH. Debian and
  // most distributions add ~/.local/bin from ~/.profile when the directory
  // exists, and it did not exist until a moment ago, so the next login shell
  // usually has it. Say that before offering the edit.
  return [
    '',
    `installed \`evterm\` at ${shim}.`,
    'open a new terminal and run `evterm status`. if that still says command not found:',
    `  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile && . ~/.profile`,
  ];
}

export async function install() {
  copyAgent();
  let lines;
  if (process.platform === 'darwin') lines = installLaunchd();
  else if (process.platform === 'linux') lines = installSystemd();
  else
    throw new Error(
      `no service installer for ${process.platform}. run \`evterm\` under your own supervisor instead.`
    );
  return [...lines, ...installShim(), ...(await confirmRunning())];
}

export function uninstall() {
  const done = [];
  // Only our own shim: a file of that name someone else wrote is not ours to
  // delete.
  const shim = path.join(HOME, '.local', 'bin', 'evterm');
  try {
    if (fs.readFileSync(shim, 'utf8').includes(ENTRY)) {
      fs.rmSync(shim);
      done.push(`removed ${shim}`);
    }
  } catch {
    /* not there, or not ours */
  }
  if (process.platform === 'darwin') {
    tryRun('launchctl', ['bootout', `gui/${process.getuid()}/${LABEL}`]) ||
      tryRun('launchctl', ['unload', '-w', PLIST]);
    if (fs.existsSync(PLIST)) {
      fs.rmSync(PLIST);
      done.push(`removed ${PLIST}`);
    }
  } else if (process.platform === 'linux') {
    tryRun('systemctl', ['--user', 'disable', '--now', 'evterm.service']);
    if (fs.existsSync(UNIT)) {
      fs.rmSync(UNIT);
      done.push(`removed ${UNIT}`);
    }
    tryRun('systemctl', ['--user', 'daemon-reload']);
  }
  // The copy stays: uninstall stops the service, it does not unlink the
  // machine. `evterm unlink` is the one that takes the credentials away.
  return done.length ? done : ['no service was installed.'];
}

/* True when this process is the copy the service runs, which is how it avoids
 * warning that a service is already running this agent: it is that service. */
export const isInstalledCopy = () =>
  path.resolve(path.dirname(fileURLToPath(import.meta.url))) === path.resolve(INSTALL_DIR);

export function serviceStatus() {
  if (process.platform === 'darwin') {
    if (!fs.existsSync(PLIST)) return 'service: not installed';
    const out = tryRun('launchctl', ['print', `gui/${process.getuid()}/${LABEL}`]);
    return out ? 'service: installed and loaded (launchd)' : 'service: installed but not loaded';
  }
  if (process.platform === 'linux') {
    if (!fs.existsSync(UNIT)) return 'service: not installed';
    let state = '';
    try {
      state = run('systemctl', ['--user', 'is-active', 'evterm.service']);
    } catch (err) {
      state = (err.stdout || '').toString().trim() || 'inactive';
    }
    return `service: installed (systemd, ${state})`;
  }
  return 'service: not supported on this platform';
}
