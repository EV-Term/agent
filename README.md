# EV Term agent

Connects a machine you own to [EV Term](https://evterm.com) so you can reach a
shell on it from your car.

```bash
curl -fsSL https://evterm.com/install.sh | sh -s ABC123
```

The code comes from the app: open EV Term in the car, tap **Add machine**, and
it shows you six characters. That script checks Node and tmux and then runs the
one command it exists to save you typing:

```bash
npx -y github:EV-Term/agent link ABC123
```

Either way, linking pairs the machine **and** installs a small background
service, because a machine that only runs while a terminal window is open is not
a machine you can reach from a car. Pass `--no-install` to skip that.

## What it actually does

It opens one WebSocket **outwards** to the EV Term server and keeps it there.
Nothing listens on this machine, no port is forwarded, and your router does not
need to know about any of it. When the car asks for a shell, the agent starts
one inside `tmux` and pipes it down that socket.

Because the shell lives in tmux, losing signal does not lose your work — the car
reattaches to the same session rather than starting a new one. This matters more
than it sounds: a car drops its connection constantly.

## What it needs

- **Node 22+** — for the built-in WebSocket client. That is the whole reason this
  has no dependencies.
- **tmux** — `brew install tmux`, `apt install tmux`. Without it you still get a
  shell, but it dies with the connection.
- **python3** — for the terminal itself. Node cannot open a pty on its own, and
  a native module would mean a compiler on your machine, which is a worse trade
  than using something already installed. `script(1)` stands in when python3 is
  missing, but it cannot be told how big your screen is, so the terminal stays
  at 80x24.

## Commands

| | |
| --- | --- |
| `evterm link <CODE>` | Pair with an account. Writes `~/.evterm/agent.json`, mode 600. |
| `evterm` | Stay connected. This is the one you leave running. |
| `evterm install` | Keep it running: a launchd agent on macOS, a systemd user service on Linux. |
| `evterm status` | What it is linked to, and whether the service is loaded. |
| `evterm uninstall` | Stop and remove that service. Stays linked. |
| `evterm unlink` | Delete the credentials here. |

### Keeping it running

`evterm` in a terminal stops when you close the lid or the window. `evterm install`
hands the job to the operating system instead:

```sh
npx -y github:EV-Term/agent link 7K4QPS     # installs the service too
npx -y github:EV-Term/agent install          # or on its own, later
```

`npx` runs the package and puts nothing on your PATH, so `evterm` on its own is
`command not found` unless you installed it globally. Every command below works
the same way with `npx github:EV-Term/agent` in front of it, and the agent prints
whichever form applies to how you started it.

It copies the agent to `~/.evterm/agent` first, because the usual way in is
`npx github:EV-Term/agent` and npm is free to delete its cache at any time. After
that, launchd or systemd starts it at login and restarts it if it dies. Logs go to
`~/.evterm/agent.log` on macOS and to `journalctl --user -u evterm` on Linux.

On a headless Linux box, check `loginctl show-user $USER -p Linger` says `yes`, or
the service stops when you log out. `evterm install` turns lingering on when it can
and tells you the sudo command when it cannot.

`--server https://...` points it at a different EV Term, and `--name "Studio Mac"`
sets how it appears in the car. Both are remembered after the first link.

## Before you run it

This program gives a remote screen a shell on this machine. That is the feature,
and it deserves to be read rather than trusted — it is one file, no
dependencies, and deliberately short enough to get through.

Worth knowing:

- The token in `~/.evterm/agent.json` is a bearer credential. Anyone holding it
  can ask for a shell here. The server stores only a hash of it.
- Removing the machine in the app revokes it immediately: the agent is told, and
  it deletes its own copy rather than retrying forever with a dead token.
- `evterm unlink` only clears this end. Remove the machine in the app too, or it
  can be linked again.
- The session is whatever your shell can do. There is no sandbox here.

## Encryption

Sessions are encrypted between the car and this machine. The server relays
frames it cannot read.

The key pair is generated here, at `evterm link`, and the private half never
leaves. The car pins the public half the first time it connects, the way SSH
pins a host key. That pinning is what makes the server relaying the key safe:
a server that substituted its own would produce a different fingerprint.

```
evterm status
```

prints the fingerprint. The car shows the same four groups on first connect, and
they have to match. If they do not, something is sitting in the middle.

Two honest limits. The first connection is trust on first use, so a server that
lied at exactly that moment would not be caught unless you compare the
fingerprint. And this covers sessions on machines that dial in; a host reached
over SSH is a different thing, because there the server is the SSH client and no
amount of browser-side crypto changes that.
