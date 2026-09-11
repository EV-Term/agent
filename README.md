# EV Term agent

Connects a machine you own to [EV Term](https://evterm.com) so you can reach a
shell on it from your car.

```bash
npx github:EV-Term/agent link ABC123
npx github:EV-Term/agent
```

The code comes from the app: open EV Term in the car, tap **Add machine**, and
it shows you six characters to type here.

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
- **python3 or `script`** — one of them, for the terminal itself. Both are
  usually already there. Node cannot open a pty on its own and a native module
  would mean a compiler on your machine, which is a worse trade than using a
  tool you already have.

## Commands

| | |
| --- | --- |
| `evterm link <CODE>` | Pair with an account. Writes `~/.evterm/agent.json`, mode 600. |
| `evterm` | Stay connected. This is the one you leave running. |
| `evterm status` | What it is linked to. |
| `evterm unlink` | Delete the credentials here. |

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

**Today the server can see the stream.** End-to-end encryption between the car
and this agent is not implemented yet. Run it against a server you control until
it is.
