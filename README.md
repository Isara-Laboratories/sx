# sx

Conditioned secret access for sandboxed AI agents.

Agents need secrets, but environment variables leak them to the whole agent (and
its LLM context), and a `.env` the agent can read can't be sandboxed away. `sx`
lets programs the agent runs *use* secrets without letting the agent *read*
them, with a human in the loop: a TouchID grant per `.env` file (1 hour) and, by
default, a confirmation of every command.

- **`sxd`** — a secrets oracle outside the sandbox. Reads `.env` files (or mints
  temporary AWS credentials from a named profile), grants a source for 1 hour on
  first use, confirms each command (unless the source is `grant-all`), and
  releases values. It never executes anything.
- **`sx`** — the in-sandbox client. For `run`, it receives the granted values,
  injects them, and execs the command as **its own** child — so the child
  inherits `sx`'s sandbox and the daemon is never a way out of it. Redacts the
  values from the command's output.

## Install

```sh
./install.sh        # builds, installs sx + sxd to ~/.cargo/bin, auto-starts sxd at login
```

On macOS this registers `sxd` as a per-user **LaunchAgent** (`RunAtLoad` +
`KeepAlive`) so it starts at login and respawns if it dies. It's a LaunchAgent,
not a LaunchDaemon, because `sxd` shows TouchID prompts — those only work inside
your GUI session, and the daemon must run as you for the peer-credential check.

```sh
sxd install            # register + start the agent, AND record the aws CLI path (--print: dry run)
sxd setup              # just (re-)record the aws CLI path in ~/.sx/config (--print: dry run)
sxd uninstall          # stop + remove it
launchctl print gui/$(id -u)/dev.sx.sxd   # inspect; log at ~/.sx/sxd.log
```

**AWS minting needs the `aws` CLI path resolved once at setup.** launchd starts
`sxd` with a minimal `$PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`), so the daemon
can't find `/usr/local/bin/aws` (or Homebrew's) by searching `$PATH`. `sxd
setup` — run automatically by `sxd install` — resolves the `aws` executable's
absolute path in *your* shell `$PATH` and stores it in `~/.sx/config` as
`aws_cli_path`. The daemon then spawns that absolute path verbatim, never
searching `$PATH`. The config is read fresh on every mint, so after a rebuild +
`sxd setup` (or `sxd install`) the already-running daemon works on the next mint
with no `launchctl` reload. (`$SX_AWS_PATH` overrides the config for tests/CI.)

Linux/Windows auto-start isn't wired up yet (a headless service can't present the
approval prompt); run `sxd` manually there for now.

## Usage

```sh
# Default: grant the file for 1h on first use, AND confirm every command.
sx run --env .env -- gh pr create     # 1st use: TouchID grants .env + confirms this cmd
sx run --env .env -- gh pr merge      # within the hour: still confirms THIS command

# Opt a file out of per-command confirmation for the hour (off by default):
sx grant-all --env .env               # one prompt, then its commands run unprompted
sx run --env .env -- gh pr merge      # no prompt

# Pick a longer (or shorter) window with --lease (default 1h, max 24h):
sx grant-all --env .env --lease 1d    # allow-all for a day; also accepts 30m, 2h, 5400
sx grant-all --aws-profile dev/readonly --aws-profile prod/readonly --lease 12h
                                      # one prompt grants both profiles for 12h

sx status                             # granted files + mode + names (never values)
sx clear .env                         # revoke early

# AWS profiles are a second source: sxd mints temporary credentials for the
# named profile and injects them, gated and TTL'd exactly like a .env grant.
sx run --aws-profile prod -- aws s3 ls          # 1st use: grant + confirm; SSO/role/static all work
sx run --env .env --aws-profile prod -- deploy  # merge both sources in one run
sx clear --aws-profile prod                     # revoke a single profile grant
```

## Teaching agents to use it

[`SKILL.md`](./SKILL.md) is an Agent-Skills skill that tells a coding agent to
reach for `sx run --env` (and never to read secret values). Install it into the
agents you use:

```sh
sx skill install                 # Claude Code, Codex, and Pi (all three)
sx skill install --claude        # just one; --print for a dry run
sx skill uninstall               # remove it
```

All three implement the same Agent Skills standard, so it's the same `SKILL.md`
in each one's skills directory: `~/.claude/skills/sx/SKILL.md` (Claude Code),
`~/.codex/skills/sx/SKILL.md` (Codex), and `~/.pi/agent/skills/sx/SKILL.md`
(Pi). Restart a running agent session to pick it up.

See [DESIGN.md](./DESIGN.md) for the threat model, the double-gate model, and
known v1 simplifications.
