---
name: sx
description: Run commands that need secrets (API keys, tokens, credentials) from a .env file or AWS credentials from a named profile without reading the secret values. Use whenever a shell command needs a credential that is not already in the environment — whether it lives in a .env file or must be minted from a named AWS profile — run the command through `sx run --env <file> -- <command>` or `sx run --aws-profile <profile> -- <command>` instead of reading the file, exporting/sourcing variables, running `aws configure export-credentials`, or echoing them.
---

# sx — use secrets without reading them

`sx` runs a command with the secrets from a `.env` file injected into it, while
keeping the secret **values** out of your context. A trusted background daemon
holds the values and injects them into the command's environment; you only ever
see redacted output (`‹redacted›`). You cannot read the values, and you don't
need to.

## When to use this

Reach for `sx` whenever a command needs a secret that isn't already in the
environment — an API token, key, password, or connection string — and that
secret lives in a `.env` file (e.g. `GITHUB_TOKEN`, `OPENAI_API_KEY`,
`DATABASE_URL`, `STRIPE_SECRET_KEY`).

It also covers AWS credentials from a named profile: when a command (e.g. `aws`,
`terraform`, `aws-cdk`) needs to run against a profile, `sx` mints temporary
credentials from it so the profile's keys never enter your context.

## How

Run the real command through `sx run`, naming a `.env` file with `--env` and/or
an AWS profile with `--aws-profile`:

```sh
sx run --env .env -- gh pr create --title "..."
sx run --env .env -- curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
sx run --env .env -- npm publish
sx run --aws-profile prod -- aws s3 ls
sx run --env .env --aws-profile prod -- ./deploy.sh
```

- `--env <path>` is repeatable; **all** of the file's variables are
  injected into the command. The variables are real inside the command — refer
  to them normally (`$OPENAI_API_KEY`), they just come back redacted in output.
- `--aws-profile <profile>` is repeatable and freely combinable with `--env` in
  one run; at least one source (`--env` or `--aws-profile`) is required. It
  mints temporary credentials from the named profile (SSO, assume-role, or
  static) and injects them as `AWS_*` env vars (`AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, usually
  `AWS_CREDENTIAL_EXPIRATION` / `AWS_REGION`). The values come back redacted in
  output, same as `.env` secrets.
- The first use of a source (file or profile) prompts the **user** (TouchID) to
  grant it for an hour; by default the user also confirms **each command**.
  These prompts go to the human, not to you.
- See what's available without seeing values: `sx status` (lists files and
  variable names only).

## Rules — important

- **Never try to read a secret value.** Do not `cat` the `.env`, run `printenv`,
  `echo $TOKEN`, `printenv AWS_SECRET_ACCESS_KEY`, or pipe a secret (including
  the minted `AWS_*` creds) through a command whose only purpose is to print it
  — the value returns as `‹redacted›`, so it only wastes a turn. To *use* a
  secret, wrap the real command in `sx run --env … --` or
  `sx run --aws-profile … --`.
- **Always go through `sx run`.** Don't `export` the values or `source` the
  `.env` — a sandbox may block reading the file directly anyway.
- If `sx run` prints `denied:`, the user declined the prompt — **stop and ask**,
  don't retry in a loop.
- Per-command confirmation is the default. If the user is doing many `sx run`
  calls and wants to skip the prompts, they (not you) can run
  `sx grant-all --env <file>` or `sx grant-all --aws-profile <profile>` once to
  allow that source for an hour — suggest it, but don't assume it, since it
  lowers their security.

## Quick reference

| Goal | Command |
|------|---------|
| Run a command with secrets | `sx run --env .env -- <cmd>` |
| Use several files at once | `sx run --env a.env --env b.env -- <cmd>` |
| Run a command with an AWS profile | `sx run --aws-profile prod -- <cmd>` |
| Mix files and profiles | `sx run --env .env --aws-profile prod -- <cmd>` |
| See available names (no values) | `sx status` |
| (user only) allow a file without per-command prompts | `sx grant-all --env .env` |
| (user only) allow a profile without per-command prompts | `sx grant-all --aws-profile prod` |
| (user only) revoke a file early | `sx clear .env` |
| (user only) revoke a profile early | `sx clear --aws-profile prod` |
