# sx

Conditioned secret access for sandboxed AI agents.

Agents need secrets, but environment variables leak them to the whole agent (and
its LLM context), and a `.env` the agent can read can't be sandboxed away. `sx`
lets programs the agent runs *use* secrets without letting the agent *read*
them, with a human in the loop at capture and at each use.

- **`sx`** — a powerless in-sandbox client. Forwards paths, secret names, and
  argv; never reads a secret.
- **`sxd`** — a daemon outside the sandbox. Reads `.env` files (TouchID-gated),
  holds values in memory under a TTL, injects them into child processes it
  spawns, and redacts them out of the output.

```sh
sxd                                   # run the daemon (outside the sandbox)
sx capture .env --ttl 30              # TouchID; load secrets for 30 minutes
sx status                             # see names available (never values)
sx run -s GITHUB_TOKEN -- gh pr create
sx clear                              # revoke
```

See [DESIGN.md](./DESIGN.md) for the threat model, the double-gate model, and
known v1 simplifications.
