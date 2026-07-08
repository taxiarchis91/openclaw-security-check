# OpenClaw Security Check

A read-only hardening audit for self-hosted [OpenClaw](https://docs.openclaw.ai)
installs. Point it at your config and it reports the common, high-impact
misconfigurations that leave a self-hosted AI-agent gateway exposed, with a
concrete fix for each.

It is **strictly read-only**. It inspects files, permissions, config values, and
listening sockets, then prints a report. It never edits anything, never "fixes"
anything, never makes a network call, and **never prints the value of a secret it
finds** — only where that secret lives so you can rotate it. No third-party
dependencies. Python 3.8+.

## Why

A fresh OpenClaw install can expose its control plane, run tools without a
sandbox, accept commands from anyone who can message the bot, and leave secrets
in a world-readable config. `openclaw doctor` catches some of this; this catches a
different, security-focused slice and explains the blast radius of each finding.
Run both.

## What it checks

- Running as **root** (privilege blast radius).
- **File and directory permissions** on the config and secret-bearing files.
- **Plaintext secrets** left in the config artifact.
- **Channel access** — open vs. allowlisted DM policy.
- **Owner-command authorization** — the gate that fails *open* when unset.
- **Gateway / Control UI exposure** — loopback vs. a public bind.
- **Sandbox** posture for tool execution.
- **Git exposure** of a config directory.

Every finding is `FAIL`, `WARN`, `INFO`, or `OK`, sorted worst-first, each with a
one-line fix. Exit code is non-zero if any `FAIL` is present, so it drops into CI
or a pre-exposure check.

## Install and run

No install. Clone or download the single file and run it:

```bash
git clone https://REPLACE-WITH-YOUR-GITHUB-REPO.git
cd openclaw-security-check
python3 audit.py
```

Or point it at a specific config or directory:

```bash
python3 audit.py --config ~/.openclaw/openclaw.json
python3 audit.py --dir    ~/.openclaw
```

It auto-detects `~/.openclaw/openclaw.json` (and honors `OPENCLAW_CONFIG_PATH`) if
you pass nothing.

## Example output

```
================================================================
 OpenClaw Security Check  -  read-only audit  (v1.3)
================================================================
 Config:    /home/you/.openclaw/openclaw.json
----------------------------------------------------------------
 [FAIL] Config directory is world-accessible
          ~/.openclaw is mode 775; other local users can read it.
          fix -> chmod 700 ~/.openclaw  (and re-check after each onboard)
 [WARN] Gateway reachable beyond loopback
          gateway bind is 0.0.0.0; anyone routable can reach the control plane.
          fix -> bind 127.0.0.1 and reach it over an authenticated tunnel
 [WARN] Owner-command list is empty
          owner-only commands are enabled with no owner set (fails open).
          fix -> set commands.ownerAllowFrom before enabling owner commands
----------------------------------------------------------------
 Summary: 1 FAIL  2 WARN  2 INFO  1 OK
================================================================
```

(Illustrative — your findings will reflect your actual install.)

## Understanding and fixing what it finds

This tool tells you **what** is wrong. The
**[Taxiarchis OpenClaw Hardening Playbook](https://REPLACE-WITH-YOUR-GUMROAD-LINK)**
tells you **why it matters and exactly how to fix it** — the reasoning behind each
finding, a hardened reference config you can adapt, an incident-response runbook,
and the footguns that only show up on real hardware (for example, the built-in
repair command that can OOM a small VPS, and the owner gate that fails open when
unset). The auditor is free and always will be; the playbook is the deep version
for people who want to get it right once.

## Scope and honesty

This is a heuristic audit aligned to OpenClaw's documented schema. **Absence of a
finding is not proof of safety.** It complements — and does not replace —
`openclaw doctor`, `openclaw security audit --deep`, and
[the official security docs](https://docs.openclaw.ai). Only ever audit machines
you own and operate.

## License

MIT. See [LICENSE](LICENSE).
