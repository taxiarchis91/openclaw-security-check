#!/usr/bin/env python3
"""
OpenClaw Security Check  -  read-only hardening audit  (v1.3)
=============================================================

Audits a local OpenClaw install for common, high-impact misconfigurations,
aligned to the documented schema at docs.openclaw.ai (config is JSON5 at
~/.openclaw/openclaw.json). It is strictly READ-ONLY: it inspects files,
permissions, config values, and listening sockets and prints a report. It
never edits, sends, or "fixes" anything, and it never prints the value of a
secret it finds (only where it lives).

This COMPLEMENTS, and does not replace, OpenClaw's own tooling. Always also
run `openclaw doctor` and read docs.openclaw.ai/gateway/security.

Usage:
    python3 audit.py                                  # auto-detect config
    python3 audit.py --config ~/.openclaw/openclaw.json
    python3 audit.py --dir   ~/.openclaw

Exit code 0 if no FAIL findings, 1 otherwise. No third-party deps. Py3.8+.
"""

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

FAIL, WARN, INFO, OK = "FAIL", "WARN", "INFO", "OK"
_ORDER = {FAIL: 0, WARN: 1, INFO: 2, OK: 3}
_findings = []

DEFAULT_CONTROL_PORT = 18789  # documented Control UI default (127.0.0.1:18789)


def add(level, title, detail="", fix=""):
    _findings.append({"level": level, "title": title, "detail": detail, "fix": fix})


# ----------------------------------------------------------------------
# locating + parsing config (JSON5)
# ----------------------------------------------------------------------

COMMON_DIRS = ["~/.openclaw", "~/.config/openclaw", "./"]
CONFIG_NAMES = ["openclaw.json"]


def find_config(explicit_config, explicit_dir):
    env_path = os.environ.get("OPENCLAW_CONFIG_PATH")
    if explicit_config:
        p = Path(explicit_config).expanduser()
        return p if p.is_file() else None
    if env_path and Path(env_path).expanduser().is_file():
        return Path(env_path).expanduser()
    dirs = [Path(explicit_dir).expanduser()] if explicit_dir else [Path(d).expanduser() for d in COMMON_DIRS]
    for d in dirs:
        for name in CONFIG_NAMES:
            cand = d / name
            if cand.is_file():
                return cand
    return None


def parse_json5(text):
    """Best-effort JSON5 -> dict. Handles comments, trailing commas, and bare
    identifier keys. Returns dict/list or None. Heuristic, not a full parser."""
    try:
        return json.loads(text)
    except Exception:
        pass
    s = re.sub(r"/\*.*?\*/", "", text, flags=re.S)          # block comments
    s = re.sub(r'(^|[^:"\'])//[^\n]*', r"\1", s)            # line comments (avoid ://)
    s = re.sub(r",(\s*[}\]])", r"\1", s)                    # trailing commas
    s = re.sub(r'([{,]\s*)([A-Za-z_$][\w$]*)(\s*:)', r'\1"\2"\3', s)  # bare keys
    try:
        return json.loads(s)
    except Exception:
        return None


def load_config(path):
    if not path:
        return None
    try:
        return parse_json5(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

def walk_keys(obj, parent=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{parent}.{k}" if parent else str(k)
            if isinstance(v, (dict, list)):
                yield from walk_keys(v, key)
            else:
                yield key, v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{parent}[{i}]"
            if isinstance(v, (dict, list)):
                yield from walk_keys(v, key)
            else:
                yield key, v


def get_path(obj, dotted):
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def is_posix():
    return os.name == "posix"


def looks_like_secret_ref(val):
    """True if value is a reference/placeholder rather than a literal secret."""
    if not isinstance(val, str):
        return True
    v = val.strip()
    if v in ("", "***"):
        return True
    if v.startswith("$") or v.startswith("${"):
        return True
    return bool(re.match(r"^(env|file|exec|secret|ref|keychain|op|vault):", v, re.I))


# ----------------------------------------------------------------------
# checks
# ----------------------------------------------------------------------

def check_running_as_root():
    if not is_posix():
        return
    try:
        if os.geteuid() == 0:
            add(FAIL, "Running as root",
                "This audit is running as root, which suggests the agent may too.",
                "Run OpenClaw as a dedicated unprivileged user. An agent with shell "
                "access running as root can do anything to the host.")
        else:
            add(OK, "Not running as root")
    except AttributeError:
        pass


def check_perms(config_path, base_dir):
    if not is_posix():
        add(INFO, "File-permission checks skipped", "Not a POSIX system.")
        return
    targets = []
    if config_path and config_path.is_file():
        targets.append(config_path)
    for extra in (".env", "secrets.json", "credentials.json",
                  "openclaw.json.bak", "openclaw.json.backup"):
        p = base_dir / extra
        if p.is_file():
            targets.append(p)
    for p in targets:
        mode = p.stat().st_mode
        if mode & (stat.S_IROTH | stat.S_IWOTH):
            add(FAIL, f"World-accessible file: {p.name}",
                f"{p} is readable or writable by any local user (mode "
                f"{oct(stat.S_IMODE(mode))}).",
                f"chmod 600 {p}")
        elif mode & (stat.S_IRGRP | stat.S_IWGRP):
            add(WARN, f"Group-accessible file: {p.name}",
                f"{p} is accessible to its group (mode {oct(stat.S_IMODE(mode))}).",
                f"chmod 600 {p} unless a trusted group truly needs it.")
        else:
            add(OK, f"Permissions look tight: {p.name}")
    if base_dir.is_dir():
        mode = base_dir.stat().st_mode
        if mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH):
            add(WARN, "Install/state directory is world-accessible",
                f"{base_dir} is reachable by other local users.",
                f"chmod 700 {base_dir}")


SECRET_KEY_HINTS = ["token", "apikey", "secret", "password", "passwd", "key"]


def _owner_only(path):
    try:
        m = path.stat().st_mode
        return not (m & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH))
    except Exception:
        return False


def check_plaintext_secrets(cfg, base_dir, config_path=None):
    found = False
    cfg_owner_only = _owner_only(config_path) if config_path else False
    if isinstance(cfg, (dict, list)):
        for key, val in walk_keys(cfg):
            leaf = key.split(".")[-1].lower()
            if any(h in leaf for h in SECRET_KEY_HINTS) and isinstance(val, str):
                if not looks_like_secret_ref(val) and len(val.strip()) >= 8:
                    found = True
                    if cfg_owner_only:
                        add(WARN, "Literal secret in config",
                            f"Config key '{key}' holds a literal credential (value "
                            f"hidden). The file is owner-only (600), which stops other "
                            f"OS users - but the agent and its tools run AS you, so a "
                            f"prompt-injected agent can read its own config and leak it. "
                            f"File perms are not the relevant boundary here.",
                            "Migrate to a SecretRef: `openclaw secrets configure` (or "
                            "`secrets apply`), then verify with `openclaw secrets audit "
                            "--check`. See docs.openclaw.ai/gateway/secrets.")
                    else:
                        add(FAIL, "Plaintext secret in a non-owner-only config",
                            f"Config key '{key}' holds a literal credential (value "
                            f"hidden) in a file readable beyond its owner - exposed to "
                            f"both other OS users and the agent's own tools.",
                            "chmod 600 the file AND migrate to a SecretRef "
                            "(`openclaw secrets configure`). See "
                            "docs.openclaw.ai/gateway/secrets.")
    env = base_dir / ".env"
    if env.is_file():
        try:
            for ln in env.read_text(encoding="utf-8", errors="ignore").splitlines():
                if re.search(r"[A-Za-z0-9_-]{16,}", ln) and "=" in ln and not ln.strip().startswith("#"):
                    found = True
                    add(INFO, "Secrets present in .env",
                        "Fine IF the file is chmod 600 and gitignored.",
                        "Confirm: chmod 600 .env and add it to .gitignore.")
                    break
        except Exception:
            pass
    if not found:
        add(OK, "No obvious plaintext secrets in config",
            "Heuristic only - confirm no literal keys sit in readable files.")


def check_channel_access(cfg):
    channels = get_path(cfg, "channels") if isinstance(cfg, dict) else None
    if not isinstance(channels, dict) or not channels:
        add(INFO, "No channels configured (or none detected)",
            "If you have connected a chat platform, confirm its dmPolicy below.",
            "Per channel set dmPolicy to 'pairing' or 'allowlist', never 'open' "
            "without a tight allowFrom.")
        return
    for name, conf in channels.items():
        if not isinstance(conf, dict):
            continue
        policy = conf.get("dmPolicy")
        allow = conf.get("allowFrom")
        if policy == "open":
            if allow == ["*"] or allow == "*":
                add(FAIL, f"Channel '{name}' is open to everyone",
                    "dmPolicy 'open' with allowFrom ['*'] lets any inbound DM "
                    "command an agent that can run shell on your machine.",
                    "Use dmPolicy 'allowlist' with your own IDs, or 'pairing'.")
            else:
                add(FAIL, f"Channel '{name}' uses dmPolicy 'open'",
                    "Open DM policy accepts unknown senders.",
                    "Switch to 'allowlist' (with allowFrom) or 'pairing'.")
        elif policy == "allowlist":
            if not allow:
                add(WARN, f"Channel '{name}' is allowlist mode but allowFrom is empty",
                    "An empty allowlist may block you or behave unexpectedly.",
                    "Populate allowFrom with your own sender IDs.")
            else:
                add(OK, f"Channel '{name}' restricted via allowlist")
        elif policy == "disabled":
            add(OK, f"Channel '{name}' DMs disabled")
        else:
            # default policy is 'pairing' (reasonably safe) when unset
            add(INFO, f"Channel '{name}' uses default/unspecified dmPolicy",
                "Default is 'pairing' (unknown senders need an approval code).",
                "Set dmPolicy explicitly to 'allowlist' for the tightest control.")


def check_command_owner(cfg):
    """commands.ownerAllowFrom authorizes owner-only commands and exec approvals.
    DM pairing only lets someone TALK to the bot; it does not grant owner rights."""
    if not isinstance(cfg, dict):
        return
    owner = get_path(cfg, "commands.ownerAllowFrom")
    channels = get_path(cfg, "channels")
    has_channel = isinstance(channels, dict) and bool(channels)
    if owner:
        add(OK, "Command owner is configured",
            "Owner-only commands and exec approvals are restricted.")
    elif has_channel:
        add(WARN, "No command owner configured",
            "commands.ownerAllowFrom is empty. Owner-only commands (/config, "
            "/diagnostics, exec approvals) have no designated human operator, and "
            "DM pairing does NOT confer owner rights.",
            "Set it to your own ID, e.g. openclaw config set commands.ownerAllowFrom "
            "'[\"telegram:123456789\"]', then restart the gateway.")
    else:
        add(INFO, "No command owner configured (no channels yet)",
            "Set commands.ownerAllowFrom before connecting any channel.",
            "openclaw config set commands.ownerAllowFrom '[\"telegram:<your-id>\"]'")


def _listening_sockets():
    tool = shutil.which("ss") or shutil.which("netstat")
    if not tool:
        return None
    args = ["ss", "-tlnH"] if "ss" in tool else ["netstat", "-tln"]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    socks = []
    for line in out.splitlines():
        m = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?|\*):(\d+)", line)
        for addr, port in m:
            socks.append((addr.strip("[]"), int(port)))
    return socks


def _is_loopback(addr):
    return addr in ("127.0.0.1", "::1") or addr.startswith("127.")


def check_gateway_exposure(cfg):
    # configured port, if any
    port = None
    gw = get_path(cfg, "gateway") if isinstance(cfg, dict) else None
    if isinstance(gw, dict):
        for k in ("port", "controlPort", "httpPort"):
            if isinstance(gw.get(k), int):
                port = gw[k]
                break
    ports = {p for p in (port, DEFAULT_CONTROL_PORT) if p}

    socks = _listening_sockets()
    if socks is None:
        add(INFO, "Could not enumerate listening sockets",
            "Neither ss nor netstat is available.",
            "Manually confirm the gateway/Control UI listens on 127.0.0.1 only.")
    else:
        exposed = [(a, p) for (a, p) in socks if p in ports and not _is_loopback(a)
                   and a not in ("",)]
        # also catch 0.0.0.0 / :: explicitly
        exposed += [(a, p) for (a, p) in socks if p in ports and a in ("0.0.0.0", "::", "*")]
        exposed = sorted(set(exposed))
        if exposed:
            add(FAIL, "Gateway/Control UI is listening on a non-loopback address",
                "Found public bind(s): " + ", ".join(f"{a}:{p}" for a, p in exposed) +
                ". The Control UI is an admin surface (chat, config, exec approvals).",
                "Bind to 127.0.0.1. For remote access use Tailscale Serve or an SSH "
                "tunnel - never a raw open port. See "
                "docs.openclaw.ai/gateway/security/exposure-runbook.")
        else:
            add(OK, "Gateway port(s) not observed on a public interface",
                f"Checked ports: {sorted(ports)} (heuristic).")

    # auth presence
    has_auth = bool(get_path(cfg, "gateway.auth.token") or
                    get_path(cfg, "gateway.auth.password") or
                    os.environ.get("OPENCLAW_GATEWAY_TOKEN"))
    if has_auth:
        tok = get_path(cfg, "gateway.auth.token")
        if isinstance(tok, str) and not looks_like_secret_ref(tok) and len(tok) < 24:
            add(WARN, "Gateway auth token looks short/weak",
                "A short literal token is easy to brute force (value hidden).",
                "Use a long random token (>=32 chars), ideally via a SecretRef.")
        else:
            add(OK, "Gateway auth appears configured")
    else:
        add(WARN, "No gateway auth token detected",
            "Docs recommend keeping Token auth even on loopback so local WS "
            "clients must authenticate.",
            "Set gateway.auth.token (or OPENCLAW_GATEWAY_TOKEN). Mandatory if you "
            "ever bind to a non-loopback address.")


def check_sandbox(cfg):
    mode = get_path(cfg, "agents.defaults.sandbox.mode") if isinstance(cfg, dict) else None
    if mode in ("non-main", "all"):
        add(OK, f"Sandboxing enabled (mode '{mode}')")
    else:
        add(WARN, "Agent sandboxing is off or unset",
            "Without sandboxing, a prompt-injected agent runs tools directly on "
            "the host.",
            "Set agents.defaults.sandbox.mode to 'non-main' or 'all'. See "
            "docs.openclaw.ai/gateway/sandboxing.")


def check_git_exposure(base_dir):
    if (base_dir / ".git").is_dir():
        gi = base_dir / ".gitignore"
        ignored = gi.read_text(errors="ignore") if gi.is_file() else ""
        risky = [n for n in (".env", "openclaw.json", "secrets.json", "credentials.json")
                 if (base_dir / n).is_file() and n not in ignored]
        if risky:
            add(FAIL, "Secrets may be tracked in git",
                f"Git repo with non-ignored sensitive files: {', '.join(risky)}.",
                "Add them to .gitignore and purge from history if already committed.")
        else:
            add(OK, "Git repo present; sensitive files appear gitignored")


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Read-only OpenClaw security audit.")
    ap.add_argument("--config", help="Path to the OpenClaw config file (openclaw.json).")
    ap.add_argument("--dir", help="Path to the OpenClaw install/state directory.")
    args = ap.parse_args()

    cfg_path = find_config(args.config, args.dir)
    base_dir = (Path(args.dir).expanduser() if args.dir
                else (cfg_path.parent if cfg_path else Path.home() / ".openclaw"))

    print("=" * 66)
    print(" OpenClaw Security Check  -  read-only audit  (v1.3)")
    print("=" * 66)
    print(f" Config:    {cfg_path if cfg_path else 'NOT FOUND (use --config/--dir)'}")
    print(f" Directory: {base_dir}")
    print("-" * 66)

    cfg = load_config(cfg_path)
    if cfg_path and cfg is None:
        add(WARN, "Config found but could not be parsed",
            f"{cfg_path} did not parse as JSON5 with the built-in heuristic parser.",
            "Some checks are limited. Try: openclaw config get  (or openclaw doctor).")

    check_running_as_root()
    check_perms(cfg_path, base_dir)
    check_plaintext_secrets(cfg, base_dir, cfg_path)
    check_channel_access(cfg)
    check_command_owner(cfg)
    check_gateway_exposure(cfg)
    check_sandbox(cfg)
    check_git_exposure(base_dir)

    _findings.sort(key=lambda f: _ORDER[f["level"]])
    counts = {FAIL: 0, WARN: 0, INFO: 0, OK: 0}
    for f in _findings:
        counts[f["level"]] += 1
        print(f" [{f['level']:<4}] {f['title']}")
        if f["detail"]:
            print(f"          {f['detail']}")
        if f["fix"]:
            print(f"          fix -> {f['fix']}")
    print("-" * 66)
    print(f" Summary: {counts[FAIL]} FAIL  {counts[WARN]} WARN  "
          f"{counts[INFO]} INFO  {counts[OK]} OK")
    print("=" * 66)
    print(" Heuristic, read-only audit. ALSO run `openclaw doctor`, `openclaw security audit --deep`, and read")
    print(" docs.openclaw.ai/gateway/security. Absence of a finding is not proof")
    print(" of safety. Audit only machines you own and operate.")
    print("-" * 66)
    print(" This check finds problems. The Taxiarchis OpenClaw Hardening Playbook")
    print(" explains and fixes every finding type above, with a hardened reference")
    print(" config and an incident runbook:")
    print("   https://REPLACE-WITH-YOUR-GUMROAD-LINK")
    print("=" * 66)
    sys.exit(1 if counts[FAIL] else 0)


if __name__ == "__main__":
    main()
