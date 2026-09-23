#!/usr/bin/env python3
"""The PreToolUse guard.

Reads one hook payload on stdin, writes a decision on stdout. It exists to stop
an agent fetching a credential out of band — straight out of the keychain, or
straight off disk — because anything it reads that way lands in its transcript.

What it deliberately does not do: block destructive commands, detect personal
data, or look for prompt injection. Those are a different tool's job, and
bolting them on here would make the guard noisy enough to get switched off.

The spec is tests/fixtures/*.jsonl. Limits are in the readme under Known gaps.
"""

import datetime
import json
import os
import re
import sys

MODES = ("enforce", "warn", "off")

HOME = os.environ.get("SECRET_CLI_HOME") or os.path.join(
    os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "secret-cli"
)

# Paths that are safe despite sitting next to something sensitive. Checked
# first, so a rule below can be broad without catching these.
ALLOWED_PATHS = [
    re.compile(r"\.env\.(example|sample|template|dist)$", re.I),
    re.compile(r"/\.ssh/([^/]+\.pub|config|known_hosts[^/]*|authorized_keys)$"),
    re.compile(r"^\.ssh/([^/]+\.pub|config|known_hosts[^/]*|authorized_keys)$"),
]

# (rule id, pattern, what to tell the agent instead)
BLOCKED_PATHS = [
    ("path.keychain", re.compile(r"/Library/Keychains/"), "the keychain itself"),
    ("path.dotenv", re.compile(r"(^|/)\.env($|[^A-Za-z0-9_])"), "a dotenv file"),
    ("path.ssh-private", re.compile(r"(^|/)\.ssh(/|$)"), "the ssh directory"),
    ("path.aws", re.compile(r"(^|/)\.aws(/|$)"), "aws credentials"),
    ("path.kube", re.compile(r"(^|/)\.kube(/|$)"), "a kubeconfig"),
    ("path.docker", re.compile(r"(^|/)\.docker/config\.json$"), "docker credentials"),
    ("path.netrc", re.compile(r"(^|/)\.netrc$"), "a netrc file"),
    ("path.npmrc", re.compile(r"(^|/)\.npmrc$"), "an npmrc"),
    ("path.pypirc", re.compile(r"(^|/)\.pypirc$"), "a pypirc"),
    ("path.git-credentials", re.compile(r"(^|/)\.git-credentials$"), "git credentials"),
    ("path.private-key", re.compile(r"\.(pem|key|p12|pfx|jks|keystore)$", re.I), "a key file"),
    ("path.ssh-keyfile", re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"), "a private key"),
    ("path.secrets-dir", re.compile(r"(^|/)secrets(/|$)"), "a secrets directory"),
    ("path.credentials-json", re.compile(r"(^|/)credentials[^/]*\.json$", re.I), "a credentials file"),
    ("path.serviceaccount", re.compile(r"(^|/)serviceaccount[^/]*\.json$", re.I), "a service account key"),
]

# Reading the keychain through the one CLI that can do it.
KEYCHAIN_READ = re.compile(
    r"(^|[\s;&|(`$])(/\S*/)?security\s+((-\S+|\S+=\S+)\s+)*"
    r"(find-generic-password|find-internet-password|dump-keychain|export)\b"
)

# Commands that put the contents of a file somewhere the agent can see it, or
# somewhere else entirely.
READERS = (
    r"cat|bat|head|tail|less|more|strings|xxd|od|hexdump|base64|openssl|"
    r"cp|mv|scp|rsync|tar|zip|gzip|dd|install|"
    r"python3?|node|ruby|perl|php|awk|sed|grep|rg|ack|jq|yq|"
    r"nc|ncat|curl|wget|tee|sort|uniq|wc|diff|cmp|md5|shasum|split"
)
READER_RE = re.compile(r"(^|[\s;&|(`$])(/\S*/)?(" + READERS + r")(\s|$)")

# Path-shaped things worth objecting to when a reader is in the same command.
BLOCKED_IN_COMMAND = [
    ("path.keychain", re.compile(r"Library/Keychains/"), "the keychain itself"),
    ("path.dotenv", re.compile(r"\.env(?!\.(example|sample|template|dist))(?![A-Za-z0-9_])")," a dotenv file"),
    ("path.ssh-keyfile", re.compile(r"id_(rsa|dsa|ecdsa|ed25519)(?!\.pub)(?![A-Za-z0-9_])"), "a private key"),
    ("path.aws", re.compile(r"\.aws/credentials"), "aws credentials"),
    ("path.kube", re.compile(r"\.kube/config"), "a kubeconfig"),
    ("path.docker", re.compile(r"\.docker/config\.json"), "docker credentials"),
    ("path.netrc", re.compile(r"\.netrc(?![A-Za-z0-9_])"), "a netrc file"),
    ("path.npmrc", re.compile(r"\.npmrc(?![A-Za-z0-9_])"), "an npmrc"),
    ("path.pypirc", re.compile(r"\.pypirc(?![A-Za-z0-9_])"), "a pypirc"),
    ("path.git-credentials", re.compile(r"\.git-credentials(?![A-Za-z0-9_])"), "git credentials"),
    ("path.private-key", re.compile(r"\.(pem|p12|pfx|jks|keystore)(?![A-Za-z0-9_])", re.I), "a key file"),
    ("path.key-suffix", re.compile(r"[\w./-]+\.key(?![A-Za-z0-9_])"), "a key file"),
    ("path.secrets-dir", re.compile(r"(^|[\s'\"/])secrets/"), "a secrets directory"),
]

ADVICE = (
    "Reading {what} would put the credential into this transcript, where it is "
    "sent upstream on every later turn and written to the session log on disk. "
    "Use 'secret run <KEY> -- <command>' so the value goes to the process and "
    "not to you, or ask the person you are working with to read it."
)


def mode():
    m = os.environ.get("SECRET_CLI_GUARD_MODE")
    if not m:
        try:
            with open(os.path.join(HOME, "guard-mode")) as fh:
                m = fh.read().strip()
        except OSError:
            m = "enforce"
    return m if m in MODES else "enforce"


def path_verdict(path):
    if not path:
        return None
    for allowed in ALLOWED_PATHS:
        if allowed.search(path):
            return None
    for rule, pattern, what in BLOCKED_PATHS:
        if pattern.search(path):
            return rule, what
    return None


def command_verdict(command):
    if not command:
        return None
    if KEYCHAIN_READ.search(command):
        return "cmd.keychain-read", "the keychain itself"
    if READER_RE.search(command):
        for rule, pattern, what in BLOCKED_IN_COMMAND:
            if pattern.search(command):
                return rule, what.strip()
    return None


def verdict(payload):
    tool = payload.get("tool_name") or ""
    args = payload.get("tool_input") or {}
    if not isinstance(args, dict):
        return None
    if tool == "Bash":
        return command_verdict(args.get("command"))
    if tool in ("Read", "Edit", "Write", "NotebookEdit"):
        return path_verdict(args.get("file_path") or args.get("notebook_path"))
    if tool in ("Grep", "Glob"):
        return path_verdict(args.get("path"))
    return None


def audit(decision, tool, rule, detail):
    try:
        os.makedirs(HOME, exist_ok=True)
        with open(os.path.join(HOME, "audit.jsonl"), "a") as fh:
            fh.write(json.dumps({
                "at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                "decision": decision,
                "tool": tool,
                "rule": rule,
                "detail": detail,
            }) + "\n")
    except OSError:
        pass


def main():
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            payload = {}
    except (ValueError, OSError):
        return 0  # never wedge a session over a payload we cannot parse

    current = mode()
    if current == "off":
        return 0

    found = verdict(payload)
    if not found:
        return 0

    rule, what = found
    tool = payload.get("tool_name") or "?"

    if current == "warn":
        audit("warn", tool, rule, what)
        print(f"secret-guard: would block {tool} — {what} ({rule})", file=sys.stderr)
        return 0

    audit("deny", tool, rule, what)
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": ADVICE.format(what=what) + f" [{rule}]",
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
