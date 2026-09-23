#!/usr/bin/env python3
"""Enumerating and filtering what is in the keychain.

Invoked by `secret list` and `secret adopt`. Not a public interface — the
behavior it implements is specified in tests/adopt.bats and tests/filter.bats.

Nothing here ever asks the keychain for a password. `dump-keychain` without
`-d` returns attributes only, which is why listing needs no access prompt and
cannot leak a value.
"""

import argparse
import os
import re
import subprocess
import sys

OURS = "secret-cli credential"
ATTR = re.compile(r'"(acct|svce|desc)"<blob>=(?:"((?:[^"\\]|\\.)*)"|<NULL>)')


def keychain_args():
    kc = os.environ.get("SECRET_CLI_KEYCHAIN")
    return [kc] if kc else []


def dump_items():
    """Every generic password in the keychain, as (service, account, desc)."""
    try:
        out = subprocess.run(
            ["security", "dump-keychain", *keychain_args()],
            capture_output=True, text=True, check=False,
        ).stdout
    except OSError:
        return []

    items, current, in_genp = [], {}, False
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("class:"):
            if in_genp and current.get("svce"):
                items.append((current.get("svce", ""), current.get("acct", ""),
                              current.get("desc", "")))
            current, in_genp = {}, '"genp"' in stripped
            continue
        match = ATTR.search(line)
        if match:
            current[match.group(1)] = (match.group(2) or "").encode().decode("unicode_escape")
    if in_genp and current.get("svce"):
        items.append((current.get("svce", ""), current.get("acct", ""),
                      current.get("desc", "")))
    return items


def read_index(home):
    try:
        with open(os.path.join(home, "keys")) as fh:
            return [l.strip() for l in fh if l.strip()]
    except OSError:
        return []


def read_adopted(home):
    out = {}
    try:
        with open(os.path.join(home, "adopted")) as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 3:
                    out[parts[0]] = (parts[1], parts[2])
    except OSError:
        pass
    return out


# --- matching ---------------------------------------------------------------

def is_subsequence(needle, haystack):
    it = iter(haystack)
    return all(char in it for char in needle)


def rank(query, name):
    """0 substring, 1 initials, 2 subsequence, None for no match."""
    if not query:
        return 0
    q, n = query.lower(), name.lower()
    if q in n:
        return 0
    initials = "".join(p[0] for p in re.split(r"[_\-. ]+", name) if p).lower()
    if initials.startswith(q):
        return 1
    if is_subsequence(q, n):
        return 2
    return None


# --- commands ---------------------------------------------------------------

def default_home():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "secret-cli")


def cmd_list(args):
    home = os.environ.get("SECRET_CLI_HOME") or default_home()
    prefix = os.environ.get("SECRET_CLI_SERVICE_PREFIX", "secret-cli.")
    managed = read_index(home)
    adopted = read_adopted(home)

    if not args.all:
        rows = []
        for key in sorted(set(managed) | set(adopted)):
            score = rank(args.filter, key)
            if score is not None:
                rows.append((score, key, key))
        for _, _, key in sorted(rows):
            print(key)
        return 0

    # Grouped so your own keys come first, then what you have adopted, then
    # everything else in the keychain — which is usually hundreds of rows.
    claimed = set(adopted.values())
    rows = []
    for key in sorted(managed):
        score = rank(args.filter, key)
        if score is not None:
            rows.append((0, score, key, ("managed", key, prefix + key)))
    for key in sorted(adopted):
        service, account = adopted[key]
        score = rank(args.filter, key)
        if score is None:
            score = rank(args.filter, service)
        if score is not None:
            rows.append((1, score, key, ("adopted", key, f"{service} ({account})")))
    for service, account, desc in sorted(dump_items()):
        if desc == OURS or service.startswith(prefix) or (service, account) in claimed:
            continue
        score = rank(args.filter, service)
        if score is not None:
            rows.append((2, score, service, ("unmanaged", service, account)))

    for *_, row in sorted(rows):
        print("\t".join(row))
    return 0


def cmd_accounts(args):
    for service, account, _ in sorted(dump_items()):
        if service == args.service:
            print(account)
    return 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list")
    p_list.add_argument("--all", action="store_true")
    p_list.add_argument("--filter", default="")
    p_list.set_defaults(func=cmd_list)

    p_acct = sub.add_parser("accounts")
    p_acct.add_argument("service")
    p_acct.set_defaults(func=cmd_accounts)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
