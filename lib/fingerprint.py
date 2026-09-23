#!/usr/bin/env python3
"""Fingerprint a value read from stdin.

Invoked by `secret fingerprint`, `verify` and `diff`. Not a public interface —
the behavior is specified in tests/fingerprint.bats.

Salted with a per-machine key by default. An unsalted hash of a low-entropy
secret is not safe to paste anywhere: the value can simply be guessed and the
hash checked. Salting means a fingerprint is only comparable against another
fingerprint from the same machine, which is the common case. --global drops the
salt for when two machines have to agree, and the caller warns about it.
"""

import argparse
import hashlib
import hmac
import os
import sys

LENGTH = 12


def machine_salt(path):
    try:
        with open(path, "rb") as fh:
            salt = fh.read().strip()
            if salt:
                return salt
    except OSError:
        pass
    salt = os.urandom(32).hex().encode()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(salt)
    return salt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--salt-file")
    parser.add_argument("--global", dest="glob", action="store_true")
    parser.add_argument("--length", type=int, default=LENGTH)
    args = parser.parse_args()

    value = sys.stdin.buffer.read()

    if args.glob:
        digest = hashlib.sha256(value).hexdigest()
        label = "sha256"
    else:
        digest = hmac.new(machine_salt(args.salt_file), value, hashlib.sha256).hexdigest()
        label = "local"

    print(f"{label}:{digest[:args.length]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
