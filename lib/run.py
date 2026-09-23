#!/usr/bin/env python3
"""Run a child process with secrets in its environment and scrub them back out
of everything it prints.

Invoked by `secret run`. Not a public interface — the behavior it implements
is specified in tests/run.bats.

Two layers of scrubbing:
  * the exact values this invocation injected, plus the encodings a program is
    most likely to print them in (base64 for Basic auth, percent-encoding for
    query strings);
  * a small set of credential shapes, so a token that was never stored here
    still does not sail past into a transcript.
"""

import base64
import os
import re
import select
import subprocess
import sys
import urllib.parse

MIN_SCRUB_LEN = 6
OPEN, CLOSE = "‹".encode(), "›".encode()

SHAPE_PATTERNS = [
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), b"private-key"),
    (re.compile(rb"sk-ant-[A-Za-z0-9_-]{16,}"), b"anthropic-api-key"),
    (re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"), b"github-token"),
    (re.compile(rb"gh[pousr]_[A-Za-z0-9]{16,}"), b"github-token"),
    (re.compile(rb"glpat-[A-Za-z0-9_-]{16,}"), b"gitlab-token"),
    (re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"), b"slack-token"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), b"aws-access-key-id"),
    (re.compile(rb"ASIA[0-9A-Z]{16}"), b"aws-session-key-id"),
    (re.compile(rb"AIza[0-9A-Za-z_-]{35}"), b"google-api-key"),
    (re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), b"jwt"),
    (re.compile(rb"sk-[A-Za-z0-9]{32,}"), b"openai-api-key"),
]


def token(label: bytes) -> bytes:
    return OPEN + b"redacted:" + label + CLOSE


def literals_for(keys):
    """Every byte string that would give a value away, longest first."""
    out = []
    for key in keys:
        value = os.environ.get(key, "")
        if len(value) < MIN_SCRUB_LEN:
            continue
        raw = value.encode("utf-8", "surrogateescape")
        forms = {raw, base64.b64encode(raw)}
        quoted = urllib.parse.quote(value, safe="").encode()
        if quoted != raw:
            forms.add(quoted)
        for form in forms:
            if len(form) >= MIN_SCRUB_LEN:
                out.append((form, token(key.encode())))
    out.sort(key=lambda pair: len(pair[0]), reverse=True)
    return out


def scrub(chunk: bytes, literals) -> bytes:
    for needle, replacement in literals:
        chunk = chunk.replace(needle, replacement)
    for pattern, label in SHAPE_PATTERNS:
        chunk = pattern.sub(token(label), chunk)
    return chunk


class Stream:
    """Buffers a pipe up to a newline so a value split across two reads is
    still caught, and flushes whatever is left when the pipe closes."""

    FLUSH_AT = 1 << 20

    def __init__(self, src, dst, literals):
        self.src, self.dst, self.literals = src, dst, literals
        self.buf = b""
        self.open = True

    def fileno(self):
        return self.src.fileno()

    def pump(self):
        data = os.read(self.fileno(), 65536)
        if not data:
            self.open = False
            self.flush(all_of_it=True)
            return
        self.buf += data
        if b"\n" in self.buf:
            head, _, self.buf = self.buf.rpartition(b"\n")
            self.write(head + b"\n")
        elif len(self.buf) > self.FLUSH_AT:
            self.flush(all_of_it=True)

    def flush(self, all_of_it=False):
        if self.buf and all_of_it:
            self.write(self.buf)
            self.buf = b""

    def write(self, data):
        self.dst.write(scrub(data, self.literals))
        self.dst.flush()


def main(argv):
    keys = [k for k in os.environ.get("SECRET_CLI_KEYS", "").split(",") if k]
    if not argv:
        print("secret: nothing to run", file=sys.stderr)
        return 2

    literals = literals_for(keys)
    env = dict(os.environ)
    env.pop("SECRET_CLI_KEYS", None)

    try:
        child = subprocess.Popen(
            argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except FileNotFoundError:
        print(f"secret: command not found: {argv[0]}", file=sys.stderr)
        return 127
    except PermissionError:
        print(f"secret: not executable: {argv[0]}", file=sys.stderr)
        return 126

    streams = [
        Stream(child.stdout, sys.stdout.buffer, literals),
        Stream(child.stderr, sys.stderr.buffer, literals),
    ]
    while any(s.open for s in streams):
        ready, _, _ = select.select([s for s in streams if s.open], [], [])
        for s in ready:
            s.pump()

    return child.wait()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
