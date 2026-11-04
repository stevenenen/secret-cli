#!/usr/bin/env python3
"""The credential guard: one entry point for two hook events.

PreToolUse: reads one hook payload on stdin, writes a decision on stdout. It
exists to stop an agent fetching a credential out of band — straight out of the
keychain, off disk, or out of an environment — because anything it reads that
way lands in its transcript.

PostToolUse: scans what a tool returned for credential shapes, so a leak the
first half missed is redacted from what the agent sees and reported at once.

What it deliberately does not do: block destructive commands, detect personal
data, or look for prompt injection. Those are a different tool's job, and
bolting them on here would make the guard noisy enough to get switched off.

The spec is tests/fixtures/*.jsonl. Limits are in the readme under Known gaps.
"""

import datetime
import json
import os
import re
import shlex
import sys

from run import SHAPE_PATTERNS, token

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
    ("path.cookie-jar", re.compile(r"(^|/)[^/]*cookie(s|jar|-jar)?(\.(txt|json|jar|sqlite|db|lwp))?$", re.I), "a cookie jar"),
    ("path.proc-environ", re.compile(r"^/proc/[^/]+/environ$"), "a process environment"),
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
    ("path.cookie-jar", re.compile(r"cookie(s|jar|-jar)?\.(txt|json|jar|sqlite|db|lwp)(?![A-Za-z0-9_])", re.I), "a cookie jar"),
]

# Printing the cookies of the agent's own browser: session tokens, every one.
BROWSER_COOKIES = re.compile(r"(^|[\s;&|(`$])agent-browser\b[^;&|]*\scookies(\s+get\b|\s*($|[;&|]))")

ADVICE = (
    "Reading {what} would put the credential into this transcript, where it is "
    "sent upstream on every later turn and written to the session log on disk. "
    "Use 'secret run <KEY> -- <command>' so the value goes to the process and "
    "not to you, or ask the person you are working with to read it."
)

# --- environments -----------------------------------------------------------
#
# A shell's environment, a container's, a process's: each holds live tokens,
# and each has a one-word way to print all of them. These rules read the
# command as the shell would split it — pipelines of simple commands, with
# $( ) cut out separately — because whether a dump is dangerous depends on
# where its output goes.

RULE_ADVICE = {
    "cmd.container-env": (
        "Inspecting a container's environment prints every credential it was "
        "started with into this transcript. Ask for fields that leave it out "
        "({{.State.Status}}, {{.Config.Image}}), or read one named non-secret "
        "variable with an anchored sed: docker inspect <c> --format "
        "'{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^NAME=//p'."
    ),
    "cmd.container-exec-env": (
        "Dumping a container's environment prints every credential it holds "
        "into this transcript. Read one named non-secret variable instead: "
        "docker exec <c> printenv NAME."
    ),
    "cmd.compose-config": (
        "docker compose config fills every variable in from the dotenv file and "
        "the shell, secrets included. Use --no-interpolate to see the file as "
        "written, or --services to list the services."
    ),
    "cmd.proc-environ": (
        "/proc/<pid>/environ is a process's whole environment, live tokens "
        "included. Read one named non-secret variable instead."
    ),
    "cmd.ps-env": (
        "ps with e or -E prints each process's environment next to it, live "
        "tokens included. Drop the e: ps aux, ps -ef."
    ),
    "cmd.shell-env-dump": (
        "This shell's environment holds live tokens; dumping it, or printing a "
        "variable whose name looks secret, puts them into this transcript. Read "
        "one named non-secret variable (printenv HOME, or env | sed -n "
        "'s/^NAME=//p'), test whether a secret is set with ${NAME:+set}, and "
        "use 'secret run <KEY> -- <command>' to hand one to a process."
    ),
    "cmd.too-deep": (
        "This is a command nested too deeply to check: substitutions or shells "
        "inside one another past the guard's limit. It is denied rather than "
        "waved through. Split it into separate steps."
    ),
    "cmd.shell-stdin": (
        "This feeds a script to a shell on stdin, so the guard cannot see what "
        "runs. Save the script to a file and read it first, or run the commands "
        "directly."
    ),
    "cmd.token-print": (
        "This command prints a credential outright, into this transcript. "
        "Capture it where it is used instead: GH_TOKEN=$(gh auth token) "
        "<command>, or pipe it into a reader such as docker login "
        "--password-stdin."
    ),
}

NAME = r"[A-Za-z_][A-Za-z0-9_]*"
ASSIGN = re.compile(NAME + r"=.*", re.S)
SECRET_NAME = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|CREDENTIAL|AUTH|SESSION", re.I
)
PROC_ENVIRON = re.compile(r"/proc/[^/\s'\"]+/environ")
SUB = re.compile(r"__SUB(\d+)__")
BODY = re.compile(r"__BODY(\d+)__")
HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([^\s'\";&|<>()]+)\2")
REDIRECT = re.compile(r"\d*(>>?|<<?<?|&>>?|>&|<&)(\S*)")
SHELLS = ("sh", "bash", "zsh", "dash", "ksh")
KEYWORDS = {"do", "then", "else", "elif", "if", "while", "until", "!", "{", "(",
            "builtin", "nohup", "noglob"}
MAX_DEPTH = 8
TOO_DEEP = ("cmd.too-deep", "a command nested too deeply to check")
# Commands that print what they are given: a token handed to one as an
# argument ends up in the transcript after all.
PRINTERS = {"echo", "printf", "print", "cat", "tee", "jq", "yq", "xargs", "eval",
            "awk", "sed", "grep", "base64", "xxd", "od", "logger", "printenv",
            "python", "python3", "node", "ruby", "perl"} | set(SHELLS)
VERBOSE = {"-v", "--verbose", "--trace", "--trace-ascii", "-x", "--debug"}
NAME_FILTERS = {"grep", "sort", "uniq", "head", "tail", "wc", "cat", "column",
                "tr", "cut", "less", "more"}


def looks_secret(name):
    return bool(SECRET_NAME.search(name))


def _close_paren(cmd, i):
    """Index just past the ')' matching the '(' at cmd[i]."""
    depth, q, n = 0, None, len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\" and q != "'":
            i += 2
            continue
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _arith_close(cmd, i):
    """For '$((' at cmd[i], the index past its '))', or None when the parens
    close some other way and it is a command substitution of a subshell."""
    j = _close_paren(cmd, i + 1)
    k = _close_paren(cmd, i + 2)
    return j if k == j - 1 and cmd[j - 2:j] == "))" else None


def find_subs(text):
    """The command substitutions inside text that is not itself a command
    line: an arithmetic expression, an unquoted heredoc body."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if text.startswith("$((", i):
            j = _arith_close(text, i)
            if j:
                out += find_subs(text[i + 3:j - 2])
                i = j
                continue
        if text.startswith("$(", i):
            j = _close_paren(text, i + 1)
            out.append(text[i + 2:j - 1])
            i = j
            continue
        if c == "`":
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            out.append(text[i + 1:j])
            i = j + 1
            continue
        i += 1
    return out


def scan(cmd):
    """Split a command line into pipelines of simple commands.

    Command and process substitutions are cut out and replaced by __SUBn__,
    so a simple command's text shows where each one lands; subs[n] is the
    inner text. A heredoc body becomes __BODYn__ on the command it feeds, with
    subs[n] the body."""
    pipelines, cur, subs, heredocs = [[]], [], [], []
    q, i, n = None, 0, len(cmd)

    def end_command():
        pipelines[-1].append("".join(cur))
        cur.clear()

    def end_pipeline():
        end_command()
        pipelines.append([])

    while i < n:
        c = cmd[i]
        if q == "'":
            cur.append(c)
            q = None if c == "'" else q
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            cur.append(cmd[i:i + 2])
            i += 2
            continue
        if c == '"':
            q = None if q == '"' else '"'
            cur.append(c)
            i += 1
            continue
        if c == "'" and q is None:
            q = "'"
            cur.append(c)
            i += 1
            continue
        if cmd.startswith("$((", i) and _arith_close(cmd, i):
            j = _arith_close(cmd, i)
            for inner in find_subs(cmd[i + 3:j - 2]):
                subs.append(inner)
                cur.append(f" __SUB{len(subs) - 1}__ ")
            i = j
            continue
        if (c == "$" or (c in "<>" and q is None)) and cmd.startswith("(", i + 1):
            j = _close_paren(cmd, i + 1)
            subs.append(cmd[i + 2:j - 1])
            cur.append(f"__SUB{len(subs) - 1}__")
            i = j
            continue
        if c == "`":
            j = cmd.find("`", i + 1)
            j = n if j < 0 else j
            subs.append(cmd[i + 1:j])
            cur.append(f"__SUB{len(subs) - 1}__")
            i = j + 1
            continue
        if q is None and cmd.startswith("<<", i) and not cmd.startswith("<<<", i):
            m = HEREDOC.match(cmd, i)
            if m:
                owner = (len(pipelines) - 1, len(pipelines[-1]))  # where cur will land
                heredocs.append((m.group(3), bool(m.group(1)), bool(m.group(2)), owner))
                cur.append(m.group(0))
                i = m.end()
                continue
        if q is None and c == "\n" and heredocs:
            end_pipeline()
            i += 1
            for delim, dash, quoted, (pi, ci) in heredocs:
                markers = []
                lines = []
                while i < n:
                    end = cmd.find("\n", i)
                    end = n if end < 0 else end
                    line = cmd[i:end]
                    i = end + 1
                    if (line.lstrip("\t") if dash else line) == delim:
                        break
                    lines.append(line)
                body = "\n".join(lines)
                # The body is data, not commands; but an unquoted one is
                # expanded, and what it expands into reaches the command.
                for inner in ([] if quoted else find_subs(body)):
                    subs.append(inner)
                    markers.append(f" __SUB{len(subs) - 1}__")
                subs.append(body)
                markers.append(f" __BODY{len(subs) - 1}__")
                pipelines[pi][ci] += "".join(markers)
            heredocs.clear()
            continue
        if q is None:
            if cmd.startswith("&&", i) or cmd.startswith("||", i):
                end_pipeline()
                i += 2
                continue
            if c == "|":
                end_command()
                i += 2 if cmd.startswith("|&", i) else 1
                continue
            if c in ";\n" or (c == "&" and not cmd.startswith("&>", i)
                              and not (i and cmd[i - 1] in "<>")):
                end_pipeline()
                i += 1
                continue
        cur.append(c)
        i += 1
    end_command()
    return [[t for t in p if t.strip()] for p in pipelines if any(t.strip() for t in p)], subs


def words(text):
    """A simple command's words, quotes removed, redirections dropped."""
    try:
        w = shlex.split(text)
    except ValueError:
        w = text.split()
    out, skip = [], False
    for x in w:
        if skip:
            skip = False
            continue
        m = REDIRECT.fullmatch(x)
        if m or BODY.fullmatch(x):
            skip = bool(m) and not m.group(2)
            continue
        out.append(x)
    while len(out) == 1 and out[0][:1] == "(" and out[0][-1:] == ")":
        out[0] = out[0][1:-1]
    if out:  # a subshell's parentheses stick to its first and last words
        while out[0].startswith("(") and out[0].count("(") > out[0].count(")"):
            out[0] = out[0][1:]
        while out[-1].endswith(")") and out[-1].count(")") > out[-1].count("("):
            out[-1] = out[-1][:-1]
    return [x for x in out if x]


def stdin_scripts(text, subs):
    """What a simple command reads on stdin, when the command line holds it:
    here-strings and heredoc bodies."""
    try:
        w = shlex.split(text)
    except ValueError:
        w = text.split()
    out = []
    for j, x in enumerate(w):
        m = re.fullmatch(r"\d*<<<(.*)", x, re.S)
        if m:
            out.append(m.group(1) or (w[j + 1] if j + 1 < len(w) else ""))
    out += [subs[int(m.group(1))] for m in BODY.finditer(text) if int(m.group(1)) < len(subs)]
    return out


def _skip_opts(w, i, valued):
    while i < len(w) and w[i].startswith("-") and w[i] != "--":
        i += 2 if w[i] in valued else 1
    if i < len(w) and w[i] == "--":
        i += 1
    return i


def base(word):
    """A command word as the guard compares it: /usr/bin/env and \\env are env."""
    return os.path.basename(word.lstrip("\\")) or word


def _env_command(w, i):
    """Past env's options and assignments: where the command it runs starts."""
    while i < len(w):
        if w[i] in ("-u", "--unset", "-C", "--chdir"):
            i += 2
        elif w[i].startswith("-") or ASSIGN.fullmatch(w[i]):
            i += 1
        else:
            break
    return i


def command_index(w):
    """Where the command word sits, past assignments, keywords and wrappers."""
    i = 0
    while i < len(w):
        x = base(w[i])
        if x in KEYWORDS or ASSIGN.fullmatch(w[i]):
            i += 1
        elif x == "command":
            j = _skip_opts(w, i + 1, set())
            if any(set(a[1:]) & {"v", "V"} for a in w[i + 1:j] if a != "--"):
                return len(w)  # a lookup; it runs nothing
            i = j
        elif x == "exec":
            i = _skip_opts(w, i + 1, {"-a"})
        elif x == "time":
            i = _skip_opts(w, i + 1, set())
        elif x == "env":
            j = _env_command(w, i + 1)
            if j >= len(w):
                break  # a bare env: the command is env itself
            i = j
        elif x == "sudo":
            i = _skip_opts(w, i + 1, {"-u", "-g", "-C", "-p", "-U", "-r", "-t", "-h"})
        elif x in ("nice", "stdbuf"):
            i = _skip_opts(w, i + 1, {"-n", "-i", "-o", "-e"})
        elif x == "timeout":
            i = _skip_opts(w, i + 1, {"-s", "-k", "--signal", "--kill-after"}) + 1
        elif x == "xargs":
            i = _skip_opts(w, i + 1, {"-I", "-n", "-L", "-P", "-d", "-E", "-s", "-a"})
        else:
            break
    return i


def normalized(argv):
    argv = argv[command_index(argv):]
    return [base(argv[0])] + argv[1:] if argv else argv


def argv_of(text):
    return normalized(words(text))


def is_secret_run(argv):
    return argv[:2] == ["secret", "run"]


def anchored_extract(text):
    """Is this an extraction of one named non-secret variable, anchored to the
    start of the line? The only shape a dump may be piped into."""
    argv = argv_of(text)
    if not argv:
        return False
    cmd, args = argv[0], argv[1:]
    if cmd == "grep":
        pats, i = [], 0
        while i < len(args):
            a = args[i]
            if a in ("-m", "--max-count"):
                i += 2
                continue
            if a.startswith("-"):
                if not re.fullmatch(r"-[Eimo]+|-m\d+|--max-count=\d+", a):
                    return False
            else:
                pats.append(a)
            i += 1
        m = len(pats) == 1 and re.fullmatch(r"\^(" + NAME + r")=(\.\*)?", pats[0])
        return bool(m) and not looks_secret(m.group(1))
    if cmd == "sed":
        opts = [a for a in args if a.startswith("-")]
        scripts = [a for a in args if not a.startswith("-")]
        if "-n" not in opts or set(opts) - {"-n", "-E", "-r"} or len(scripts) != 1:
            return False
        m = (re.fullmatch(r"s(.)\^(" + NAME + r")=(\.\*|\\\(\.\*\\\)|\(\.\*\))?\1[^;\n]*?\1p", scripts[0])
             or re.fullmatch(r"/\^()(" + NAME + r")=[^/;\n]*/p", scripts[0]))
        return bool(m) and not looks_secret(m.group(2))
    return False


def _prints_secret_var(args):
    for a in args:
        for m in re.finditer(r"\$(\{)?([#!])?(" + NAME + r")(:?\+|\*|@)?", a):
            brace, mark, name, tail = m.groups()
            if mark == "#":
                continue  # a length, not the value
            if mark == "!":
                if brace and tail in ("*", "@"):
                    continue  # names, not values
                return True
            if brace and tail and "+" in tail:
                continue  # ${NAME:+set} says whether it is set, nothing more
            if looks_secret(name):
                return True
    return False


def shell_env_dump(argv, rest):
    cmd, args = argv[0], argv[1:]
    dump = False
    if cmd == "env":
        dump = True  # normalized() has already unwrapped env running a command
    elif cmd == "printenv":
        names = [a for a in args if not a.startswith("-")]
        if any(looks_secret(n) for n in names):
            return "cmd.shell-env-dump", "a secret-looking variable"
        dump = not names
    elif cmd == "set":
        dump = not args
    elif cmd == "export":
        dump = all(a.startswith("-") for a in args)
    elif cmd in ("declare", "typeset"):
        opts = "".join(a[1:] for a in args if a.startswith("-"))
        names = [a for a in args if not a.startswith("-")]
        if not names:
            dump = not opts or bool(set(opts) & set("xp"))
        elif "p" in opts and any(looks_secret(n.split("=")[0]) for n in names):
            return "cmd.shell-env-dump", "a secret-looking variable"
    elif cmd == "compgen":
        lists_vars = {"-v", "-e"} & set(args) or "variable" in args or "export" in args
        if lists_vars and any((argv_of(t) or [""])[0] not in NAME_FILTERS for t in rest):
            return "cmd.shell-env-dump", "the shell's environment"
    elif cmd in ("echo", "printf", "print"):
        if _prints_secret_var(args):
            return "cmd.shell-env-dump", "a secret-looking variable"
    if dump and not (rest and anchored_extract(rest[0])):
        return "cmd.shell-env-dump", "the shell's environment"
    return None


def ps_env(argv):
    if argv[0] != "ps":
        return None
    args = argv[1:]
    bsd = args and re.fullmatch(r"[A-Za-z]+", args[0]) and "e" in args[0]
    if bsd or any(re.fullmatch(r"-[A-Za-z]*E[A-Za-z]*", a) for a in args):
        return "cmd.ps-env", "every process's environment"
    return None


DOCKER_GLOBAL = {"-H", "--host", "-c", "--context", "--config", "-l", "--log-level",
                 "--tlscacert", "--tlscert", "--tlskey", "--url", "--connection"}
COMPOSE_GLOBAL = {"-f", "--file", "-p", "--project-name", "--profile", "--env-file",
                  "--project-directory", "--ansi", "--progress", "--parallel"}


def docker_args(argv):
    """argv past docker/podman and their global options, or None. The
    standalone compose binaries come back as ['compose', ...]."""
    if argv[0] in ("docker-compose", "podman-compose"):
        return ["compose"] + argv[1:]
    if argv[0] not in ("docker", "podman"):
        return None
    return argv[_skip_opts(argv, 1, DOCKER_GLOBAL):]


def compose_args(sub):
    """Past 'compose' and its global options."""
    if not sub or sub[0] != "compose":
        return None
    return sub[_skip_opts(sub, 1, COMPOSE_GLOBAL):]


# The environment list and nothing else, one entry per line: the one format
# that may touch Env, and only when an anchored extraction reads it.
_DOT = r"(\.|\$\w+)"
ENV_RANGE = re.compile(
    r"\{\{-?range(\$\w+:?=)?\.Config\.Env-?\}\}"
    r"(\{\{println" + _DOT + r"\}\}"
    r"|\{\{" + _DOT + r"\}\}(\{\{println\}\}|\{\{\"\\n\"\}\}|\\n)"
    r"|\{\{printf\"%s\\n\"" + _DOT + r"\}\})"
    r"\{\{-?end-?\}\}"
)
_BLOCK = re.compile(
    r"\{\{-?\s*(range|with)\b(?:(?!\{\{-?\s*(?:range|with)\b).)*?\{\{-?\s*end\s*-?\}\}", re.S
)


def touches_env(fmt):
    if "Env" in fmt or re.search(r"\.Config\b(?!\.)", fmt):
        return True
    # A bare dot outside any range prints the whole object, Env included.
    while True:
        stripped = _BLOCK.sub("", fmt)
        if stripped == fmt:
            break
        fmt = stripped
    return bool(re.search(r"\{\{-?\s*(json\s+|print(ln|f\s+\S+)?\s+)?\.\s*-?\}\}", fmt))


def container_env(argv, rest):
    sub = docker_args(argv)
    if sub is None:
        return None
    if sub[:1] == ["inspect"]:
        args = sub[1:]
    elif sub[:2] == ["container", "inspect"]:
        args = sub[2:]
    else:
        return None
    if "--help" in args:
        return None
    formats, i = [], 0
    while i < len(args):
        a = args[i]
        if a in ("-f", "--format"):
            formats.append(args[i + 1] if i + 1 < len(args) else "")
            i += 2
            continue
        if a.startswith("--format="):
            formats.append(a[9:])
        elif a.startswith("-f") and not a.startswith("--"):
            formats.append(a[2:])
        i += 1
    hit = ("cmd.container-env", "a container's environment")
    if not formats:
        return hit  # the default JSON includes Config.Env
    for fmt in formats:
        if not touches_env(fmt):
            continue
        if ENV_RANGE.fullmatch(re.sub(r"\s+", "", fmt)) and rest and anchored_extract(rest[0]):
            continue
        return hit
    return None


def container_exec_env(argv, rest):
    inner = None
    sub = docker_args(argv)
    if sub is not None:
        comp = compose_args(sub)
        if comp is not None and comp[:1] in (["exec"], ["run"]):
            i = _skip_opts(comp, 1, {"-e", "--env", "-u", "--user", "-w", "--workdir",
                                     "--index", "--name", "--entrypoint", "-v",
                                     "--volume", "-p", "--publish", "-l", "--label"})
            inner = comp[i + 1:]
        elif sub[:1] == ["exec"] or sub[:2] == ["container", "exec"]:
            start = 1 if sub[0] == "exec" else 2
            i = _skip_opts(sub, start, {"-e", "--env", "--env-file", "-u", "--user",
                                        "-w", "--workdir", "--detach-keys"})
            inner = sub[i + 1:]
    elif argv[0] == "kubectl" and "exec" in argv:
        if "--" in argv:
            inner = argv[argv.index("--") + 1:]
        else:
            i = _skip_opts(argv, argv.index("exec") + 1,
                           {"-n", "--namespace", "-c", "--container", "--context",
                            "--kubeconfig", "-f", "--filename"})
            inner = argv[i + 1:]
    if not inner:
        return None
    found = argv_verdict(inner, rest)
    if found and found[0] in ("cmd.shell-env-dump", "cmd.proc-environ", "cmd.ps-env"):
        return "cmd.container-exec-env", "a container's environment"
    return found


def compose_config(argv):
    sub = docker_args(argv)
    comp = compose_args(sub) if sub else None
    if not comp or comp[0] != "config":
        return None
    args = comp[1:]
    hit = ("cmd.compose-config", "the interpolated compose config")
    if "--environment" in args:
        return hit
    if "--no-interpolate" in args or "--help" in args:
        return None
    names_only = {"--services", "--volumes", "--profiles", "--images", "--networks", "-q", "--quiet"}
    if names_only & set(args) or any(a.startswith("--hash") for a in args):
        return None
    return hit


def _has_seq(args, seq):
    return any(args[i:i + len(seq)] == seq for i in range(len(args)))


def prints_token(argv):
    cmd, a = argv[0], argv[1:]
    if "--help" in a or "-h" in a:
        return False
    if cmd == "gh":
        return _has_seq(a, ["auth", "token"]) or (
            _has_seq(a, ["auth", "status"]) and ("-t" in a or "--show-token" in a))
    if cmd == "git":
        return _has_seq(a, ["credential", "fill"]) or (
            any(x.startswith("credential-") for x in a) and "get" in a)
    if cmd == "gcloud":
        return "auth" in a and bool({"print-access-token", "print-identity-token"} & set(a))
    if cmd == "az":
        return _has_seq(a, ["account", "get-access-token"]) or (
            _has_seq(a, ["acr", "login"]) and "--expose-token" in a)
    if cmd == "aws":
        for i in range(len(a) - 2):
            if a[i:i + 2] == ["configure", "get"] and looks_secret(a[i + 2]):
                return True
        return any(_has_seq(a, s) for s in (["configure", "export-credentials"],
                                             ["ecr", "get-login-password"],
                                             ["sts", "get-session-token"]))
    if cmd == "kubectl" and "get" in a:
        pos = [x for x in a[a.index("get") + 1:] if not x.startswith("-")]
        if not pos or not pos[0].startswith("secret"):
            return False
        out = None
        for i, x in enumerate(a):
            if x in ("-o", "--output"):
                out = a[i + 1] if i + 1 < len(a) else ""
            elif x.startswith("--output="):
                out = x[9:]
            elif x.startswith("-o") and not x.startswith("--"):
                out = x[2:].lstrip("=")
        return out is not None and out not in ("name", "wide")
    if cmd == "doppler" and a[:1] == ["secrets"]:
        pos = [x for x in a[1:] if not x.startswith("-")]
        if pos[:1] in (["get"], ["download"]):
            return True
        return not pos and "--only-names" not in a
    if cmd == "op":
        return a[:1] == ["read"] or (_has_seq(a, ["item", "get"]) and "--reveal" in a)
    return False


def consumes_quietly(text):
    """A pipe reader that takes a credential on stdin and does not print it."""
    argv = argv_of(text)
    return bool(argv) and ("--password-stdin" in argv or "--with-token" in argv
                           or argv[:2] in (["secret", "set"], ["secret", "update"],
                                           ["secret", "verify"]))


SHELL_VALUED = {"-o", "-O", "+o", "+O", "--rcfile", "--init-file"}
STDIN_PATHS = {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}


def shell_verdict(argv, piped, stdin):
    """A shell runs a -c string, a script file, or whatever arrives on stdin."""
    args, i, flags = argv[1:], 0, ""
    while i < len(args) and args[i][:1] in "-+" and args[i] != "-":
        a = args[i]
        if a == "--":
            i += 1
            break
        if a in SHELL_VALUED:
            i += 2
            continue
        if not a.startswith("--"):
            flags += a[1:]
        i += 1
    positional = args[i:]
    if "c" in flags:
        return env_verdict(positional[0]) if positional else None
    reads_stdin = "s" in flags or not positional or positional[0] in STDIN_PATHS
    if not reads_stdin:
        return None  # a script file: out of this guard's sight, as any program is
    for script in stdin:
        found = env_verdict(script)
        if found:
            return found
    if piped:
        return "cmd.shell-stdin", "a script piped into a shell"
    return None


def argv_verdict(argv, rest, text=None, piped=False, stdin=()):
    """The environment rules for one simple command; rest is what its output
    is piped into. Anything run through 'secret run' is left alone: that is
    the sanctioned path, and its output is scrubbed."""
    argv = normalized(argv)
    if not argv or is_secret_run(argv):
        return None
    if argv[0] in SHELLS:
        return shell_verdict(argv, piped, stdin)
    if argv[0] in ("eval", "source", "."):
        return env_verdict(" ".join(argv[1:]))
    for check in (container_env, container_exec_env):
        found = check(argv, rest)
        if found:
            return found
    if PROC_ENVIRON.search(text or " ".join(argv)):
        return "cmd.proc-environ", "a process environment"
    found = compose_config(argv) or ps_env(argv) or shell_env_dump(argv, rest)
    if found:
        return found
    if prints_token(argv) and not (rest and consumes_quietly(rest[0])):
        return "cmd.token-print", "a credential"
    return None


def _captured_quietly(text, n, command):
    """Does substitution n land somewhere nothing prints it: an assignment,
    or an argument to a command that neither echoes nor traces it?"""
    if re.search(r"\bset\s+-[a-z]*x", command):
        return False
    w = words(text)
    ci = command_index(w)
    argv = normalized(w)
    for j, x in enumerate(w):
        if f"__SUB{n}__" not in x:
            continue
        if ASSIGN.fullmatch(x) and (j < ci or argv[:1] in (
                ["export"], ["local"], ["declare"], ["typeset"], ["readonly"], ["env"])):
            continue
        if not argv or argv[0] in PRINTERS or VERBOSE & set(argv):
            return False
        if argv[0] == "curl" and any(re.fullmatch(r"-[A-Za-z]*v[A-Za-z]*", a) for a in argv):
            return False
    return True


_depth = 0


def env_verdict(command):
    """Every nested command line — a substitution, a -c string, an eval —
    comes back through here, so this is where nesting is counted. Past the
    cap the answer is deny: what cannot be checked is not let through."""
    global _depth
    if _depth >= MAX_DEPTH:
        return TOO_DEEP
    _depth += 1
    try:
        return _env_verdict(command)
    finally:
        _depth -= 1


def _env_verdict(command):
    pipelines, subs = scan(command)
    for pipeline in pipelines:
        for idx, text in enumerate(pipeline):
            found = argv_verdict(words(text), pipeline[idx + 1:], text,
                                 piped=idx > 0, stdin=stdin_scripts(text, subs))
            if found:
                return found
            for m in SUB.finditer(text):
                n = int(m.group(1))
                if n >= len(subs):
                    continue
                inner = env_verdict(subs[n])
                if inner is None:
                    continue
                if inner[0] == "cmd.token-print" and _captured_quietly(text, n, command):
                    continue
                return inner
    return None


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
    if BROWSER_COOKIES.search(command):
        return "cmd.browser-cookies", "the browser's cookies"
    if READER_RE.search(command):
        for rule, pattern, what in BLOCKED_IN_COMMAND:
            if pattern.search(command):
                return rule, what.strip()
    return env_verdict(command)


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


# --- detection --------------------------------------------------------------
#
# What the rules above miss still reaches the agent in a tool's output. The
# shapes come from run.py, so 'secret run' and this agree on what a credential
# looks like.

LABELED_SHAPES = [(pattern, label.decode()) for pattern, label in SHAPE_PATTERNS]


def redact(value, found):
    """A copy of value with every credential shape replaced, same structure.
    The labels of the shapes it met are added to found."""
    if isinstance(value, str):
        raw = value.encode("utf-8", "surrogatepass")
        for pattern, label in LABELED_SHAPES:
            if pattern.search(raw):
                found.add(label)
                raw = pattern.sub(token(label.encode()), raw)
        return raw.decode("utf-8", "surrogatepass")
    if isinstance(value, list):
        return [redact(v, found) for v in value]
    if isinstance(value, dict):
        return {k: redact(v, found) for k, v in value.items()}
    return value


def describe_call(tool, args):
    """Which call it was, in a few words, with any credential in them redacted."""
    if not isinstance(args, dict):
        args = {}
    text = {
        "Bash": args.get("command"),
        "Read": args.get("file_path"),
        "Grep": " in ".join(str(x) for x in (args.get("pattern"), args.get("path")) if x),
        "WebFetch": args.get("url"),
    }.get(tool) or ""
    text = " ".join(redact(str(text), set()).split())
    return text[:117] + "..." if len(text) > 120 else text


def post_tool_use(payload, current):
    found = set()
    redacted = redact(payload.get("tool_response"), found)
    if not found:
        return 0
    tool = payload.get("tool_name") or "?"
    call = describe_call(tool, payload.get("tool_input"))
    shapes = ", ".join(sorted(found))
    for shape in sorted(found):
        audit("leak", tool, f"leak.{shape}", call)
    where = f"the output of {tool}" + (f" ({call})" if call else "")
    hidden = current == "enforce"
    user = (
        f"secret-guard: a credential shaped like {shapes} appeared in {where}. "
        + ("The agent was handed a redacted copy, but the raw output has already left the tool"
           " and reached Claude Code's telemetry, so rotate it now."
           if hidden else "The agent has read it, so rotate it now.")
    )
    agent = (
        f"secret-guard: {where} contained a credential shaped like {shapes}"
        + (", replaced by a redaction marker. Do not try to recover it." if hidden else ".")
        + " Tell the person you are working with that it should be rotated, and do not"
        " print it again; use 'secret run <KEY> -- <command>' to hand a credential to a process."
    )
    out = {"systemMessage": user,
           "hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": agent}}
    if hidden:
        field = "updatedMCPToolOutput" if tool.startswith("mcp__") else "updatedToolOutput"
        out["hookSpecificOutput"][field] = redacted
    print(json.dumps(out))
    return 0


def pre_tool_use(payload, current):
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
    advice = RULE_ADVICE.get(rule) or ADVICE.format(what=what)
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": advice + f" [{rule}]",
        }
    }))
    return 0


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

    try:
        if payload.get("hook_event_name") == "PostToolUse":
            return post_tool_use(payload, current)
        return pre_tool_use(payload, current)
    except Exception:  # a bug here must never wedge a session either
        return 0


if __name__ == "__main__":
    sys.exit(main())
