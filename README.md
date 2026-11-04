# secret

Give a credential to a process without giving it to your coding agent.

```sh
secret set GH_TOKEN                  # prompted, hidden, never on a command line
secret run GH_TOKEN -- curl -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/user
```

The agent writes that second line. It never sees the token.

## Why

A coding agent works by running commands and reading their output. Every byte it
reads becomes part of its transcript, and a transcript is not a scratchpad:

- it is re-sent to the model provider on every subsequent turn of the session;
- it is written to a session log on your disk, in plaintext, and kept;
- once a value is in it, there is no taking it back out.

So `echo $GH_TOKEN`, `cat .env`, and `security find-generic-password -w -s …` are
not conveniences. They are how a token ends up somewhere you never intended.

Keeping a secret out of your shell profile is only half of it. The other half is
assuming the thing running the command is a model that reads the output, and
building for that. That is what this does.

## How

Four layers. The first three are in order of how much they matter; the fourth
catches what gets past them.

**1. The value is never an argument.** `set` reads it from a hidden prompt, or
from stdin when scripted. `run` puts it in the child's environment. It is never
in a command line, so it is never in the process table and never in your shell
history.

**2. Output is scrubbed.** `run` streams the child's stdout and stderr through a
filter that replaces the value — and its base64 and percent-encoded forms — with
`‹redacted:KEY›`. This is the layer that earns its keep. `curl -v` echoing an
`Authorization` header, a stack trace carrying a connection string, a library
logging its own config: all of these leak a secret that was injected correctly,
and all of them are caught here.

It also redacts credentials it has never been told about, by shape: AWS access
keys, GitHub and GitLab tokens, Slack tokens, Google API keys, OpenAI and
Anthropic keys, JWTs, and PEM private key blocks.

**3. A guard hook.** Layers 1 and 2 hold only if the agent uses `secret run`
rather than reading the keychain directly. `secret init` installs a PreToolUse
hook that denies the out-of-band routes: `security find-generic-password`,
`dump-keychain`, and reads of `.env`, `~/.ssh` private keys, `~/.aws`, `~/.kube`,
`.netrc`, `.npmrc`, `.git-credentials`, cookie jars and the keychain files
themselves, plus listing the agent browser's cookies — over
`Bash`, `Read`, `Grep` and `Glob` alike, since skipping the shell is otherwise
the obvious way around it.

It also denies printing an environment, because the agent's own shell holds
live tokens and so does every container it can reach:

- `env`, `printenv`, `set`, `export -p` and `declare -x` with nothing to narrow
  them, and `printenv`, `echo` or `printf` of a variable whose name looks secret
  (`TOKEN`, `SECRET`, `PASSWORD`, `API_KEY`, `AUTH`, `SESSION` and the like);
- `docker inspect` that can include `Config.Env`, `docker exec` or
  `kubectl exec` running an environment dump, `docker compose config` (it fills
  in the dotenv file) unless `--no-interpolate`, `/proc/*/environ`, and `ps`
  with `e` or `-E`;
- commands that print a token outright — `gh auth token`, `gcloud auth
  print-access-token`, `kubectl get secret -o yaml` and their kin — unless the
  output is captured, as in `GH_TOKEN=$(gh auth token) docker compose up -d`,
  or piped into a reader such as `docker login --password-stdin`.

One named, non-secret variable stays readable: `printenv HOME`, or a dump piped
straight into an anchored extraction such as `sed -n 's/^NAME=//p'`. Anything
run through `secret run` is left alone.

The guard reads a command the way the shell would: through `sudo`, `env`,
`command`, `exec`, `nice` and `time`, by full path, inside `$( )`, backticks,
arithmetic, unquoted heredocs, `eval` and `bash -c`. It denies a script piped
into a shell, since it cannot see what that runs, and denies a command nested
too deeply to check rather than letting it through.

**4. A leak check.** The same hook also runs after `Bash`, `Read`, `Grep`,
`WebFetch` and MCP tools, and scans what they returned for the credential
shapes layer 2 knows. On a hit it hands the agent a copy with the value
replaced by a redaction marker, writes the shape to the audit log, and tells
you which call it was so you can rotate the credential now. It never repeats
the value. The replacement uses Claude Code's `updatedToolOutput`
(`updatedMCPToolOutput` for MCP tools); checked on Claude Code 2.1.318, where
neither the agent nor the session log received the raw value.

What the guard deliberately does **not** do: block destructive commands, detect
personal data, or look for prompt injection. Those belong to a different tool,
and bolting them on here makes a guard noisy enough to get switched off.

## Install

Requires macOS (the store is the login Keychain), bash, and python3. `swiftc`,
from the Xcode Command Line Tools, is optional — without it `secret show` falls
back to a dialog that can be screenshotted.

```sh
git clone https://github.com/stevenenen/secret-cli.git
cd secret-cli
./install.sh          # symlinks bin/secret into ~/.local/bin
secret init           # shows what it will change, then asks
```

`install.sh` does not touch any agent's config. `secret init` does, and prints
the change and waits for a yes before doing it. Keep the clone where it is —
the hook path written into the agent config points back at it.

## Use

```
secret set <KEY>              store a new secret (prompted, hidden)
secret update <KEY>           replace an existing one
secret rename <OLD> <NEW>     give it a different name
secret rm <KEY>               forget it
secret list [--all] [filter]  names only, never values
secret show <KEY> [--how]     show the value in a window screenshots cannot see
secret adopt <service>        use a keychain item another app created
secret fingerprint <KEY>      a short digest, safe to paste anywhere
secret verify <KEY>           is the value on stdin the one <KEY> holds?
secret diff <KEY> <KEY>       do two keys hold the same value?
secret run <KEY>... -- <cmd>  run <cmd> with the secrets in its environment
secret init [host]            install the guard hook, with consent
secret help
```

### Finding things

`list` takes a filter that matches three ways, best first: a substring, the
initials of the `SNAKE_CASE` parts, or the letters in order with gaps.

```sh
secret list tok       # substring    -> GH_TOKEN
secret list cpa       # initials     -> CXS_PROD_APIKEY
secret list ghtn      # subsequence  -> GH_TOKEN
```

`--all` adds every other item in your keychain, marked `unmanaged`, in three
tab-separated columns with your own keys first. It reads attributes only, so no
password is fetched and no access dialog appears.

### Using a credential another app already stored

```sh
secret list --all | grep -i somevendor    # find it
secret adopt com.somevendor.api --as VENDOR_KEY
secret run VENDOR_KEY -- ./deploy.sh
```

An adopted item stays the property of the app that created it. This tool reads
it and can forget it; `update` and `rm` will not write to or delete it. macOS
will ask your permission the first time it is read, which is the keychain's own
access control and is not bypassed.

### Is this the same secret?

The question that tempts everyone into pasting "just the first few characters" of
a live credential into a chat window. A prefix is permanent once it is in a
transcript, and it narrows a brute force. Ask it properly instead.

```sh
secret fingerprint CLEARANCE_DEV_SECRET        # local:c6cc8e3003c9
secret diff CLEARANCE_DEV_SECRET OLD_SECRET    # match / no match, exit 0 / 1

# against a value from somewhere else, without it passing through anyone
az keyvault secret show --name CCP-PURPLEID-CLIENT-SECRET --query value -o tsv \
  | secret verify CLEARANCE_DEV_SECRET
```

A fingerprint is an HMAC salted with a key generated once per machine, so two
fingerprints are only comparable where they were made. That matters: an unsalted
hash of a low-entropy value is not safe to paste, because the value can be
guessed and the hash checked. Use `--global` for the plain `sha256` when two
machines genuinely have to agree — it warns when you do.

### Reading one yourself

`secret show <KEY>` puts the value in a macOS window. It is on screen for you
and never in the terminal, so it cannot reach scrollback, a pipe, or an agent's
tool output. Nothing is copied to the clipboard.

The window is built to resist the two ways something else on the Mac could read
it anyway:

- **`NSWindow.sharingType = .none`** — macOS excludes it from `screencapture`,
  Screenshot.app, QuickTime recording and screen sharing. Enforced by the window
  server, not by asking nicely.
- **No accessibility element** — the text stays out of the accessibility tree.
  This is the one that matters: an agent with accessibility access reads windows
  without taking a screenshot at all, so blocking capture alone would be theater.

That needs a real window, so `install.sh` compiles a small Swift helper with
`swiftc`, which ships with the Xcode Command Line Tools. Without it, `show`
falls back to a plain AppleScript dialog that works but can be screenshotted,
and says so every time. `secret show <KEY> --how` tells you which you have.

A key has to be a valid environment variable name — `GH_TOKEN`, not `gh-token` —
because `run` sets one variable per key you name on that invocation.

Nothing is exported globally. The variables exist only inside the process tree
of that one command, only for the keys you listed, and only for as long as it
runs. Your shell never sees them, no shell profile is touched, and the secrets
you did not name are not injected.

```sh
# several at once
secret run DB_USER DB_PASS -- ./migrate.sh

# scripted, no terminal
printf '%s' "$value" | secret set CI_TOKEN

# opt out of scrubbing when you need the raw bytes
secret run PRIVKEY --no-scrub -- ssh-add -
```

### Agents other than Claude Code

The CLI is host-agnostic — any agent, any shell, anything that can run a
command. Only the guard hook is host-specific, because each agent has its own
hook mechanism. `secret init --list-hosts` shows what is supported; adding one
is a new file in `hosts/`. Without a guard, the first two layers still work.

## Known gaps

This reduces accidental leakage. It is not a sandbox, and it is not a defense
against an agent that is actively trying to get around it. The guard is a
denylist: it is meant to catch an agent's accidental leaks, not a determined
attempt to evade it.

- **The guard matches literal text.** A path or command name assembled at
  runtime slips past: `f=.en; cat ${f}v`, or `open('.e'+'nv')` inside a
  `python3 -c`. These are in `tests/fixtures/guard-known-gaps.jsonl` and the
  suite fails if one ever starts being caught, so this list stays honest.
- **The guard covers the `security` binary, not the Keychain API.** A python
  `keyring` call reaches the same data without going through it.
- **Scrubbing is line-oriented.** A value split across two writes with no
  newline between them is caught only once the line completes.
- **Derived values are not scrubbed.** If a command prints the decoded claims of
  a JWT, the claims are not the token and go through.
- **The environment is visible to the child's descendants.** That is what
  injection means: anything the command runs can read the value.
- **A short value is not scrubbed at all.** Under six characters, redaction
  would mangle unrelated output. `set` warns when you store one.
- **`secret run` is exempt from the environment rules.** Its child inherits the
  agent's whole environment, so `secret run KEY -- env` prints every variable;
  only the named keys and the known shapes are scrubbed.
- **A variable is judged by its name.** `echo "$DB_PASS"` goes through, and so
  does a token captured under an innocent name and printed later:
  `x=$(gh auth token); echo "$x"`. The leak check catches the second if the
  token has a known shape.
- **Pod specs are not treated as secrets.** `kubectl get pod -o yaml` shows an
  environment value written inline into the spec.
- **The leak check knows shapes, not values.** An opaque token with no
  recognizable prefix passes it. Once it fires, the raw output has already left
  the tool and reached Claude Code's telemetry: the redaction protects the
  conversation, not the credential. A Claude Code version without
  `updatedToolOutput` hands the agent the raw output and only the warning.
- **A script file is not read.** `bash ./script.sh` or `source ./script.sh` runs
  whatever the file holds; the guard sees only its name.
- **A variable expanded in a heredoc body is not checked.** `cat <<EOF` with
  `$GH_TOKEN` on a line prints it; substitutions in the body are checked.
- **`show` cannot stop a camera pointed at the screen.** Nothing can.

## Development

```sh
brew install bats-core shellcheck
bats tests/
shellcheck bin/secret lib/*.sh hosts/*.sh hooks/*.sh
```

Tests drive the `secret` binary and assert on observable behavior only — exit
status, output, and what a later command can see. No test reaches into an
internal function, so the implementation can be rewritten without touching them.
Each test gets a throwaway keychain, so the suite cannot touch a real credential.

The guard's spec is the three corpora in `tests/fixtures/`: payloads that must
be denied, payloads that must be left alone, and the known gaps above.

## License

MIT.
