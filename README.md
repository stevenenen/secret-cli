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

Keeping secrets out of the shell profile is a solved problem — `envchain`,
`op run`, `summon`, `aws-vault` all do it. What none of them do is assume the
thing running the command is an LLM that reads the output. That is the gap this
fills.

## How

Three layers, in order of how much they matter.

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
`.netrc`, `.npmrc`, `.git-credentials` and the keychain files themselves — over
`Bash`, `Read`, `Grep` and `Glob` alike, since skipping the shell is otherwise
the obvious way around it.

What the guard deliberately does **not** do: block destructive commands, detect
personal data, or look for prompt injection. Those belong to a different tool,
and bolting them on here makes a guard noisy enough to get switched off.

## Install

Requires macOS (the store is the login Keychain), bash, and python3.

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
secret rm <KEY>               forget it
secret list                   names only, never values
secret run <KEY>... -- <cmd>  run <cmd> with the secrets in its environment
secret init [host]            install the guard hook, with consent
secret help
```

Keys are environment variable names, because that is what they become.

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
against an agent that is actively trying to get around it.

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
  injection means. Anything the child runs can read the value, exactly as with
  `envchain`, `op run` or `summon`.
- **A short value is not scrubbed at all.** Under six characters, redaction
  would mangle unrelated output. `set` warns when you store one.

## Development

```sh
brew install bats-core shellcheck
bats tests/          # 98 behavioral tests
shellcheck bin/secret lib/*.sh hosts/*.sh hooks/*.sh
```

Tests drive the `secret` binary and assert on observable behavior only — exit
status, output, and what a later command can see. No test reaches into an
internal function, so the implementation can be rewritten without touching them.
Each test gets a throwaway keychain, so the suite cannot touch a real credential.

The guard's spec is the three corpora in `tests/fixtures/`: payloads that must
be denied, payloads that must be left alone, and the known gaps above.

## Prior art

[`envchain`](https://github.com/sorah/envchain) is the same storage-and-inject
idea and predates this by a decade; if you do not need the scrubbing or the
guard, use it instead. [`summon`](https://github.com/cyberark/summon),
[`teller`](https://github.com/tellerops/teller), 1Password's `op run` and
[`aws-vault`](https://github.com/99designs/aws-vault) all solve the injection
half for their own stores.

## License

MIT.
