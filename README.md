# You — Gemini agent for Termux

An early, approval-controlled Python CLI for Android/Termux. Gemini supplies reasoning in the cloud; this program runs local tools. Default model: `gemini-3.6-flash` (configurable).

**Status: v0.1 foundation prototype.** Offline tests pass on Linux. Real Termux compatibility, your API credentials, model access, and live function calling still require testing. This is not a completed roadmap or a secure code sandbox.

## Install in Termux

Use a maintained Termux installation. Keep the project and workspace in Termux private storage, not shared Android storage.

```sh
pkg update
pkg install python git
cd ~
git clone https://github.com/markoza99/You
cd You
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

If already cloned, enter the existing directory and run `git pull --ff-only` instead of cloning again. Runtime uses Python's standard library; installation needs setuptools. Android installation is not yet verified.

### Set your API key privately

In Termux's Bash shell, use hidden input (the key is not placed in shell history):

```sh
read -r -s -p 'Gemini API key: ' GEMINI_API_KEY; echo
export GEMINI_API_KEY
export YOU_MODEL=gemini-3.6-flash
you doctor
you doctor --online
```

Do not paste your key into chat, source code, or Git. `.env.example` is documentation only; `.env` files are **not automatically loaded**. The variable lasts for the shell session. `doctor --online` sends a small API request and consumes quota; plain `doctor` checks local settings only.

## Use

```sh
you chat 'Explain Python CSV files simply.'
you run 'Create a hello.py script that prints Hello, then read it back.'
```

Writes display the exact content and require typing `yes`. Noninteractive approvals are denied. Reads are limited to the dedicated workspace, default `~/.local/share/you/workspace`. Workspace contents read by tools are sent to Gemini: do not place confidential data there without understanding this.

### Optional Python execution

```sh
you run --allow-python 'Create hello.py, run it, and verify its output.'
```

**Warning:** approved Python scripts can access Termux's files and network, modify/delete data, or use other installed tools. They are **not sandboxed**. Read the displayed code before approving. The child does not inherit the API key environment variable, but that is not isolation from credentials stored on disk. Do not approve untrusted code. Python execution is disabled by default and still requires approval when enabled.

### Limits and configuration

Global options go before the subcommand:

```sh
you --workspace "$HOME/my-agent-workspace" run 'List the files.'
you run --max-steps 6 --max-tokens 16000 --max-seconds 120 'Write a short report.'
```

- Tools: `list_files`, `read_file`, `write_file`; opt-in `run_python`.
- Writes/reads and captured execution output: 16,000 bytes; directory listing: up to 100 entries.
- Default: 8 model turns, at most 4 tool calls per turn, 24,000 reported-token threshold, 180-second runtime threshold.
- API timeout: 45 seconds; Python timeout: 15 seconds, with process-group cleanup.
- Token checks happen after a response, so one request can exceed the threshold. Runtime checks happen between actions and can overrun during a request, a script, or approval. These are not hard spending/time caps. Set service-side quota controls as well.
- No automatic retries, saved conversations, scheduled jobs, or general shell execution in this version.
- `answered` means the model produced a final response, **not** independently certified task success. File writes return a read-back hash; script output/exit code is evidence, not proof of correctness.
- Ctrl+C cancels. Do not run multiple agents against the same workspace.

## Test

```sh
python -m pip install pytest
python -m pytest -q
```

Tests use fake provider replies and never need a real key or network access. The CI configuration is included in the downloadable ZIP but is not installed in this repository because the GitHub connection cannot write workflow files. Run the tests locally for now. See `docs/STATUS.md` for implemented versus pending roadmap items.

## Next milestones

Live phone validation, file search, more structured result verification, persistent SQLite tasks/memory, research tools, Android capabilities, and bounded scheduling. No root access or unrestricted autonomy is planned for this initial release.
