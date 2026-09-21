# You — Termux agent (DeepSeek V4 Flash via VyceAI)

An early, approval-controlled Python CLI for Android/Termux. The model runs in the cloud through VyceAI’s OpenAI-compatible API; this program runs local tools. Default model: `deepseek-v4-flash`.

**Status: v0.2.** Offline tests pass on Linux. This is not a completed roadmap or a secure code sandbox. VyceAI is a third-party proxy, not official DeepSeek.

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

If already cloned:

```sh
cd ~/You
git pull --ff-only
. .venv/bin/activate
python -m pip install -e .
```

### Set your VyceAI key privately

Do not paste the key into chat, source code, or Git.

```sh
unset GEMINI_API_KEY
read -r -s -p 'VyceAI API key: ' YOU_API_KEY; echo
export YOU_API_KEY
export YOU_API_BASE=https://vyceai.com/v1
export YOU_MODEL=deepseek-v4-flash
you save-key
you doctor
you doctor --online
```

`you save-key` writes the key to `~/.local/share/you/credentials.json` (mode 600). Later Termux sessions can run `you` without exporting the key again. Do not copy that file or paste keys into chat.

`.env.example` is documentation only; `.env` files are **not automatically loaded**. The variable lasts for the shell session. `doctor --online` sends a small API request.

## Use

Short goals are enough. The agent plans, uses built-in tools, and remembers facts like `tv_ip`. It still cannot install packages or skip approvals.

```sh
you chat 'Say hi in one short sentence.'
you run 'Create a hello.py script that prints Hello, then read it back.'
you run 'Find my TV on Wi-Fi and say if DIAL YouTube works.'
```

Writes display the exact content and require typing `yes`. For one run only, pass `--yes` to skip those prompts (scripts are still unsandboxed). There is no permanent auto-approve mode. Workspace default: `~/.local/share/you/workspace`. File contents read by tools are sent to the API.

`--max-seconds` counts model request time only, not the time you spend at the approval prompt. HTTP 503/520 are retried a few times. Script stdout is printed after `run_python`.

### Optional Python execution

```sh
you run --allow-python 'Create hello.py, run it, and verify its output.'
you run --allow-python 'Open youtube.com in the phone browser.'
```

Approved Python and shell are **not sandboxed**. Read the displayed code or command before typing `yes`.

Opening a URL needs Termux:API (`pkg install termux-api` plus the Termux:API app from the same store as Termux).

**Android blocks this by default.** On Android 11+ an app cannot start an activity unless it is in the foreground or holds **Draw over other apps**. `am start` and `termux-open-url` then exit 0 and do nothing. Grant Termux *Settings → Apps → Termux → Display over other apps*.

Because of that, `open_url` always returns `verified: false`. A zero exit code means the command ran, not that the browser appeared. The agent is instructed to ask you to look at the screen rather than claim success.

## Limits

- Tools: `list_files`, `read_file`, `write_file`, `local_ipv4`, `ssdp_discover`, `dial_inspect`, `dial_launch`, `android_check`, `check_command`, `pkg_install`, `open_url`, `think`, `memory_get`, `memory_set`; opt-in `run_python` and `run_shell`.
- The agent is expected to be self-sufficient: it checks for a missing program with `check_command` and installs it with `pkg_install` rather than telling you to do it. `pkg_install` still shows an approval prompt, and uses a 300 s timeout instead of the 15 s one used by `run_shell`.
- `lan_scan` lists this phone's Wi-Fi `/24` (IP + MAC via ARP/SSDP). Prefer it over a ping loop: Android often denies `/proc/net/arp` and `ip neigh`.
- `run_shell` runs one Termux command (`am`, `termux-open-url`, `pkg`, `ping`, `curl`). It is enabled by the same `--allow-python` / `--allow-exec` flag, because approved Python can already spawn a shell. Every command is shown before it runs.
- `open_url` opens an http(s) address via `termux-open-url`, falling back to `am start`. It reports every attempt and always sets `verified: false` — Android can block the launch silently.
- A few catastrophic patterns (`rm -rf /`, `mkfs`, fork bombs) are refused before the prompt. That is a guardrail against a careless model, **not** a security boundary.
- On failure the agent is told to read the error and try a different approach, up to about 5 real attempts, instead of stopping at the first error.
- For LAN IP / nearby devices, the agent should use `local_ipv4` and `ssdp_discover` instead of writing scan scripts. SSDP still misses silent TVs.
- `dial_inspect` / `dial_launch` talk to one LAN IPv4 via DIAL. A YouTube home-screen icon is not DIAL; HTTP 404 means that app is not exposed.
- Default: 12 model turns, at most 4 tool calls per turn, 40k token threshold.
- Extra tools: `think`, `memory_get`, `memory_set`. Facts are stored in `~/.local/share/you/memory.json`.
- API timeout: 90 seconds. HTTP 429 means rate limit; wait and retry. That is not automatically a billing failure.
- `answered` means the model produced a final response, not independently certified success.

VyceAI’s dashboard lists paid per-token prices even on Free Tier. Free credits/quotas still apply; check your VyceAI account. Some reports say `deepseek-v4-flash` can invent tool results — this CLI only accepts real tool executions.

## Test

```sh
python -m pip install pytest
python -m pytest -q
```
