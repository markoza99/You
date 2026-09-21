# Evidence-based recovery

This change fixes premature DIAL termination; it does not add a Cast, Android TV remote, or ADB control client.

## Behavior

- DIAL launch failure is scoped to DIAL and returned to the model with a `tv_capabilities` suggestion. It does not automatically end the run or prove that all TV control is impossible.
- `tv_capabilities` checks five TCP ports on a single validated LAN /24 host: 8008, 8009, 6466, 6467, 5555. Connections have a 1.5-second timeout and run concurrently. It sends no application commands. Open ports are protocol hints, not authentication, protocol, or launch verification. Closed ports do not rule out services on other ports.
- `environment_info` supplies actual platform, Python version, workspace, command paths, code-execution flag, and enabled tools. It is injected before the first model call. It does not dump environment variables or perform network discovery.
- Saved memory is historical evidence, not a forced stop policy. An arbitrary first SSDP device is no longer automatically remembered as a TV. Existing saved facts are not deleted; verify old target IPs before controlling a device.
- All six approval-denial paths return a structured terminal denial. A denied action ends the run before remaining tool calls execute. Execution failures display `failed`, not `failed/denied`.
- Malformed tool JSON no longer references an uninitialized `args` variable.

## Behavior

- DIAL launch failure is scoped to DIAL and returned to the model with a `tv_capabilities` suggestion. It does not automatically end the run or prove that all TV control is impossible.
- `tv_capabilities` checks five TCP ports on a single validated LAN /24 host: 8008, 8009, 6466, 6467, 5555. Connections have a 1.5-second timeout and run concurrently. It sends no application commands. Open ports are protocol hints, not authentication, protocol, or launch verification. Closed ports do not rule out services on other ports.
- `host_probe` is a new bounded, single-host, read-only probe of ONE validated LAN /24 IP: ICMP echo, PTR, TCP reachability on a small fixed well-known port set (plus up to 8 caller-requested ports), and HTTP/HTTPS service banners. It rejects out-of-LAN, loopback, broadcast, and the phone's own IP before any connection. It never authenticates, fingerprints the OS, pairs, launches, or does mDNS/SSDP/NetBIOS (those are returned as `unimplemented`, not faked).
- `environment_info` supplies actual platform, Python version, workspace, command paths, code-execution flag, and enabled tools. It is injected before the first model call. It does not dump environment variables or perform network discovery.
- **Unknown/disabled tools no longer end the goal.** Calling an invented tool (e.g. `run_sheel`) or a disabled execution tool (e.g. `run_shell` without `--allow-python`) returns a structured `unknown_tool` result that lists the enabled tools and, for a disabled execution tool, the exact CLI flag (`--allow-python`). The model is expected to recover by picking an enabled tool, not to be force-stopped.
- **Repeated identical failures no longer silently terminate the run.** The loop no longer kills the goal after N failures; it flags the repeated call ("do not repeat; write your report") so the model can report the blocker. Only a *user denial* is terminal.
- **Partial evidence report on every non-`answered` outcome.** Runtime, token, and step limits (and denials) now return a bounded `evidence` list of observed tool outcomes plus a `note`, instead of a bare "limit_reached" with no report. Successful calls are not treated as failure evidence; no extra unsafe actions are taken to fill the report.
- Saved memory is historical evidence, not a forced stop policy. An arbitrary first SSDP device is no longer automatically remembered as a TV. Existing saved facts are not deleted; verify old target IPs before controlling a device.
- All approval-denial paths return a structured terminal denial. A denied action ends the run before remaining tool calls execute. Execution failures display `failed`, not `failed/denied`.
- Prompt scope tightened: default to a single target IP (no whole-LAN sweep unless needed), do not re-probe an already-refused port (e.g. 8008 DIAL 404), SSDP is UDP multicast (not a TCP loop), TTL 64 is a hop limit not an OS, and a router banner is not a DHCP table or the target vendor.

## Limits

Recovery remains model-driven and bounded by the existing step/token/runtime policies. `host_probe` is a convenience probe, not a full scanner or fingerprinter; it does not add Cast/Android-TV/ADB clients, bypass pairing, or guarantee any launch. Denials remain terminal. No claim is made that a particular TV can launch YouTube.

## Validation

`python -m pytest -q -p no:cacheprovider`: 120 tests passed in the development sandbox. `python -m compileall -q src tests` also passed.

New tests (in `tests/test_recovery_and_probe.py`) simulate: an unknown/invented tool returning a structured recoverable result with the exact enable flag, a disabled execution tool (`run_shell`) being reported with `--allow-python`, the loop recovering from a first unknown tool instead of terminating, a repeated identical failure flagging (not killing) the run, a user denial staying terminal with a report fallback, a budget-exhaustion partial evidence report with no extra unsafe actions, and `host_probe` rejecting out-of-LAN / loopback / self / non-IPv4 targets before any connection and labeling ports and mDNS/SSDP/NetBIOS as unverified/unimplemented. All network is mocked; no live model request, Termux session, or physical TV/lan was used.

## Install

```sh
cd You
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
# tests
python -m pip install pytest
python -m pytest -q -p no:cacheprovider
```

## Try the review branch

From your existing clone (save or commit local changes first):

```sh
git fetch origin
git switch --track origin/fix/evidence-based-agent-recovery
python -m pip install -e .
you run 'open youtube in my tv'
```

If that local branch already exists, use `git switch fix/evidence-based-agent-recovery` instead. Review every approval. If another control client is needed and shell execution is disabled, the agent should report that prerequisite instead of claiming to have performed it.
