# Evidence-based recovery

This change fixes premature DIAL termination; it does not add a Cast, Android TV remote, or ADB control client.

## Behavior

- DIAL launch failure is scoped to DIAL and returned to the model with a `tv_capabilities` suggestion. It does not automatically end the run or prove that all TV control is impossible.
- `tv_capabilities` checks five TCP ports on a single validated LAN /24 host: 8008, 8009, 6466, 6467, 5555. Connections have a 1.5-second timeout and run concurrently. It sends no application commands. Open ports are protocol hints, not authentication, protocol, or launch verification. Closed ports do not rule out services on other ports.
- `environment_info` supplies actual platform, Python version, workspace, command paths, code-execution flag, and enabled tools. It is injected before the first model call. It does not dump environment variables or perform network discovery.
- Saved memory is historical evidence, not a forced stop policy. An arbitrary first SSDP device is no longer automatically remembered as a TV. Existing saved facts are not deleted; verify old target IPs before controlling a device.
- All six approval-denial paths return a structured terminal denial. A denied action ends the run before remaining tool calls execute. Execution failures display `failed`, not `failed/denied`.
- Malformed tool JSON no longer references an uninitialized `args` variable.

## Limits

Recovery remains model-driven and bounded by the existing step/token/runtime policies. Existing repeated-failure and unknown-tool circuit breakers remain. An alternative protocol may need a compatible client, explicit approval, and user pairing. Pairing and debugging permissions are not bypassed. No claim is made that a particular TV can launch YouTube.

## Validation

`python -m pytest -q -p no:cacheprovider`: 106 tests passed in the development sandbox. `python -m compileall -q src tests` also passed.

New tests simulate DIAL failure followed by capability discovery, terminal denial, malformed JSON recovery, enabled-tool context, port hint semantics, invalid/off-LAN targets, and unidentified SSDP devices. No live model request, Termux session, or physical TV was used for validation.

## Try the review branch

From your existing clone (save or commit local changes first):

```sh
git fetch origin
git switch --track origin/fix/evidence-based-agent-recovery
python -m pip install -e .
you run 'open youtube in my tv'
```

If that local branch already exists, use `git switch fix/evidence-based-agent-recovery` instead. Review every approval. If another control client is needed and shell execution is disabled, the agent should report that prerequisite instead of claiming to have performed it.
