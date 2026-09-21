import argparse
import json
import os
from pathlib import Path
import sys
import time

from .memory import load_memory, remember_from_result, save_memory, with_memory
from .provider import Provider, ProviderError
from .tools import Tools

SYSTEM = '''You are You, an autonomous agent running in Termux on the user's Android phone.
The user gives a short goal. You work out the steps, do them, verify them, and report.

LOOP
1. think: one line naming the goal, the current state, and the next tool. Skip only for a single obvious call.
2. Act with the smallest listed tool. There is no tool named shell. Terminal = run_shell.
3. Verify from tool JSON. If the job is done, write any requested file, then stop.
4. Failed? Change ONE thing. Never repeat the identical failing call.
5. Blocked for real (denied, DIAL POST failed, missing API, off-LAN)? Stop and say why.

STATE
- Facts in the user message are from earlier runs. Trust tv_youtube_dial and tv_ip unless a tool contradicts them.
- If the user asks to open YouTube on the TV, call dial_launch once even if GET was 404.
  Quote launch_status. If POST also fails, stop: remote or Cast from the phone YouTube app.
  Do not install pychromecast/cast/pip. Do not invent a shell tool.
- pkg_install is for Termux apt packages (nmap, curl, dnsutils). It cannot install PyPI modules.

BE SELF-SUFFICIENT
- Never ask the user to run a command you can run yourself.
- Never ask the user to install something. Install it with pkg_install and carry on.
- Never ask permission in prose. The program shows its own approval prompt; just call the tool.
- Never end a turn with a question a tool could have answered.
- Stop early only if the user denied an action, or you are genuinely blocked and can say why.

EVIDENCE
- Exit code 0 is not proof. Empty output is not proof.
- Quote the tool output behind each claim.
- For anything on screen you cannot see, say the command was accepted and ask the user to look.
- Never write "Success" or a checkmark for something you did not verify.
- Never call software missing because a listing came back empty; Android hides packages.

DEBUGGING
- When something silently does nothing, diagnose instead of guessing: android_check,
  check_command, command -v X, echo "$VAR", or re-run showing output.
- Change one thing per attempt so you learn what fixed it.
- Never repeat an identical failing call.

TERMUX FACTS
- run_shell runs one command. run_python cannot execute a .sh file.
- Big file? Use grep, head, tail or wc through run_shell instead of read_file.
- Open a web page with open_url. Android can block activity starts silently.
- LAN work: local_ipv4, ssdp_discover, lan_scan, lan_probe, dial_inspect, dial_launch. Stay on this phone's /24.
- To list Wi-Fi devices with IP and MAC, call lan_scan. Do not write a ping loop.
- To identify ONE LAN IP (ping, reverse DNS, HTTP/HTTPS), call lan_probe. Do not install
  nslookup, dnsmasq, bind-tools, or getent. identity=unknown is a valid answer.
- If lan_scan.incomplete is true or count is 1, do NOT stop. Next call ssdp_discover, then
  local_ipv4. Report every IP you have, even if MAC is unknown. Permission denied on ARP is
  expected on Android, not a reason to quit.
- There is no tool named shell. The terminal tool is run_shell. If a tool is unknown, pick one from the list; do not retry the invented name even once.
- run_shell uses bash. Android often denies /proc/net/arp and ip neigh; that is not a missing-tool problem.
- Downloads and installs belong in pkg_install: run_shell has a much shorter timeout.
- Termux nslookup is package dnsutils, not bind-tools. Never install dnsmasq for DNS lookup.
- Never pkg_install pychromecast, python-*, pip, or Cast libraries. Those are not Termux packages.
- If a report file is requested, write it before you hit token/step limits. Unknown is allowed.

MEMORY
- memory_get when the goal leans on earlier facts. memory_set for durable ones like tv_ip.

LIMITS
- Stay inside the goal. Install or change nothing unrelated to it.
- Do not scan other networks or the wider internet.
- If the user denies an action, stop. Do not work around it.
'''


def safe_print(value):
    text = str(value)
    print(''.join(c if c in '\n\t' or (ord(c) >= 32 and ord(c) != 127 and not 128 <= ord(c) <= 159)
                  else repr(c)[1:-1] for c in text))


def approval(name, details):
    safe_print('\nAPPROVAL REQUIRED: ' + name)
    safe_print(json.dumps(details, indent=2, ensure_ascii=True))
    if not sys.stdin.isatty():
        return False
    try:
        return input('Type yes to approve this exact action; anything else denies: ').strip() == 'yes'
    except EOFError:
        return False


def auto_approval(name, details):
    target = details.get('path') or details.get('command') or details.get('app') or ''
    safe_print('Auto-approved for this run: %s %s' % (name, str(target)[:300]))
    return True


CONFIG_DIR = Path.home() / '.local/share/you'
CREDENTIALS_PATH = CONFIG_DIR / 'credentials.json'


def load_saved_config():
    try:
        data = json.loads(CREDENTIALS_PATH.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def save_credentials(key, base, model):
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {'YOU_API_KEY': key, 'YOU_API_BASE': base, 'YOU_MODEL': model}
    tmp = CREDENTIALS_PATH.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(payload))
    tmp.chmod(0o600)
    tmp.replace(CREDENTIALS_PATH)
    return CREDENTIALS_PATH


def api_key():
    saved = load_saved_config()
    return (os.environ.get('YOU_API_KEY')
            or os.environ.get('VYCEAI_API_KEY')
            or os.environ.get('GEMINI_API_KEY')
            or saved.get('YOU_API_KEY')
            or '')


def parse_tool_arguments(raw):
    if raw in (None, ''):
        return {}
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise ValueError('Tool arguments must be a JSON object.')
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError('Tool arguments must be a JSON object.')
    return parsed


def run_agent(provider, tools, goal, max_steps=16, max_tokens=60000, max_seconds=240):
    if not goal.strip() or len(goal) > 16000:
        raise ValueError('Goal must be between 1 and 16000 characters.')
    if min(max_steps, max_tokens, max_seconds) <= 0:
        raise ValueError('All limits must be positive.')
    facts = load_memory()
    messages = [{'role': 'user', 'content': with_memory(goal, facts)}]
    used = 0.0
    total = 0
    fail_counts = {}
    openai_tools = tools.openai_tools if hasattr(tools, 'openai_tools') else None
    for step in range(max_steps):
        if used >= max_seconds:
            save_memory(facts)
            return {'status': 'limit_reached', 'reason': 'Runtime limit', 'tokens': total}
        started = time.monotonic()
        message, usage = provider.generate(messages, SYSTEM, openai_tools)
        used += time.monotonic() - started
        total += int(usage.get('totalTokenCount', 0))
        messages.append(message)
        if total >= max_tokens:
            save_memory(facts)
            return {'status': 'limit_reached', 'reason': 'Token usage threshold', 'tokens': total}
        thought = (message.get('content') or '').strip()
        if thought and (message.get('tool_calls') or []):
            safe_print('Thinking: ' + tools.redact(thought)[:1000])
        calls = message.get('tool_calls') or []
        if not calls:
            text = thought
            if not text:
                raise ProviderError('Model returned neither visible text nor tool calls.')
            save_memory(facts)
            return {'status': 'answered', 'text': tools.redact(text), 'tokens': total, 'steps': step + 1}
        if len(calls) > 4:
            return {'status': 'limit_reached', 'reason': 'Too many tool calls in one response', 'tokens': total}
        for call in calls:
            function = call.get('function') or {}
            name = function.get('name', '')
            try:
                args = parse_tool_arguments(function.get('arguments'))
                result = tools.execute(name, args)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                result = {'ok': False, 'error': str(exc)[:1000]}
            facts = remember_from_result(facts, name, result)
            if name == 'memory_set' and result.get('ok'):
                facts = load_memory()
            if not result.get('ok'):
                sig = name + '|' + json.dumps(args, sort_keys=True, default=str)[:180]
                fail_counts[sig] = fail_counts.get(sig, 0) + 1
                if fail_counts[sig] >= 2:
                    result = dict(result)
                    result['stop'] = True
                    result['error'] = (result.get('error') or 'failed') + (
                        ' Repeated identical failure. Pick a different listed tool or stop.')
                if name == 'shell' or (isinstance(result.get('error'), str)
                                       and 'Unknown tool' in result['error']
                                       and fail_counts.get(sig, 0) >= 1):
                    result = dict(result)
                    result['stop'] = True
            status = 'ok' if result.get('ok') else 'failed/denied'
            extra = ''
            if name in ('run_python', 'run_shell') and result.get('output'):
                extra = '\n' + result['output'][:2000]
            elif name in ('local_ipv4', 'ssdp_discover', 'lan_scan', 'lan_probe', 'dial_inspect', 'dial_launch', 'think', 'memory_get', 'memory_set', 'open_url', 'android_check', 'check_command', 'pkg_install'):
                extra = '\n' + json.dumps(result, ensure_ascii=True)[:2000]
            elif not result.get('ok') and result.get('error'):
                extra = ' (' + str(result['error'])[:200] + ')'
            safe_print('Tool ' + name + ': ' + status + extra)
            messages.append({
                'role': 'tool',
                'tool_call_id': call.get('id') or name,
                'content': json.dumps(result, ensure_ascii=True),
            })
            if result.get('stop'):
                save_memory(facts)
                return {
                    'status': 'blocked',
                    'reason': result.get('error', 'blocked'),
                    'text': tools.redact(str(result.get('error', 'blocked'))),
                    'tokens': total,
                    'steps': step + 1,
                }
    save_memory(facts)
    return {'status': 'limit_reached', 'reason': 'Maximum agent steps', 'tokens': total}


def main(argv=None):
    parser = argparse.ArgumentParser(description='You: approval-controlled Termux agent (VyceAI / DeepSeek)')
    saved = load_saved_config()
    parser.add_argument('--workspace', default=os.environ.get('YOU_WORKSPACE', str(Path.home() / '.local/share/you/workspace')))
    parser.add_argument('--model', default=os.environ.get('YOU_MODEL') or saved.get('YOU_MODEL') or 'deepseek-v4-flash')
    parser.add_argument('--api-base', default=os.environ.get('YOU_API_BASE') or saved.get('YOU_API_BASE') or 'https://vyceai.com/v1')
    commands = parser.add_subparsers(dest='command', required=True)
    doctor = commands.add_parser('doctor', help='Check local configuration; --online tests the API')
    doctor.add_argument('--online', action='store_true')
    savekey = commands.add_parser('save-key', help='Save YOU_API_KEY from the environment into a private local file')
    chat = commands.add_parser('chat', help='One-shot chat without tools')
    chat.add_argument('prompt')
    run = commands.add_parser('run', help='Run a bounded goal with workspace tools')
    run.add_argument('goal')
    run.add_argument('--allow-python', '--allow-exec', dest='allow_python', action='store_true',
                     help='Expose unsandboxed run_python and run_shell; each execution still asks approval unless --yes')
    run.add_argument('--yes', action='store_true', help='Approve writes, Python, and shell for THIS run only. Not a permanent auto-approve mode.')
    run.add_argument('--max-steps', type=int, default=16)
    run.add_argument('--max-tokens', type=int, default=60000)
    run.add_argument('--max-seconds', type=int, default=240)
    args = parser.parse_args(argv)
    key = api_key()
    try:
        if args.command == 'doctor':
            root = Path(args.workspace).expanduser()
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            import tempfile
            with tempfile.TemporaryFile(dir=root) as test:
                test.write(b'workspace test')
            safe_print('Python: ' + sys.version.split()[0])
            safe_print('Workspace: ' + str(root.resolve()))
            safe_print('API base: ' + args.api_base)
            safe_print('Model: ' + args.model)
            safe_print('API key: ' + ('configured (hidden)' if key else 'missing (set YOU_API_KEY)'))
            safe_print('Android/Termux: ' + ('detected' if 'com.termux' in sys.executable else 'not detected; phone compatibility unverified'))
            if args.online:
                Provider(key, args.model, args.api_base).generate(
                    [{'role': 'user', 'content': 'Reply OK.'}], SYSTEM)
                safe_print('Online check: passed')
            else:
                safe_print('Network/model access: not tested; use doctor --online (uses API quota).')
            return 0 if key else 1
        if args.command == 'save-key':
            if not key:
                raise ValueError('Set YOU_API_KEY in this shell first, then run: you save-key')
            path = save_credentials(key, args.api_base, args.model)
            safe_print('Saved API settings privately to ' + str(path))
            safe_print('Do not copy this file. Later shells can run you without exporting the key.')
            return 0
        provider = Provider(key, args.model, args.api_base)
        if args.command == 'chat':
            if not args.prompt.strip() or len(args.prompt) > 16000:
                raise ValueError('Prompt must be between 1 and 16000 characters.')
            message, _ = provider.generate([{'role': 'user', 'content': args.prompt}], SYSTEM)
            text = (message.get('content') or '')
            safe_print(text.replace(key, '[REDACTED]') if key else text)
            return 0
        decide = auto_approval if args.yes else approval
        if args.yes:
            safe_print('Warning: --yes auto-approves writes and Python for this run only. Scripts are not sandboxed.')
        tools = Tools(args.workspace, decide, args.allow_python, key)
        result = run_agent(provider, tools, args.goal, args.max_steps, args.max_tokens, args.max_seconds)
        safe_print(result.get('text', result.get('reason', '')))
        safe_print('Status: %s | reported tokens: %s' % (result['status'], result['tokens']))
        return 0 if result['status'] == 'answered' else 2
    except KeyboardInterrupt:
        safe_print('Cancelled.')
        return 130
    except (ProviderError, OSError, ValueError) as exc:
        safe_print('Error: ' + (str(exc).replace(key, '[REDACTED]') if key else str(exc)))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
