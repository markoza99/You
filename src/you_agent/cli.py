import argparse
import json
import os
from pathlib import Path
import sys
import time

from .memory import load_memory, remember_from_result, save_memory, with_memory
from .provider import Provider, ProviderError
from .tools import Tools

SYSTEM = '''You are You, a personal Termux agent. The user gives a short goal. You decide the steps.

How to work:
- Call think with a short plan before tools when the goal is more than one step.
- NEVER ask the user for permission in text. The program shows its own approval prompt.
  If you want to run something, call the tool. Asking in prose does nothing and wastes the run.
- run_shell runs one Termux command (am, termux-open-url, pkg, ls, ping, curl). Use it instead of
  writing a .sh file: you cannot execute .sh with run_python.
- Keep trying. If a tool fails, read the error, change the command, and try another way.
  Make up to 5 real attempts with different approaches before you give up.
  Never repeat the identical failing call twice in a row.
- If a needed program is missing, you may propose one install with run_shell (pkg install ...).
  The user still approves it. Do not install anything unrelated to the goal.
- Prefer built-in tools over writing scripts. Do not invent tools that are not listed.
- Use memory_get if the goal refers to earlier facts (TV IP, phone IP). Use memory_set for durable facts.
- Tool JSON is the only evidence. Quote it. Never invent hosts, files, or HTTP success.
- Writes, run_python, run_shell, and dial_launch need user approval. If the user denies, stop.
  Do not retry a denied action or work around the denial.
- Android: Termux cannot tap other apps. To open a URL on this phone, call open_url.
  Exit code 0 is NOT proof that anything appeared on screen. Android 11+ silently blocks
  activity starts from Termux unless Termux is in the foreground or has "Draw over other apps".
  After open_url, say the command was accepted and ask the user to look at the screen.
  Never write "Success", "It is now open", or a checkmark for an on-screen action you cannot see.
- Never tell the user an app is missing because a package list came back empty.
  Android hides packages from normal apps. Trust android_check's termux_api_state field.
  If every open_url attempt was silent, call android_check and report termux_api_state
  plus its problems list, instead of guessing a cause.
- Do not scan the internet or other subnets. LAN tools stay on this phone /24.
- 0.0.0.0 and 127.0.0.1 are not the phone address.
- TV / Cast: ssdp_discover or remembered tv_ip, then dial_inspect, then dial_launch only if youtube_dial_available is true. A YouTube home-screen icon is not DIAL. HTTP 404 means DIAL YouTube is not exposed; say that and stop.
- Finish with what was verified, not a long tutorial.
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


def run_agent(provider, tools, goal, max_steps=16, max_tokens=40000, max_seconds=240):
    if not goal.strip() or len(goal) > 16000:
        raise ValueError('Goal must be between 1 and 16000 characters.')
    if min(max_steps, max_tokens, max_seconds) <= 0:
        raise ValueError('All limits must be positive.')
    facts = load_memory()
    messages = [{'role': 'user', 'content': with_memory(goal, facts)}]
    used = 0.0
    total = 0
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
            status = 'ok' if result.get('ok') else 'failed/denied'
            extra = ''
            if name in ('run_python', 'run_shell') and result.get('output'):
                extra = '\n' + result['output'][:2000]
            elif name in ('local_ipv4', 'ssdp_discover', 'dial_inspect', 'dial_launch', 'think', 'memory_get', 'memory_set', 'open_url', 'android_check'):
                extra = '\n' + json.dumps(result, ensure_ascii=True)[:2000]
            elif not result.get('ok') and result.get('error'):
                extra = ' (' + str(result['error'])[:200] + ')'
            safe_print('Tool ' + name + ': ' + status + extra)
            messages.append({
                'role': 'tool',
                'tool_call_id': call.get('id') or name,
                'content': json.dumps(result, ensure_ascii=True),
            })
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
    run.add_argument('--max-tokens', type=int, default=40000)
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
