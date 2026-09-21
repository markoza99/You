"""Small durable facts for later runs. Not a vector store."""
import json
from pathlib import Path

CONFIG_DIR = Path.home() / '.local/share/you'
MEMORY_PATH = CONFIG_DIR / 'memory.json'
MAX_MEMORY_ITEMS = 40


def load_memory():
    try:
        data = json.loads(MEMORY_PATH.read_text())
        facts = data.get('facts') if isinstance(data, dict) else None
        if isinstance(facts, dict):
            return {str(k)[:40]: str(v)[:300] for k, v in list(facts.items())[:MAX_MEMORY_ITEMS]}
    except (OSError, ValueError, TypeError):
        pass
    return {}


def save_memory(facts):
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    clean = {str(k)[:40]: str(v)[:300] for k, v in list(facts.items())[:MAX_MEMORY_ITEMS]}
    tmp = MEMORY_PATH.with_suffix('.json.tmp')
    tmp.write_text(json.dumps({'facts': clean}, ensure_ascii=True, indent=2))
    tmp.chmod(0o600)
    tmp.replace(MEMORY_PATH)
    return clean


def remember_from_result(facts, name, result):
    if not result.get('ok'):
        return facts
    updated = dict(facts)
    if name == 'local_ipv4' and result.get('ip'):
        updated['phone_ip'] = result['ip']
        updated['phone_subnet'] = result.get('subnet', '')
    if name == 'lan_scan':
        if result.get('phone_ip'):
            updated['phone_ip'] = result['phone_ip']
        if result.get('subnet'):
            updated['phone_subnet'] = result['subnet']
        for device in result.get('devices') or []:
            server = (device.get('ssdp_server') or '').lower()
            if 'chromecast' in server or 'dial' in (device.get('ssdp_st') or '').lower():
                updated['tv_ip'] = device.get('ip', '')
                break
    if name == 'ssdp_discover':
        if result.get('phone_ip'):
            updated['phone_ip'] = result['phone_ip']
        devices = result.get('devices') or []
        for device in devices:
            server = (device.get('server') or '').lower()
            if 'chromecast' in server or 'dial' in (device.get('st') or '').lower():
                updated['tv_ip'] = device.get('ip', '')
                updated['tv_server'] = device.get('server', '')[:200]
                break
        if devices and 'tv_ip' not in updated:
            updated['tv_ip'] = devices[0].get('ip', '')
    if name == 'dial_inspect' and result.get('ip'):
        updated['tv_ip'] = result['ip']
        if result.get('friendly_name'):
            updated['tv_name'] = result['friendly_name']
        updated['tv_youtube_dial'] = 'yes' if result.get('youtube_dial_available') else 'no'
    return updated


def with_memory(goal, facts):
    if not facts:
        return goal
    lines = ['Known facts from earlier runs (verify with tools if the task depends on them):']
    for key, value in facts.items():
        lines.append('- %s: %s' % (key, value))
    lines.append('User goal: ' + goal)
    return '\n'.join(lines)
