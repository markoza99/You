import json
import pytest
from you_agent.cli import run_agent
from you_agent.tools import Tools
from you_agent.memory import remember_from_result


@pytest.fixture
def tools(tmp_path, monkeypatch):
    import you_agent.memory as memory
    monkeypatch.setattr(memory, 'CONFIG_DIR', tmp_path / 'state')
    monkeypatch.setattr(memory, 'MEMORY_PATH', tmp_path / 'state/memory.json')
    return Tools(tmp_path / 'work', lambda *_: True)


class Sequence:
    def __init__(self, messages):
        self.messages = iter(messages)
        self.seen = []

    def generate(self, messages, system, tools=None):
        self.seen.append(list(messages))
        return next(self.messages), {'totalTokenCount': 1}


def call(name, args, id='c1'):
    return {'role': 'assistant', 'tool_calls': [{
        'id': id, 'type': 'function',
        'function': {'name': name, 'arguments': json.dumps(args)}}]}


def failed_dial(monkeypatch, tools):
    monkeypatch.setattr(tools, '_lan_peer', lambda ip: '192.168.1.78')
    monkeypatch.setattr(tools, 'dial_inspect', lambda ip: {
        'ok': True, 'application_url': 'http://192.168.1.64:8008/apps/',
        'youtube_dial_available': False})
    monkeypatch.setattr(tools, '_dial_post', lambda *args: (404, ''))


def test_dial_failure_continues_to_discovery(monkeypatch, tools, capsys):
    failed_dial(monkeypatch, tools)
    seen = []
    def capabilities(ip):
        seen.append(ip)
        return {'ok': True, 'protocols_verified': False, 'ports': []}
    monkeypatch.setattr(tools, 'tv_capabilities', capabilities)
    provider = Sequence([
        call('dial_launch', {'ip': '192.168.1.64', 'app': 'YouTube'}),
        call('tv_capabilities', {'ip': '192.168.1.64'}, 'c2'),
        {'role': 'assistant', 'content': 'DIAL failed. No other protocol was verified.'}])
    result = run_agent(provider, tools, 'open YouTube on TV')
    assert result['status'] == 'answered'
    assert seen == ['192.168.1.64']
    failure = json.loads(provider.seen[1][-1]['content'])
    assert failure['error_kind'] == 'dial_launch_failed'
    assert failure['failed_method'] == 'DIAL'
    assert len(failure['attempts']) == 3
    assert 'will not open' not in failure['error']
    assert 'failed/denied' not in capsys.readouterr().out


def test_denial_stops_pending_actions(monkeypatch, tools, capsys):
    tools.approve = lambda *_: False
    message = call('write_file', {'path': 'a.txt', 'content': 'no'})
    message['tool_calls'] += call('write_file', {'path': 'b.txt', 'content': 'no'}, 'c2')['tool_calls']
    result = run_agent(Sequence([message]), tools, 'write files')
    assert result['status'] == 'blocked'
    assert not (tools.root / 'a.txt').exists()
    assert not (tools.root / 'b.txt').exists()
    assert 'Tool write_file: denied' in capsys.readouterr().out


def test_dial_denial_never_posts(monkeypatch, tools):
    failed_dial(monkeypatch, tools)
    tools.approve = lambda *_: False
    monkeypatch.setattr(tools, '_dial_post', lambda *args: pytest.fail('denied'))
    result = tools.execute('dial_launch', {'ip': '192.168.1.64', 'app': 'YouTube'})
    assert result['denied'] and result['stop']


def test_malformed_arguments_can_recover(tools):
    message = call('read_file', {})
    message['tool_calls'][0]['function']['arguments'] = '{bad json'
    provider = Sequence([message, {'role': 'assistant', 'content': 'Invalid call handled.'}])
    assert run_agent(provider, tools, 'read a file')['status'] == 'answered'
    assert json.loads(provider.seen[1][-1]['content'])['ok'] is False


@pytest.mark.parametrize('enabled', [False, True])
def test_environment_matches_enabled_tools(tools, enabled, monkeypatch):
    tools.allow_python = enabled
    monkeypatch.setenv('UNRELATED_SECRET', 'never include this')
    context = tools.execute('environment_info', {})
    assert context['enabled_tools'] == [d['name'] for d in tools.declarations]
    assert ('run_shell' in context['enabled_tools']) is enabled
    assert 'never include this' not in json.dumps(context)
    provider = Sequence([{'role': 'assistant', 'content': 'Ready.'}])
    run_agent(provider, tools, 'what can you do?')
    assert 'Runtime context (observed locally)' in provider.seen[0][0]['content']


def test_tv_probe_ports_are_only_hints(tools, monkeypatch):
    monkeypatch.setattr(tools, 'local_ipv4', lambda: {'ok': True, 'ip': '192.168.1.78'})
    seen = []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    def connect(address, timeout):
        seen.append(address)
        if address[1] == 8009: return Connection()
        raise OSError('connection refused')
    monkeypatch.setattr('you_agent.tools.socket.create_connection', connect)
    result = tools.execute('tv_capabilities', {'ip': '192.168.1.64'})
    assert result['ok'] and not result['protocols_verified']
    assert {ip for ip, port in seen} == {'192.168.1.64'}
    assert {port for ip, port in seen} == {8008, 8009, 6466, 6467, 5555}
    assert [p['port'] for p in result['ports'] if p['reachable']] == [8009]


@pytest.mark.parametrize('ip', ['10.0.0.1', '192.168.1.0', '192.168.1.255', '192.168.1.78', 'example.com'])
def test_tv_probe_rejects_invalid_targets(tools, monkeypatch, ip):
    monkeypatch.setattr(tools, 'local_ipv4', lambda: {'ok': True, 'ip': '192.168.1.78'})
    monkeypatch.setattr('you_agent.tools.socket.create_connection', lambda *a, **k: pytest.fail('must not connect'))
    assert not tools.execute('tv_capabilities', {'ip': ip})['ok']


def test_unidentified_ssdp_device_is_not_saved_as_tv():
    result = remember_from_result({}, 'ssdp_discover', {
        'ok': True, 'devices': [{'ip': '192.168.1.1', 'server': 'router'}]})
    assert 'tv_ip' not in result
