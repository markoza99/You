"""Tests for unknown/disabled-tool recovery, repeated-failure non-termination,
partial evidence reports, and the bounded single-host host_probe tool.

All network is mocked: nothing ever leaves the process, and out-of-LAN targets are
verified to be rejected before any connection is attempted.
"""
import json

import pytest

from you_agent.cli import run_agent
from you_agent.tools import Tools


@pytest.fixture
def tools(tmp_path, monkeypatch):
    import you_agent.memory as memory
    monkeypatch.setattr(memory, 'CONFIG_DIR', tmp_path / 'state')
    monkeypatch.setattr(memory, 'MEMORY_PATH', tmp_path / 'state/memory.json')
    return Tools(tmp_path / 'work', lambda *_: True, allow_python=False)


class Sequence:
    def __init__(self, messages):
        self.messages = iter(messages)
        self.seen = []

    def generate(self, messages, system, tools=None):
        self.seen.append(list(messages))
        return next(self.messages), {'totalTokenCount': 1}


def call(name, args, cid='c1'):
    return {'role': 'assistant', 'tool_calls': [{
        'id': cid, 'type': 'function',
        'function': {'name': name, 'arguments': json.dumps(args)}}]}


def last_tool_result(provider):
    return json.loads(provider.seen[-1][-1]['content'])


def test_unknown_tool_is_structured_and_recoverable(tools):
    r = tools.execute('run_sheel', {'command': 'ls'})
    assert r['ok'] is False
    assert r['error_kind'] == 'unknown_tool'
    assert r['recoverable'] is True
    assert r['do_not_retry'] is True
    # run_shell is DISABLED (not in available_tools); the hint points to it via enabled_flag.
    assert 'run_shell' not in r['available_tools']
    assert 'environment_info' in r['available_tools']
    assert 'stop' not in r
    assert r['enabled_flag'] == '--allow-python'
    assert 'run_shell' in r['enable_hint']
    assert '--allow-python' in r['enable_hint']


def test_invented_tool_has_no_enable_flag(tools):
    r = tools.execute('fly_to_moon', {})
    assert r['error_kind'] == 'unknown_tool'
    assert 'enabled_flag' not in r
    assert 'fly_to_moon' not in r['available_tools']


def test_shell_name_maps_to_disabled_run_shell(tools):
    r = tools.execute('shell', {'command': 'ls'})
    assert r['error_kind'] == 'unknown_tool'
    assert r['enabled_flag'] == '--allow-python'


def test_unknown_tool_with_execution_enabled(tools):
    tools.allow_python = True
    r = tools.execute('run_sheel', {'command': 'ls'})
    assert r['error_kind'] == 'unknown_tool'
    assert 'run_shell' in r['available_tools']
    assert 'enabled_flag' not in r


def test_run_agent_recovers_from_first_unknown_tool(tools, capsys):
    provider = Sequence([
        call('run_sheel', {'command': 'ls'}),
        {'role': 'assistant', 'content': 'Recovered; used an enabled tool instead.'},
    ])
    result = run_agent(provider, tools, 'list files')
    assert result['status'] == 'answered'
    assert result['evidence']
    fed = last_tool_result(provider)
    assert fed['error_kind'] == 'unknown_tool'
    assert fed['recoverable'] is True
    assert fed.get('stop') is not True
    out = capsys.readouterr().out
    assert 'blocked' not in out.lower()


def test_unknown_then_enabled_tool_then_answer(tools):
    provider = Sequence([
        call('shell', {'command': 'ls'}),
        call('environment_info', {}),
        {'role': 'assistant', 'content': 'done'},
    ])
    result = run_agent(provider, tools, 'what can you do')
    assert result['status'] == 'answered'


def test_repeated_identical_failure_does_not_terminate(tools):
    msg = call('read_file', {})  # missing required 'path' -> schema error, recoverable
    provider = Sequence([msg, msg, msg, msg, msg])
    result = run_agent(provider, tools, 'read', max_steps=5)
    assert result['status'] == 'limit_reached'
    assert result['reason'] == 'Maximum agent steps'
    assert result['evidence']
    assert 'Do not repeat it' in last_tool_result(provider)['error']


def test_denial_is_terminal_and_reports(tools, capsys):
    tools.approve = lambda *_: False
    message = call('write_file', {'path': 'a.txt', 'content': 'no'})
    message['tool_calls'] += call('write_file', {'path': 'b.txt', 'content': 'no'}, 'c2')['tool_calls']
    result = run_agent(Sequence([message]), tools, 'write files')
    assert result['status'] == 'blocked'
    assert not (tools.root / 'a.txt').exists()
    assert not (tools.root / 'b.txt').exists()
    assert result.get('note')
    assert 'denied' in result['note'].lower()
    assert any(e['kind'] == 'denied' for e in result['evidence'])
    assert 'Tool write_file: denied' in capsys.readouterr().out


def test_limit_report_includes_partial_evidence(tools):
    # A model that keeps trying a disabled tool (run_shell) without --allow-python: every call
    # fails as unknown/disabled. After hitting the step budget it must produce a partial
    # evidence report (not a silent no-report) and must not take extra unsafe actions.
    msgs = [call('run_shell', {'command': 'ls %d' % i}) for i in range(10)]
    provider = Sequence(msgs)
    result = run_agent(provider, tools, 'do many things', max_steps=10)
    assert result['status'] == 'limit_reached'
    assert result['note']
    assert 'budget' in result['note'].lower()
    assert result['evidence']
    # Only disabled shell attempts were recorded; no real write/execution happened.
    assert all(e['tool'] == 'run_shell' for e in result['evidence'])
    # No files were created.
    assert not list(tools.root.iterdir())


def test_host_probe_rejects_out_of_lan_before_any_connect(tools, monkeypatch):
    monkeypatch.setattr(tools, 'local_ipv4', lambda: {'ok': True, 'ip': '192.168.1.78', 'subnet': '192.168.1.0/24'})
    monkeypatch.setattr(tools, '_run_process', lambda argv, timeout=None:
                        {'ok': False, 'exit_code': 1, 'output': '', 'error': None})
    monkeypatch.setattr('you_agent.tools.socket.create_connection',
                        lambda *a, **k: pytest.fail('must not connect out of LAN'))
    for ip in ('10.0.0.5', '8.8.8.8', '192.168.1.0', '192.168.1.255'):
        assert not tools.execute('host_probe', {'ip': ip})['ok']


def test_host_probe_rejects_loopback_self_and_non_ipv4(tools, monkeypatch):
    monkeypatch.setattr(tools, 'local_ipv4', lambda: {'ok': True, 'ip': '192.168.1.78', 'subnet': '192.168.1.0/24'})
    monkeypatch.setattr(tools, '_run_process', lambda argv, timeout=None:
                        {'ok': False, 'exit_code': 1, 'output': '', 'error': None})
    monkeypatch.setattr(tools, '_http_probe', lambda ip, port, use_ssl=False: {'ok': False})
    monkeypatch.setattr('you_agent.tools.socket.create_connection',
                        lambda *a, **k: (_ for _ in ()).throw(OSError('refused')))
    for ip in ('127.0.0.1', '192.168.1.78', 'example.com'):
        assert not tools.execute('host_probe', {'ip': ip})['ok']


def test_host_probe_targets_single_ip_and_labels_hints(tools, monkeypatch):
    monkeypatch.setattr(tools, 'local_ipv4', lambda: {'ok': True, 'ip': '192.168.1.78', 'subnet': '192.168.1.0/24'})
    monkeypatch.setattr(tools, '_run_process', lambda argv, timeout=None:
                        {'ok': True, 'exit_code': 0, 'output': '1 packets received', 'error': None})
    monkeypatch.setattr(tools, '_http_probe', lambda ip, port, use_ssl=False:
                        {'ok': port == 80, 'port': port, 'server': 'nginx' if port == 80 else '',
                         'status': 200 if port == 80 else None, 'title': 'x'})
    seen = []

    def connect(address, timeout):
        seen.append(address)
        class C:
            def __enter__(self): return self
            def __exit__(self, *a): pass
        if address[1] in (80, 443):
            return C()
        raise OSError('refused')

    monkeypatch.setattr('you_agent.tools.socket.create_connection', connect)
    r = tools.execute('host_probe', {'ip': '192.168.1.64'})
    assert r['ok'] is True
    assert r['os_fingerprint'] is False
    assert r['protocols_verified'] is False
    assert r['unimplemented'] == ['mDNS', 'SSDP', 'NetBIOS']
    assert {ip for ip, _ in seen} == {'192.168.1.64'}
    assert not any(not ip.startswith('192.168.1.') for ip, _ in seen)
    ports = {p['port'] for p in r['ports']}
    assert {80, 443, 8008, 8009, 5555, 6466, 22, 23, 8080} <= ports
    http = [p for p in r['ports'] if p['port'] == 80][0]
    assert http['reachable'] is True
    assert http['service']['banner'] == 'nginx'


def test_host_probe_caps_extra_requested_ports(tools, monkeypatch):
    monkeypatch.setattr(tools, 'local_ipv4', lambda: {'ok': True, 'ip': '192.168.1.78', 'subnet': '192.168.1.0/24'})
    monkeypatch.setattr(tools, '_run_process', lambda argv, timeout=None:
                        {'ok': False, 'exit_code': 1, 'output': '', 'error': None})
    monkeypatch.setattr('you_agent.tools.socket.create_connection',
                        lambda *a, **k: (_ for _ in ()).throw(OSError('refused')))
    monkeypatch.setattr(tools, '_http_probe', lambda ip, port, use_ssl=False: {'ok': False})
    requested = ' '.join(str(p) for p in range(9000, 9050))
    r = tools.execute('host_probe', {'ip': '192.168.1.64', 'ports': requested})
    requested_ports = {p['port'] for p in r['ports'] if p['hint'] == 'requested'}
    assert len(requested_ports) <= Tools._PROBE_MAX_PORT_ARG


def test_host_probe_in_declarations_and_environment(tools):
    assert 'host_probe' in {d['name'] for d in tools.declarations}
    assert 'host_probe' in tools.execute('environment_info', {})['enabled_tools']


