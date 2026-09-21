import io
import json
import socket
import sys
from urllib.error import HTTPError

import pytest
from you_agent.tools import Tools, LIMIT
from you_agent.cli import run_agent, main, approval, auto_approval
from you_agent.provider import Provider, ProviderError


@pytest.fixture
def tools(tmp_path):
    return Tools(tmp_path / 'work', lambda *_: True)


@pytest.mark.parametrize('path', ['../outside', '/etc/passwd', '.env', 'folder/.secret'])
def test_path_rejected(tools, path):
    assert not tools.execute('read_file', {'path': path})['ok']


def test_symlink_rejected(tools, tmp_path):
    (tools.root / 'link').symlink_to(tmp_path)
    assert not tools.execute('write_file', {'path': 'link/file', 'content': 'bad'})['ok']


def test_write_verify_read(tools):
    result = tools.execute('write_file', {'path': 'a/report.txt', 'content': 'hello'})
    assert result['verified']
    assert tools.execute('read_file', {'path': 'a/report.txt'})['content'] == 'hello'


def test_write_denied(tools):
    tools.approve = lambda *_: False
    assert not tools.execute('write_file', {'path': 'no.txt', 'content': 'no'})['ok']
    assert not (tools.root / 'no.txt').exists()


@pytest.mark.parametrize('name,args', [('shell', {}), ('read_file', {'path': 1}),
    ('read_file', {'path': 'a', 'extra': 'x'}), ('write_file', {'path': 'a'}),
    ('write_file', {'path': 'a', 'content': 'x' * (LIMIT + 1)}), ('run_python', {'path': 'a.py'})])
def test_invalid_tool_calls(tools, name, args):
    assert not tools.execute(name, args)['ok']


def test_local_ipv4_rejects_loopback(monkeypatch, tools):
    class FakeSock:
        def connect(self, addr):
            pass
        def getsockname(self):
            return ('127.0.0.1', 1)
        def close(self):
            pass
    monkeypatch.setattr('you_agent.tools.socket.socket', lambda *a, **k: FakeSock())
    result = tools.execute('local_ipv4', {})
    assert not result['ok']


def test_ssdp_same_subnet_only(monkeypatch, tools):
    class FakeSock:
        def __init__(self):
            self.sent = False
        def settimeout(self, *_):
            pass
        def setsockopt(self, *a, **k):
            pass
        def bind(self, addr):
            pass
        def connect(self, addr):
            pass
        def getsockname(self):
            return ('192.168.1.78', 1)
        def sendto(self, data, dest):
            self.sent = True
        def recvfrom(self, n):
            raise socket.timeout()
        def close(self):
            pass
    import socket as sockmod
    monkeypatch.setattr('you_agent.tools.socket.socket', lambda *a, **k: FakeSock())
    monkeypatch.setattr('you_agent.tools.socket.timeout', sockmod.timeout)
    result = tools.execute('ssdp_discover', {})
    assert result['ok']
    assert result['phone_ip'] == '192.168.1.78'
    assert result['devices'] == []


def test_dial_rejects_other_subnet(monkeypatch, tools):
    class FakeSock:
        def connect(self, addr):
            pass
        def getsockname(self):
            return ('192.168.1.78', 1)
        def close(self):
            pass
    monkeypatch.setattr('you_agent.tools.socket.socket', lambda *a, **k: FakeSock())
    result = tools.execute('dial_inspect', {'ip': '10.0.0.5'})
    assert not result['ok']


def test_dial_inspect_youtube_404(monkeypatch, tools):
    class FakeSock:
        def connect(self, addr):
            pass
        def getsockname(self):
            return ('192.168.1.78', 1)
        def close(self):
            pass

    class FakeHTTP:
        def __init__(self, host, port, timeout=None):
            self.path = None
        def request(self, method, path, headers=None, body=None):
            self.path = path
        def getresponse(self):
            path = self.path
            class Resp:
                def getheaders(self_inner):
                    return [('Application-URL', 'http://192.168.1.64:8008/apps/')]
                def read(self_inner, n=None):
                    if path.endswith('device-desc.xml'):
                        self_inner.status = 200
                        return b'<root><device><friendlyName>Android TV</friendlyName><manufacturer>SWTV</manufacturer><modelName>SWTV</modelName></device></root>'
                    self_inner.status = 404
                    return b''
            resp = Resp()
            if path.endswith('device-desc.xml'):
                resp.status = 200
            else:
                resp.status = 404
            return resp
        def close(self):
            pass
    monkeypatch.setattr('you_agent.tools.socket.socket', lambda *a, **k: FakeSock())
    monkeypatch.setattr('you_agent.tools.http.client.HTTPConnection', FakeHTTP)
    result = tools.execute('dial_inspect', {'ip': '192.168.1.64'})
    assert result['ok']
    assert result['friendly_name'] == 'Android TV'
    assert result['youtube_dial_available'] is False
    assert result['apps'][0]['status'] == 404


def test_dial_launch_denied(monkeypatch, tools):
    tools.approve = lambda *_: False
    class FakeSock:
        def connect(self, addr):
            pass
        def getsockname(self):
            return ('192.168.1.78', 1)
        def close(self):
            pass
    class FakeHTTP:
        def __init__(self, host, port, timeout=None):
            self.path = None
        def request(self, method, path, headers=None, body=None):
            self.path = path
            self.method = method
        def getresponse(self):
            class Resp:
                status = 200
                def getheaders(self_inner):
                    return [('Application-URL', 'http://192.168.1.64:8008/apps/')]
                def read(self_inner, n=None):
                    return b'<root><device><friendlyName>Android TV</friendlyName><manufacturer>SWTV</manufacturer><modelName>SWTV</modelName></device></root>'
            if getattr(self, 'method', 'GET') == 'POST':
                raise AssertionError('launch POST must not run when denied')
            return Resp()
        def close(self):
            pass
    monkeypatch.setattr('you_agent.tools.socket.socket', lambda *a, **k: FakeSock())
    monkeypatch.setattr('you_agent.tools.http.client.HTTPConnection', FakeHTTP)
    result = tools.execute('dial_launch', {'ip': '192.168.1.64', 'app': 'YouTube'})
    assert not result['ok']


def test_redaction(tools):
    tools.secret = 'test-secret'
    (tools.root / 'a').write_text('a test-secret b')
    assert 'test-secret' not in tools.execute('read_file', {'path': 'a'})['content']
    assert not tools.execute('write_file', {'path': 'b', 'content': 'test-secret'})['ok']


def test_read_limit(tools):
    (tools.root / 'a').write_text('x' * (LIMIT + 100))
    result = tools.execute('read_file', {'path': 'a'})
    assert result['truncated'] and len(result['content']) == LIMIT


def test_run_python(tools):
    tools.allow_python = True
    (tools.root / 'a.py').write_text('print(2 + 3)')
    result = tools.execute('run_python', {'path': 'a.py'})
    assert result['ok'] and result['output'].strip() == '5'


def test_run_denied(tools):
    tools.allow_python = True
    tools.approve = lambda *_: False
    (tools.root / 'a.py').write_text("open('unwanted', 'w').write('bad')")
    assert not tools.execute('run_python', {'path': 'a.py'})['ok']
    assert not (tools.root / 'unwanted').exists()


def test_timeout(tools):
    tools.allow_python = True
    tools.timeout = 0.15
    (tools.root / 'a.py').write_text('while True: pass')
    result = tools.execute('run_python', {'path': 'a.py'})
    assert not result['ok'] and 'timed out' in result['error']


def test_output_cap(tools):
    tools.allow_python = True
    (tools.root / 'a.py').write_text('while True: print("x" * 4096, flush=True)')
    result = tools.execute('run_python', {'path': 'a.py'})
    assert not result['ok'] and result['truncated'] and len(result['output']) <= LIMIT


def test_shell_hidden_unless_allowed(tools):
    names = [d['name'] for d in tools.declarations]
    assert 'run_shell' not in names
    assert not tools.execute('run_shell', {'command': 'echo hi'})['ok']
    tools.allow_python = True
    assert 'run_shell' in [d['name'] for d in tools.declarations]


def test_shell_runs_and_captures_output(tools):
    tools.allow_python = True
    result = tools.execute('run_shell', {'command': 'echo hello-shell'})
    assert result['ok'] and result['exit_code'] == 0
    assert 'hello-shell' in result['output']


def test_shell_reports_failure_for_missing_command(tools):
    tools.allow_python = True
    result = tools.execute('run_shell', {'command': 'this-command-does-not-exist-xyz'})
    assert not result['ok'] and result['exit_code'] != 0


def test_shell_denied_does_not_run(tools):
    tools.allow_python = True
    tools.approve = lambda *_: False
    result = tools.execute('run_shell', {'command': 'touch unwanted-shell'})
    assert not result['ok']
    assert not (tools.root / 'unwanted-shell').exists()


@pytest.mark.parametrize('command', ['rm -rf /', 'mkfs.ext4 /dev/block/sda', ':(){ :|:& };:'])
def test_shell_refuses_catastrophic(tools, command):
    tools.allow_python = True
    called = {'n': 0}
    def approve(*_):
        called['n'] += 1
        return True
    tools.approve = approve
    result = tools.execute('run_shell', {'command': command})
    assert not result['ok'] and 'catastrophic' in result['error']
    assert called['n'] == 0


def test_shell_refuses_command_with_secret(tools):
    tools.allow_python = True
    tools.secret = 'sk-secret-value'
    result = tools.execute('run_shell', {'command': 'curl -H "key: sk-secret-value" x'})
    assert not result['ok']
    assert 'sk-secret-value' not in json.dumps(result)


def test_shell_timeout(tools):
    tools.allow_python = True
    tools.timeout = 0.2
    result = tools.execute('run_shell', {'command': 'sleep 5'})
    assert not result['ok'] and 'timed out' in result['error']


@pytest.mark.parametrize('url', ['ftp://x.com', 'javascript:alert(1)', 'youtube.com',
                                 'https://a b.com', 'https://x.com\nrm -rf'])
def test_open_url_rejects_bad_url(tools, url):
    tools.allow_python = True
    assert not tools.execute('open_url', {'url': url})['ok']


def test_open_url_without_helpers(monkeypatch, tools):
    tools.allow_python = True
    monkeypatch.setattr('you_agent.tools.shutil.which', lambda name: None)
    result = tools.execute('open_url', {'url': 'https://youtube.com'})
    assert not result['ok']
    assert 'termux-api' in result['hint']


def test_open_url_denied_does_not_run(monkeypatch, tools):
    tools.allow_python = True
    tools.approve = lambda *_: False
    monkeypatch.setattr('you_agent.tools.shutil.which', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(Tools, '_run_process',
                        lambda self, argv: pytest.fail('must not run when denied'))
    result = tools.execute('open_url', {'url': 'https://youtube.com'})
    assert not result['ok'] and 'denied' in result['error'].lower()


def test_open_url_silent_is_not_success(monkeypatch, tools):
    tools.allow_python = True
    monkeypatch.setattr('you_agent.tools.shutil.which',
                        lambda name: '/usr/bin/termux-open-url' if name == 'termux-open-url' else None)
    monkeypatch.setattr(Tools, '_run_process', lambda self, argv: {
        'ok': True, 'exit_code': 0, 'output': '', 'error': None, 'truncated': False})
    result = tools.execute('open_url', {'url': 'https://youtube.com'})
    assert result['ok'] is False
    assert result['verified'] is False
    assert result['attempts'][0]['silent_no_output'] is True


def test_open_url_falls_through_to_am_when_silent(monkeypatch, tools):
    tools.allow_python = True
    monkeypatch.setattr('you_agent.tools.shutil.which', lambda name: '/bin/' + name)
    calls = []
    def fake(self, argv):
        calls.append(argv[0])
        if argv[0] == 'termux-open-url':
            return {'ok': True, 'exit_code': 0, 'output': '', 'error': None, 'truncated': False}
        return {'ok': True, 'exit_code': 0,
                'output': 'Starting: Intent { act=android.intent.action.VIEW }',
                'error': None, 'truncated': False}
    monkeypatch.setattr(Tools, '_run_process', fake)
    result = tools.execute('open_url', {'url': 'https://youtube.com'})
    assert calls == ['termux-open-url', 'am']
    assert result['ok'] is True
    assert result['verified'] is False


def test_android_check_flags_missing_api_app(monkeypatch, tools):
    tools.allow_python = True
    monkeypatch.setattr('you_agent.tools.shutil.which', lambda name: '/bin/' + name)
    monkeypatch.setattr(Tools, '_run_process', lambda self, argv: {
        'ok': True, 'exit_code': 0, 'output': 'package:com.termux\n',
        'error': None, 'truncated': False})
    result = tools.execute('android_check', {})
    assert result['ok'] is True
    # Listing worked and com.termux.api is absent, so "missing" is a sound conclusion here.
    assert result['package_listing_usable'] is True
    assert result['termux_api_state'] == 'missing'
    assert any('Termux:API app is not installed' in p for p in result['problems'])


def test_android_check_unknown_when_listing_empty(monkeypatch, tools):
    tools.allow_python = True
    monkeypatch.setattr('you_agent.tools.shutil.which', lambda name: '/bin/' + name)
    monkeypatch.setattr(Tools, '_run_process', lambda self, argv: {
        'ok': True, 'exit_code': 0, 'output': '', 'error': None, 'truncated': False})
    result = tools.execute('android_check', {})
    # An empty package list must never be reported as "app missing".
    assert result['termux_api_state'] == 'unknown'
    assert not any('not installed' in p for p in result['problems'])


def test_android_check_working_probe(monkeypatch, tools):
    tools.allow_python = True
    monkeypatch.setattr('you_agent.tools.shutil.which', lambda name: '/bin/' + name)
    def fake(self, argv):
        if argv[0] == 'termux-battery-status':
            return {'ok': True, 'exit_code': 0, 'output': '{"percentage": 13}',
                    'error': None, 'truncated': False}
        return {'ok': True, 'exit_code': 0, 'output': '', 'error': None, 'truncated': False}
    monkeypatch.setattr(Tools, '_run_process', fake)
    result = tools.execute('android_check', {})
    assert result['termux_api_state'] == 'working'
    assert any('Display over other apps' in p for p in result['problems'])


def test_no_arg_tools_ignore_stray_arguments(monkeypatch, tmp_path, tools):
    import you_agent.memory as mem
    monkeypatch.setattr(mem, 'MEMORY_PATH', tmp_path / 'memory.json')
    monkeypatch.setattr(mem, 'CONFIG_DIR', tmp_path)
    # The model sometimes sends stray keys; a no-arg tool must still run.
    assert tools.execute('memory_get', {'query': 'tv'})['ok']
    assert tools.execute('local_ipv4', {'unused': 'x'}) is not None


def test_open_url_detects_blocked_am(monkeypatch, tools):
    tools.allow_python = True
    monkeypatch.setattr('you_agent.tools.shutil.which',
                        lambda name: '/system/bin/am' if name == 'am' else None)
    monkeypatch.setattr(Tools, '_run_process', lambda self, argv: {
        'ok': True, 'exit_code': 0,
        'output': 'Error: Activity not started, unable to resolve Intent',
        'error': None, 'truncated': False})
    result = tools.execute('open_url', {'url': 'https://youtube.com'})
    assert result['ok'] is False
    assert result['attempts'][0]['reported_error_text'] is True


def test_shell_silent_success_gets_warning_note(tools):
    tools.allow_python = True
    result = tools.execute('run_shell', {'command': 'true'})
    assert result['ok'] and not result['output'].strip()
    assert 'NOT' in result['note'] and 'evidence' in result['note']


def test_changed_after_approval(tools):
    tools.allow_python = True
    (tools.root / 'a.py').write_text('print(1)')
    def approve(*_):
        (tools.root / 'a.py').write_text('print(2)')
        return True
    tools.approve = approve
    assert 'changed' in tools.execute('run_python', {'path': 'a.py'})['error']


class Fake:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.messages = []
    def generate(self, messages, system, tools=None):
        self.messages.append(json.loads(json.dumps(messages)))
        return next(self.replies), {'totalTokenCount': 10}


def test_loop_preserves_tool_call_id(tools):
    call = {'role': 'assistant', 'content': None, 'tool_calls': [{
        'id': 'call1', 'type': 'function',
        'function': {'name': 'write_file', 'arguments': json.dumps({'path': 'a', 'content': 'hello'})}}]}
    fake = Fake([call, {'role': 'assistant', 'content': 'Created.'}])
    result = run_agent(fake, tools, 'create a file')
    assert result['status'] == 'answered'
    assert fake.messages[1][1] == call
    assert fake.messages[1][2]['role'] == 'tool'
    assert fake.messages[1][2]['tool_call_id'] == 'call1'


def test_step_limit(tools):
    call = {'role': 'assistant', 'tool_calls': [{'id': 'c1', 'type': 'function',
        'function': {'name': 'list_files', 'arguments': '{"path": "."}'}}]}
    assert run_agent(Fake([call]), tools, 'list', max_steps=1)['status'] == 'limit_reached'


def test_token_threshold_prevents_tool(tools):
    call = {'role': 'assistant', 'tool_calls': [{'id': 'c1', 'type': 'function',
        'function': {'name': 'write_file', 'arguments': '{"path": "a", "content": "x"}'}}]}
    assert run_agent(Fake([call]), tools, 'write', max_tokens=5)['status'] == 'limit_reached'
    assert not (tools.root / 'a').exists()


def test_no_key(monkeypatch, capsys):
    monkeypatch.delenv('YOU_API_KEY', raising=False)
    monkeypatch.delenv('VYCEAI_API_KEY', raising=False)
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    assert main(['chat', 'hi']) == 1
    assert 'missing' in capsys.readouterr().out


def test_noninteractive_denial(monkeypatch):
    monkeypatch.setattr(sys, 'stdin', io.StringIO('yes\n'))
    assert not approval('write_file', {'path': 'a'})


def test_provider_request(monkeypatch):
    def urlopen(req, timeout):
        body = json.loads(req.data)
        assert req.get_header('Authorization') == 'Bearer fake'
        assert req.get_header('User-agent')
        assert 'fake' not in req.full_url
        assert body['model'] == 'deepseek-v4-flash'
        assert body['messages'][0]['role'] == 'system'
        assert body['messages'][1]['role'] == 'user'
        return io.BytesIO(json.dumps({'choices': [{'finish_reason': 'stop', 'message': {
            'role': 'assistant', 'content': 'OK'}}], 'usage': {'total_tokens': 3}}).encode())
    monkeypatch.setattr('urllib.request.urlopen', urlopen)
    message, usage = Provider('fake').generate([{'role': 'user', 'content': 'hi'}], 'system')
    assert message['content'] == 'OK'
    assert usage['totalTokenCount'] == 3


@pytest.mark.parametrize('status', [400, 401, 403, 404, 429, 500])
def test_provider_errors_do_not_leak(monkeypatch, status):
    def fail(*args, **kwargs):
        raise HTTPError('url', status, 'fake-secret', {}, None)
    monkeypatch.setattr('urllib.request.urlopen', fail)
    with pytest.raises(ProviderError) as exc:
        Provider('fake-secret').generate([], 's')
    assert 'fake-secret' not in str(exc.value)


def test_incomplete_response(monkeypatch):
    monkeypatch.setattr('urllib.request.urlopen', lambda *a, **kw: io.BytesIO(json.dumps({
        'choices': [{'finish_reason': 'length', 'message': {'role': 'assistant', 'content': 'partial'}}]}).encode()))
    with pytest.raises(ProviderError):
        Provider('fake').generate([], 's')


def test_openai_tool_schema(tools):
    schema = tools.openai_tools
    assert schema[0]['type'] == 'function'
    assert schema[0]['function']['parameters']['type'] == 'object'
    assert schema[0]['function']['parameters']['properties']['path']['type'] == 'string'


def test_auto_approval():
    assert auto_approval('write_file', {'path': 'a.py'}) is True


def test_yes_flag_uses_auto_approval(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv('YOU_API_KEY', 'fake')
    class FakeProv:
        def generate(self, messages, system, tools=None):
            return {'role': 'assistant', 'content': 'done'}, {'totalTokenCount': 1}
    monkeypatch.setattr('you_agent.cli.Provider', lambda *a, **k: FakeProv())
    assert main(['--workspace', str(tmp_path), 'run', '--yes', 'hello']) == 0
    assert 'auto-approves' in capsys.readouterr().out.lower()


def test_think_and_memory(monkeypatch, tmp_path, tools):
    import you_agent.memory as mem
    monkeypatch.setattr(mem, 'MEMORY_PATH', tmp_path / 'memory.json')
    monkeypatch.setattr(mem, 'CONFIG_DIR', tmp_path)
    assert tools.execute('think', {'note': 'use ssdp then dial'})['ok']
    assert tools.execute('memory_set', {'key': 'tv_ip', 'value': '192.168.1.64'})['ok']
    facts = tools.execute('memory_get', {})['facts']
    assert facts['tv_ip'] == '192.168.1.64'
    remembered = mem.remember_from_result({}, 'ssdp_discover', {
        'ok': True, 'phone_ip': '192.168.1.78',
        'devices': [{'ip': '192.168.1.64', 'server': 'Chromecast/1.6', 'st': 'urn:dial-multiscreen-org:device:dial:1'}],
    })
    assert remembered['tv_ip'] == '192.168.1.64'
    wrapped = mem.with_memory('open youtube', remembered)
    assert '192.168.1.64' in wrapped


def test_retry_on_520(monkeypatch):
    calls = {'n': 0}
    def urlopen(req, timeout):
        calls['n'] += 1
        if calls['n'] < 3:
            raise HTTPError('url', 520, 'cf', {}, None)
        return io.BytesIO(json.dumps({'choices': [{'finish_reason': 'stop', 'message': {
            'role': 'assistant', 'content': 'OK'}}], 'usage': {'total_tokens': 1}}).encode())
    monkeypatch.setattr('urllib.request.urlopen', urlopen)
    monkeypatch.setattr('you_agent.provider.time.sleep', lambda *_: None)
    message, _ = Provider('fake').generate([{'role': 'user', 'content': 'hi'}], 'system')
    assert message['content'] == 'OK'
    assert calls['n'] == 3
