import io
import json
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
