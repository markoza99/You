"""Workspace tools. Path controls are not isolation for approved Python code."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urljoin, urlparse

LIMIT = 16000


def declaration(name, description, properties, required):
    return {"name": name, "description": description, "parameters": {
        "type": "OBJECT", "properties": properties, "required": required}}


TEXT = {"type": "STRING"}
DECLARATIONS = [
    declaration("list_files", "List up to 100 entries in a workspace directory.", {"path": TEXT}, ["path"]),
    declaration("read_file", "Read a UTF-8 workspace file, up to 16000 bytes.", {"path": TEXT}, ["path"]),
    declaration("write_file", "Create or overwrite a UTF-8 file, only after user approval.",
                {"path": TEXT, "content": TEXT}, ["path", "content"]),
    declaration("run_python", "Run a workspace Python script after explicit approval. NOT sandboxed.",
                {"path": TEXT}, ["path"]),
    declaration("local_ipv4", "Detect this device LAN IPv4 (not 127.0.0.1, not 0.0.0.0). No extra packages.", {}, []),
    declaration("ssdp_discover", "SSDP M-SEARCH on this LAN /24 only, up to 5 seconds. Prefer this over writing a scan script.", {}, []),
    declaration("dial_inspect", "Read DIAL/UPnP description and YouTube app status on one LAN IPv4. Uses Application-URL. Does not launch.",
                {"ip": TEXT}, ["ip"]),
    declaration("dial_launch", "POST a DIAL launch to one LAN IPv4 app (YouTube, YouTubeLeanback, Netflix). Requires approval. Not a home-screen tap.",
                {"ip": TEXT, "app": TEXT}, ["ip", "app"]),
]


class Tools:
    def __init__(self, workspace, approve, allow_python=False, secret="", timeout=15):
        self.root = Path(workspace).expanduser().resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.approve = approve
        self.allow_python = allow_python
        self.secret = secret
        self.timeout = timeout

    @property
    def declarations(self):
        return [d for d in DECLARATIONS if self.allow_python or d['name'] != 'run_python']

    @property
    def openai_tools(self):
        converted = []
        for item in self.declarations:
            parameters = json.loads(json.dumps(item['parameters']))
            parameters['type'] = 'object'
            for prop in parameters.get('properties', {}).values():
                if isinstance(prop, dict) and prop.get('type') == 'STRING':
                    prop['type'] = 'string'
            converted.append({
                'type': 'function',
                'function': {
                    'name': item['name'],
                    'description': item['description'],
                    'parameters': parameters,
                },
            })
        return converted

    def redact(self, value):
        return value.replace(self.secret, "[REDACTED]") if self.secret else value

    def path(self, value):
        relative = Path(value)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError("Only relative workspace paths are permitted.")
        if any(p.startswith('.') for p in relative.parts if p != '.'):
            raise ValueError("Hidden paths are excluded from tools.")
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("Symlinks are excluded from tools.")
        resolved = current.resolve()
        if not resolved.is_relative_to(self.root):
            raise ValueError("Path escapes workspace.")
        return resolved

    def execute(self, name, args):
        try:
            expected = {d['name']: d for d in self.declarations}
            if name not in expected:
                raise ValueError("Unknown or disabled tool.")
            fields = expected[name]['parameters']['required']
            if not isinstance(args, dict) or set(args) != set(fields):
                raise ValueError("Tool arguments do not match the schema.")
            if any(not isinstance(v, str) for v in args.values()):
                raise ValueError("Tool arguments must be strings.")
            if name == 'local_ipv4':
                return self.local_ipv4()
            if name == 'ssdp_discover':
                return self.ssdp_discover()
            if name == 'dial_inspect':
                return self.dial_inspect(args['ip'])
            if name == 'dial_launch':
                return self.dial_launch(args['ip'], args['app'])
            if len(args['path']) > 512:
                raise ValueError("Path too long.")
            path = self.path(args['path'])
            if name == 'list_files':
                entries = []
                for i, child in enumerate(path.iterdir()):
                    if i >= 100:
                        return {"ok": True, "entries": entries, "truncated": True}
                    if not child.name.startswith('.') and not child.is_symlink():
                        entries.append(child.name + ('/' if child.is_dir() else ''))
                return {"ok": True, "entries": entries, "truncated": False}
            if name == 'read_file':
                if not path.is_file():
                    raise ValueError("Not a regular file.")
                with path.open('rb') as stream:
                    data = stream.read(LIMIT + 1)
                return {"ok": True, "content": self.redact(data[:LIMIT].decode('utf-8', errors='replace')),
                        "truncated": len(data) > LIMIT}
            if name == 'write_file':
                content = args['content'].encode('utf-8')
                if len(content) > LIMIT:
                    raise ValueError("Write exceeds 16000 bytes.")
                if self.secret and self.secret in args['content']:
                    raise ValueError("Refusing to write the API key.")
                if not self.approve('write_file', dict(args)):
                    return {"ok": False, "error": "User denied file write."}
                path = self.path(args['path'])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                return {"ok": True, "bytes": len(content), "sha256": digest,
                        "verified": digest == hashlib.sha256(content).hexdigest()}
            if path.suffix != '.py' or not path.is_file() or path.stat().st_size > LIMIT:
                raise ValueError("Expected a regular .py script no larger than 16000 bytes.")
            code = path.read_bytes()
            details = {"path": args['path'], "code": code.decode('utf-8'),
                       "cwd": str(self.root), "timeout_seconds": self.timeout,
                       "warning": "NOT SANDBOXED: can access Termux files/network and change or delete data."}
            if not self.approve('run_python', details):
                return {"ok": False, "error": "User denied Python execution."}
            if self.path(args['path']).read_bytes() != code:
                raise ValueError("Script changed after approval; refusing execution.")
            return self.run_python(path)
        except (OSError, ValueError, UnicodeError) as exc:
            return {"ok": False, "error": self.redact(str(exc))[:1000]}

    def local_ipv4(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(('1.1.1.1', 80))
            ip = sock.getsockname()[0]
        finally:
            sock.close()
        if not ip or ip.startswith('127.') or ip in ('0.0.0.0', '::'):
            return {"ok": False, "error": "Could not detect a non-loopback IPv4 address."}
        subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
        return {"ok": True, "ip": ip, "subnet": subnet,
                "note": "LAN address used to reach the internet, not a public IP."}

    def ssdp_discover(self):
        info = self.local_ipv4()
        if not info.get('ok'):
            return info
        local_ip = info['ip']
        prefix = '.'.join(local_ip.split('.')[:3]) + '.'
        message = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 2\r\n'
            'ST: ssdp:all\r\n'
            '\r\n'
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(0.4)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            try:
                sock.bind((local_ip, 0))
            except OSError:
                sock.bind(('', 0))
            sock.sendto(message.encode(), ('239.255.255.250', 1900))
            found = {}
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(65507)
                except socket.timeout:
                    continue
                ip = addr[0]
                if not ip.startswith(prefix) or ip == local_ip:
                    continue
                headers = {}
                for line in data.decode('utf-8', errors='replace').splitlines():
                    if ':' in line:
                        key, _, value = line.partition(':')
                        headers[key.strip().lower()] = value.strip()
                found[ip] = {
                    "ip": ip,
                    "server": headers.get('server', ''),
                    "st": headers.get('st', ''),
                    "usn": headers.get('usn', ''),
                }
        finally:
            sock.close()
        return {
            "ok": True,
            "phone_ip": local_ip,
            "subnet": info['subnet'],
            "devices": list(found.values()),
            "count": len(found),
            "note": "SSDP only lists devices that answer multicast. A silent Android TV often will not appear. Use the TV network page or router DHCP list.",
        }

    def _lan_peer(self, ip):
        info = self.local_ipv4()
        if not info.get('ok'):
            raise ValueError(info.get('error') or 'Could not detect this phone LAN IP.')
        local = info['ip']
        if not re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', ip):
            raise ValueError('ip must be IPv4 dotted decimal.')
        if any(int(p) > 255 for p in ip.split('.')):
            raise ValueError('Invalid IPv4 address.')
        if ip.split('.')[:3] != local.split('.')[:3]:
            raise ValueError('Target is not on this phone /24.')
        if ip in (local, '127.0.0.1', '0.0.0.0'):
            raise ValueError('Target must be another host on this LAN.')
        return local

    def _http_get(self, host, port, path, extra_headers=None):
        headers = {'Accept': '*/*', 'User-Agent': 'You-Termux-Agent/0.2 DIAL'}
        if extra_headers:
            headers.update(extra_headers)
        conn = http.client.HTTPConnection(host, port, timeout=8)
        try:
            conn.request('GET', path, headers=headers)
            response = conn.getresponse()
            body = response.read(LIMIT + 1)
            header_map = {k.lower(): v for k, v in response.getheaders()}
            return response.status, header_map, body[:LIMIT].decode('utf-8', errors='replace')
        finally:
            conn.close()

    def _xml_tag(self, xml, tag):
        match = re.search(r'<%s(?:\s[^>]*)?>([^<]+)</%s>' % (tag, tag), xml, re.I)
        return match.group(1).strip() if match else ''

    def dial_inspect(self, ip):
        self._lan_peer(ip)
        status, headers, body = self._http_get(ip, 8008, '/ssdp/device-desc.xml')
        app_base = (headers.get('application-url') or '').rstrip('/') + '/'
        parsed = urlparse(app_base) if app_base != '/' else None
        if not parsed or parsed.scheme != 'http' or parsed.hostname != ip:
            app_base = 'http://%s:8008/apps/' % ip
            parsed = urlparse(app_base)
        names = ['YouTube', 'YouTubeLeanback', 'YouTubeTV']
        apps = []
        for name in names:
            path = urlparse(urljoin(app_base, name)).path or '/'
            try:
                app_status, _, app_body = self._http_get(parsed.hostname, parsed.port or 8008, path)
            except OSError as exc:
                apps.append({'name': name, 'status': None, 'error': str(exc)[:200]})
                continue
            apps.append({'name': name, 'status': app_status, 'body': app_body[:500]})
        youtube_ok = any(a.get('status') in (200, 201, 204) for a in apps)
        return {
            'ok': status == 200,
            'ip': ip,
            'description_status': status,
            'friendly_name': self._xml_tag(body, 'friendlyName'),
            'manufacturer': self._xml_tag(body, 'manufacturer'),
            'model': self._xml_tag(body, 'modelName'),
            'application_url': app_base,
            'youtube_dial_available': youtube_ok,
            'apps': apps,
            'note': 'A YouTube icon on the TV home screen is not DIAL. 404 means this TV does not expose that DIAL app. Do not claim launch succeeded.',
        }

    def dial_launch(self, ip, app):
        self._lan_peer(ip)
        allowed = {'YouTube', 'YouTubeLeanback', 'YouTubeTV', 'Netflix'}
        if app not in allowed:
            raise ValueError('app must be one of: ' + ', '.join(sorted(allowed)))
        inspect = self.dial_inspect(ip)
        app_base = inspect['application_url']
        parsed = urlparse(app_base)
        path = urlparse(urljoin(app_base, app)).path or '/'
        details = {
            'ip': ip,
            'app': app,
            'url': 'http://%s:%s%s' % (parsed.hostname, parsed.port or 8008, path),
            'friendly_name': inspect.get('friendly_name', ''),
            'warning': 'Sends HTTP POST to this LAN TV only. Home-screen YouTube may still ignore DIAL.',
        }
        if not self.approve('dial_launch', details):
            return {'ok': False, 'error': 'User denied DIAL launch.', 'inspect': inspect}
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 8008, timeout=8)
        try:
            conn.request('POST', path, body=b'', headers={
                'Content-Type': 'text/plain; charset="utf-8"',
                'Origin': 'https://www.youtube.com',
                'User-Agent': 'You-Termux-Agent/0.2 DIAL',
            })
            response = conn.getresponse()
            body = response.read(LIMIT)
            launch_status = response.status
            launch_body = body.decode('utf-8', errors='replace')[:500]
        finally:
            conn.close()
        return {
            'ok': launch_status in (200, 201, 204),
            'ip': ip,
            'app': app,
            'launch_status': launch_status,
            'launch_body': launch_body,
            'inspect': inspect,
            'note': 'HTTP 201/200/204 means the DIAL server accepted the launch. The TV home-screen app can still stay closed.',
        }

    def run_python(self, path):
        # Minimal inherited environment; never pass API keys to the child.
        env = {k: os.environ[k] for k in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'PREFIX') if k in os.environ}
        process = subprocess.Popen([sys.executable, '-I', str(path)], cwd=self.root,
                                   env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        captured = bytearray()
        reason = None
        start = time.monotonic()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while selector.get_map():
                if time.monotonic() - start > self.timeout:
                    reason = 'Execution timed out.'
                    break
                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured.extend(chunk)
                    if len(captured) > LIMIT:
                        reason = 'Output limit exceeded.'
                        break
                if reason:
                    break
            if reason is None:
                try:
                    process.wait(timeout=max(0.01, self.timeout - (time.monotonic() - start)))
                except subprocess.TimeoutExpired:
                    reason = 'Execution timed out.'
        finally:
            # Clean up the entire process group, including children on cancellation.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            selector.close()
            process.stdout.close()
        return {"ok": reason is None and process.returncode == 0, "exit_code": process.returncode,
                "output": self.redact(bytes(captured[:LIMIT]).decode('utf-8', errors='replace')),
                "error": reason, "truncated": len(captured) > LIMIT}
