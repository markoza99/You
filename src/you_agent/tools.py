"""Workspace tools. Path controls are not isolation for approved Python code."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import time

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
