"""Workspace tools. Path controls are not isolation for approved Python code."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import ssl
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
    declaration("run_shell", "Run one shell command in Termux after explicit approval. Use for am, termux-open-url, pkg, ls, ping. NOT sandboxed.",
                {"command": TEXT}, ["command"]),
    declaration("open_url", "Open an http(s) URL on this phone. Tries termux-open-url then am start. Requires approval. Exit code 0 does NOT prove the browser opened.",
                {"url": TEXT}, ["url"]),
    declaration("android_check", "Read-only Android/Termux diagnostic: which termux packages and CLIs exist, Android version. Use when a phone action silently does nothing.", {}, []),
    declaration("check_command", "Read-only: is a command installed in Termux? Returns its path or null. Call this before installing anything.",
                {"name": TEXT}, ["name"]),
    declaration("pkg_install", "Install one Termux package with pkg. Use it yourself when a command you need is missing. Requires approval. Longer timeout than run_shell.",
                {"package": TEXT}, ["package"]),
    declaration("local_ipv4", "Detect this device LAN IPv4 (not 127.0.0.1, not 0.0.0.0). No extra packages.", {}, []),
    declaration("ssdp_discover", "SSDP M-SEARCH on this LAN /24 only, up to 5 seconds. Prefer this over writing a scan script.", {}, []),
    declaration("lan_scan", "List devices on THIS phone Wi-Fi /24 with IP and MAC. Parallel ping plus ARP/SSDP. Prefer this over writing a ping loop. Stay on this LAN.", {}, []),
    declaration("lan_probe", "Identify one LAN IPv4: ping, reverse DNS, HTTP/HTTPS headers. Stay on this phone /24. Prefer this over nslookup/curl/pkg_install.",
                {"ip": TEXT}, ["ip"]),
    declaration("dial_inspect", "Read DIAL/UPnP description and YouTube app status on one LAN IPv4. Uses Application-URL. Does not launch.",
                {"ip": TEXT}, ["ip"]),
    declaration("dial_launch", "POST a DIAL launch to one LAN IPv4 app (YouTube, YouTubeLeanback, Netflix). Requires approval. Not a home-screen tap.",
                {"ip": TEXT, "app": TEXT}, ["ip", "app"]),
    declaration("think", "Write a short plan or self-check. Does not change the device.",
                {"note": TEXT}, ["note"]),
    declaration("memory_get", "Read saved facts from earlier runs (tv_ip, phone_ip).", {}, []),
    declaration("memory_set", "Save one short fact for later runs. Key like tv_ip or phone_ip.",
                {"key": TEXT, "value": TEXT}, ["key", "value"]),
]


class Tools:
    def __init__(self, workspace, approve, allow_python=False, secret="", timeout=15,
                 install_timeout=300):
        self.root = Path(workspace).expanduser().resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.approve = approve
        self.allow_python = allow_python
        self.secret = secret
        self.timeout = timeout
        self.install_timeout = install_timeout

    @property
    def declarations(self):
        return [d for d in DECLARATIONS
                if self.allow_python or d['name'] not in ('run_python', 'run_shell')]

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
                raise ValueError("Unknown tool %r. Available: %s" % (
                    name, ', '.join(sorted(expected))))
            fields = expected[name]['parameters']['required']
            if not isinstance(args, dict):
                raise ValueError("Tool arguments must be a JSON object.")
            if not fields:
                # Tools that take no arguments: drop stray keys instead of failing the step.
                args = {}
            elif not set(fields).issubset(set(args)):
                raise ValueError("Tool arguments do not match the schema. Expected: "
                                 + ', '.join(sorted(fields)))
            else:
                # Models often send extra keys (timeout, cwd). Keep only the schema fields.
                args = {k: args[k] for k in fields}
            if any(not isinstance(v, str) for v in args.values()):
                raise ValueError("Tool arguments must be strings.")
            if name == 'local_ipv4':
                return self.local_ipv4()
            if name == 'ssdp_discover':
                return self.ssdp_discover()
            if name == 'lan_scan':
                return self.lan_scan()
            if name == 'lan_probe':
                return self.lan_probe(args['ip'])
            if name == 'dial_inspect':
                return self.dial_inspect(args['ip'])
            if name == 'dial_launch':
                return self.dial_launch(args['ip'], args['app'])
            if name == 'think':
                note = args['note'].strip()
                if not note or len(note) > 1000:
                    raise ValueError('think note must be 1 to 1000 characters.')
                return {'ok': True, 'note': note}
            if name == 'memory_get':
                from .memory import load_memory
                return {'ok': True, 'facts': load_memory()}
            if name == 'memory_set':
                from .memory import load_memory, save_memory
                key = args['key'].strip()[:40]
                value = args['value'].strip()[:300]
                if not re.fullmatch(r'[a-z][a-z0-9_]{0,39}', key):
                    raise ValueError('memory key must be lowercase letters, digits, underscore.')
                facts = load_memory()
                facts[key] = value
                save_memory(facts)
                return {'ok': True, 'key': key, 'value': value}
            if name == 'run_shell':
                return self.run_shell(args['command'])
            if name == 'open_url':
                return self.open_url(args['url'])
            if name == 'android_check':
                return self.android_check()
            if name == 'check_command':
                return self.check_command(args['name'])
            if name == 'pkg_install':
                return self.pkg_install(args['package'])
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

    def _add_lan_device(self, devices, ip, local_ip, source, mac='unknown', extra=None):
        entry = devices.get(ip, {'ip': ip, 'mac': 'unknown', 'source': source, 'self': ip == local_ip})
        if mac and mac not in ('unknown', '00:00:00:00:00:00', '*'):
            entry['mac'] = mac
        if extra:
            entry.update(extra)
        if entry.get('source') and source not in entry['source']:
            entry['source'] = entry['source'] + '+' + source
        else:
            entry['source'] = source
        devices[ip] = entry

    def lan_scan(self):
        info = self.local_ipv4()
        if not info.get('ok'):
            return info
        local_ip = info['ip']
        prefix = '.'.join(local_ip.split('.')[:3])
        errors = []
        devices = {}
        env = self._child_env()

        def ping_one(i):
            ip = '%s.%d' % (prefix, i)
            try:
                proc = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=2, env=env)
                return ip if proc.returncode == 0 else None
            except (OSError, subprocess.TimeoutExpired):
                return None

        def tcp_one(i):
            ip = '%s.%d' % (prefix, i)
            for port in (80, 443, 8008, 5353):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.25)
                try:
                    err = sock.connect_ex((ip, port))
                except OSError:
                    err = -1
                finally:
                    sock.close()
                # 0 = open, 111 = ECONNREFUSED (host up, port closed)
                if err in (0, 111):
                    return ip
            return None

        with ThreadPoolExecutor(max_workers=64) as pool:
            for ip in pool.map(ping_one, range(1, 255)):
                if ip:
                    self._add_lan_device(devices, ip, local_ip, 'ping')
            for ip in pool.map(tcp_one, range(1, 255)):
                if ip:
                    self._add_lan_device(devices, ip, local_ip, 'tcp')

        try:
            arp_text = Path('/proc/net/arp').read_text()
        except OSError as exc:
            arp_text = ''
            errors.append('/proc/net/arp: %s' % exc)
        for line in arp_text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            ip, mac = parts[0], parts[3]
            if not ip.startswith(prefix + '.'):
                continue
            if mac in ('00:00:00:00:00:00', '*'):
                continue
            self._add_lan_device(devices, ip, local_ip, 'arp', mac)

        neigh = self._run_process(['ip', 'neigh', 'show'])
        if not neigh.get('ok'):
            errors.append('ip neigh: %s' % (neigh.get('output') or neigh.get('error') or 'failed'))
        else:
            for line in neigh.get('output', '').splitlines():
                parts = line.split()
                if not parts or not parts[0].startswith(prefix + '.'):
                    continue
                ip = parts[0]
                mac = parts[parts.index('lladdr') + 1] if 'lladdr' in parts else 'unknown'
                self._add_lan_device(devices, ip, local_ip, 'ip-neigh', mac)

        ssdp = self.ssdp_discover()
        for item in ssdp.get('devices') or []:
            ip = item.get('ip')
            if not ip:
                continue
            self._add_lan_device(devices, ip, local_ip, 'ssdp', extra={
                'ssdp_server': item.get('server', ''),
                'ssdp_st': item.get('st', ''),
            })

        self._add_lan_device(devices, local_ip, local_ip, 'self')
        rows = sorted(devices.values(), key=lambda d: [int(p) for p in d['ip'].split('.')])
        incomplete = len(rows) <= 1 or any('Permission denied' in e for e in errors)
        return {
            'ok': True,
            'phone_ip': local_ip,
            'subnet': info['subnet'],
            'devices': rows,
            'count': len(rows),
            'errors': errors,
            'incomplete': incomplete,
            'note': 'MAC needs ARP/netlink, which Android often denies. Live IPs still count. '
                    'If count is 1, call ssdp_discover next. Do not stop. Router DHCP is more complete.',
        }

    def _same_lan(self, ip):
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
        if ip in ('127.0.0.1', '0.0.0.0'):
            raise ValueError('Loopback is not a LAN host.')
        return local, info['subnet']

    def _http_probe(self, ip, port, use_ssl=False):
        conn = None
        try:
            if use_ssl:
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=4, context=context)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=4)
            conn.request('GET', '/', headers={'User-Agent': 'You-Termux-Agent/0.2', 'Accept': '*/*'})
            response = conn.getresponse()
            raw = response.read(2048)
            body = raw.decode('utf-8', errors='replace')
            title = ''
            match = re.search(r'<title[^>]*>([^<]{1,120})</title>', body, re.I)
            if match:
                title = match.group(1).strip()
            headers = {k.lower(): v for k, v in response.getheaders()}
            return {'ok': True, 'port': port, 'tls': use_ssl, 'status': response.status,
                    'server': headers.get('server', ''), 'title': title}
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            return {'ok': False, 'port': port, 'tls': use_ssl, 'error': str(exc)[:200]}
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    def lan_probe(self, ip):
        local, subnet = self._same_lan(ip)
        ping = self._run_process(['ping', '-c', '1', '-W', '1', ip], timeout=4)
        alive = bool(ping.get('ok'))
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            hostname = None
        http80 = self._http_probe(ip, 80, False)
        https443 = self._http_probe(ip, 443, True)
        http8008 = self._http_probe(ip, 8008, False)
        guess = 'unknown'
        evidence = []
        if hostname:
            evidence.append('ptr=' + hostname)
        for probe in (http80, https443, http8008):
            if probe.get('ok'):
                bit = ':%s status=%s' % (probe['port'], probe.get('status'))
                if probe.get('server'):
                    bit += ' server=' + probe['server']
                if probe.get('title'):
                    bit += ' title=' + probe['title']
                evidence.append(bit)
        if ip == local:
            guess = 'this phone'
        elif hostname:
            guess = hostname
        elif any(p.get('ok') and 'dial' in (p.get('server') or '').lower() for p in (http80, http8008)):
            guess = 'cast/dial device'
        return {
            'ok': True,
            'ip': ip,
            'phone_ip': local,
            'subnet': subnet,
            'alive': alive,
            'ping_output': (ping.get('output') or '')[:400],
            'hostname': hostname,
            'http': [http80, https443, http8008],
            'identity': guess,
            'evidence': evidence,
            'note': 'identity=unknown is valid. Do not install nslookup/dnsmasq/bind-tools. '
                    'Write any requested report with this JSON even if the host stays unnamed.',
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

    # Catastrophic patterns refused before the approval prompt. This is a guardrail
    # against a careless model, NOT a security boundary: approved shell is arbitrary code.
    REFUSED_SHELL = (
        r'rm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*/\s*($|;|&)',
        r'mkfs(\.|\s)',
        r'dd\s+[^|]*of=/dev/(block|sd|mmc)',
        r':\(\)\s*\{.*\};\s*:',
        r'>\s*/dev/(block|sd|mmc)',
        r'chmod\s+-R\s+777\s+/\s*($|;|&)',
    )

    def open_url(self, url):
        url = url.strip()
        if not re.fullmatch(r'https?://[^\s<>"\'\\]{1,2000}', url):
            raise ValueError('url must be a single http:// or https:// address.')
        available = {
            'termux-open-url': bool(shutil.which('termux-open-url')),
            'am': bool(shutil.which('am')),
        }
        if not any(available.values()):
            return {
                'ok': False,
                'url': url,
                'available': available,
                'error': 'Neither termux-open-url nor am is installed.',
                'hint': 'Install the Termux:API app from the same store as Termux, then: pkg install termux-api',
            }
        details = {
            'url': url,
            'available': available,
            'plan': 'Try termux-open-url, then am start, until one exits 0.',
            'warning': 'NOT SANDBOXED: launches an Android intent as your Termux user.',
        }
        if not self.approve('open_url', details):
            return {'ok': False, 'url': url, 'error': 'User denied opening the URL.'}
        attempts = []
        evidence = False
        if available['termux-open-url']:
            result = self._run_process(['termux-open-url', url])
            silent = result['ok'] and not result['output'].strip()
            attempts.append({'method': 'termux-open-url', 'exit_code': result['exit_code'],
                             'output': result['output'][:500], 'error': result['error'],
                             'silent_no_output': silent})
            evidence = result['ok'] and not silent
        # termux-open-url exits 0 even when the Termux:API app is missing or Android blocked
        # the launch. When it says nothing, fall through to am, which prints a real
        # "Starting: Intent" line or an explicit error we can show the user.
        if not evidence and available['am']:
            result = self._run_process(
                ['am', 'start', '-a', 'android.intent.action.VIEW', '-d', url])
            output = result['output']
            blocked = 'error' in output.lower() or 'not started' in output.lower()
            started = 'starting:' in output.lower()
            attempts.append({'method': 'am start', 'exit_code': result['exit_code'],
                             'output': output[:500], 'error': result['error'],
                             'reported_error_text': blocked,
                             'silent_no_output': result['ok'] and not output.strip()})
            evidence = result['ok'] and started and not blocked
        return {
            'ok': evidence,
            'url': url,
            'available': available,
            'attempts': attempts,
            'verified': False,
            'note': ('ok=true only means a command reported starting the intent. It is still not '
                     'proof the browser is on screen. If every attempt was silent with no output, '
                     'the launch was almost certainly swallowed: the Termux:API APP may not be '
                     'installed (the pkg alone is not enough), or Android 11+ blocked the activity '
                     'start because Termux lacks "Draw over other apps". Run android_check and tell '
                     'the user what is missing. Never claim the browser opened.'),
        }

    def android_check(self):
        # Fixed read-only commands, no model-supplied arguments, so no approval prompt.
        packages = self._run_process(
            ['/bin/sh', '-c', 'pm list packages 2>/dev/null | grep -i termux'])
        lines = [l.strip() for l in packages['output'].splitlines() if l.strip()]
        # Android 11+ hides other packages from a normal app, so an empty list proves nothing.
        listing_usable = bool(lines)
        # Functional probe: if the Termux:API APP is installed and permitted, this returns JSON.
        probe = self._run_process(['termux-battery-status']) if shutil.which(
            'termux-battery-status') else {'ok': False, 'output': '', 'error': 'CLI missing'}
        api_working = False
        if probe.get('ok') and probe.get('output', '').strip().startswith('{'):
            try:
                json.loads(probe['output'])
                api_working = True
            except ValueError:
                api_working = False
        if api_working:
            api_state = 'working'
        elif listing_usable:
            api_state = 'installed' if any('com.termux.api' in l for l in lines) else 'missing'
        else:
            api_state = 'unknown'
        version = self._run_process(
            ['/bin/sh', '-c', 'getprop ro.build.version.release; getprop ro.build.version.sdk'])
        release = version['output'].strip().splitlines()
        cli = {n: bool(shutil.which(n)) for n in
               ('termux-open-url', 'termux-toast', 'termux-battery-status', 'am', 'pm')}
        problems = []
        if api_state == 'missing':
            problems.append('The Termux:API app is not installed. "pkg install termux-api" only '
                            'adds the CLI. Install the Termux:API app from the SAME store as Termux.')
        elif api_state == 'unknown':
            problems.append('Could not determine whether the Termux:API app is installed: '
                            'pm list packages is filtered on Android 11+ and the battery probe '
                            'did not return JSON. Ask the user to check Settings > Apps, and to '
                            'confirm Termux and Termux:API come from the SAME store.')
        if api_state == 'working':
            problems.append('Termux:API is installed and responding. If a launch is still silent, '
                            'the cause is Android activity-start restrictions: grant Termux '
                            '"Display over other apps", and keep Termux in the foreground.')
        return {
            'ok': True,
            'termux_api_state': api_state,
            'termux_api_probe_output': probe.get('output', '')[:300],
            'package_listing_usable': listing_usable,
            'termux_packages': lines,
            'cli_available': cli,
            'android_release_and_sdk': release,
            'problems': problems,
            'note': 'termux_api_state is the reliable field. An empty package list is NOT proof '
                    'the app is missing: Android 11+ hides packages from normal apps. Never tell '
                    'the user an app is missing based only on an empty package list.',
        }

    COMMAND_PACKAGES = {
        'nslookup': 'dnsutils',
        'dig': 'dnsutils',
        'host': 'dnsutils',
        'nmap': 'nmap',
        'curl': 'curl',
        'wget': 'wget',
        'python3': None,
        'ping': None,
        'ip': None,
    }
    PKG_ALIASES = {
        'bind-tools': 'dnsutils',
        'bind9-utils': 'dnsutils',
        'bind9-dnsutils': 'dnsutils',
        'dnsutils': 'dnsutils',
    }

    def check_command(self, name):
        name = name.strip()
        if not re.fullmatch(r'[A-Za-z0-9._+-]{1,60}', name):
            raise ValueError('Invalid command name.')
        path = shutil.which(name)
        pkg = self.COMMAND_PACKAGES.get(name)
        note = 'If installed is false, install it yourself with pkg_install.'
        if pkg:
            note = 'Termux package for this command is %s, not bind-tools or dnsmasq. ' % pkg + note
        elif name in self.COMMAND_PACKAGES:
            note = 'This command is part of Termux base; do not pkg_install it.'
        elif name in ('nslookup', 'dig', 'getent'):
            note = 'Do not install a DNS server for reverse lookup. Use lan_probe instead.'
        return {
            'ok': True,
            'name': name,
            'installed': bool(path),
            'path': path,
            'pkg': pkg,
            'note': note,
        }

    def pkg_install(self, package):
        package = package.strip()
        if not re.fullmatch(r'[a-z0-9][a-z0-9._+-]{0,60}', package):
            raise ValueError('Invalid Termux package name.')
        mapped = self.PKG_ALIASES.get(package, package)
        if package == 'dnsmasq':
            return {'ok': False, 'package': package,
                    'error': 'dnsmasq is a DHCP/DNS server, not nslookup. For reverse DNS use '
                             'lan_probe. To install nslookup: pkg_install dnsutils.'}
        if not shutil.which('pkg'):
            return {'ok': False, 'package': package,
                    'error': 'pkg is not available; this does not look like Termux.'}
        details = {
            'package': mapped,
            'requested': package,
            'command': 'pkg install -y ' + mapped,
            'timeout_seconds': self.install_timeout,
            'warning': 'Installs software on this phone as your Termux user.',
        }
        if not self.approve('pkg_install', details):
            return {'ok': False, 'package': mapped, 'error': 'User denied package install.'}
        result = self._run_process(['pkg', 'install', '-y', mapped],
                                   timeout=self.install_timeout)
        output = result.get('output', '')
        return {
            'ok': result['ok'],
            'package': mapped,
            'requested': package,
            'exit_code': result['exit_code'],
            'output': output[-800:],
            'error': result.get('error'),
            'note': 'Verify with check_command afterwards. Termux nslookup is in dnsutils, not bind-tools.',
        }

    def run_shell(self, command):
        command = command.strip()
        if not command:
            raise ValueError('Empty shell command.')
        if len(command) > 4000:
            raise ValueError('Shell command exceeds 4000 characters.')
        if '\x00' in command:
            raise ValueError('Shell command contains a null byte.')
        if self.secret and self.secret in command:
            raise ValueError('Refusing to run a command containing the API key.')
        for pattern in self.REFUSED_SHELL:
            if re.search(pattern, command, re.I):
                return {'ok': False, 'error': 'Refused: command matches a catastrophic pattern.',
                        'command': command}
        details = {
            'command': command,
            'cwd': str(self.root),
            'timeout_seconds': self.timeout,
            'warning': 'NOT SANDBOXED: runs with your Termux user access and can change or delete data.',
        }
        if not self.approve('run_shell', details):
            return {'ok': False, 'error': 'User denied shell execution.', 'command': command}
        shell = shutil.which('bash') or '/bin/sh'
        result = self._run_process([shell, '-c', command])
        result['command'] = command
        if result['ok'] and not result['output'].strip():
            result['note'] = ('Exit code 0 with no output. The command ran, but this is NOT '
                              'evidence that any on-screen effect happened. Do not claim success; '
                              'ask the user to confirm, or verify with another command.')
        return result

    def run_python(self, path):
        return self._run_process([sys.executable, '-I', str(path)])

    def _child_env(self):
        # Inherit the real Termux environment. am/app_process need ANDROID_DATA, ANDROID_ROOT
        # and BOOTCLASSPATH, and termux-* helpers need TERMUX_*/LD_LIBRARY_PATH. Stripping the
        # environment made both exit 0 while doing nothing. Remove only secret-bearing values.
        env = dict(os.environ)
        for name in ('YOU_API_KEY', 'VYCEAI_API_KEY', 'GEMINI_API_KEY',
                     'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'):
            env.pop(name, None)
        if self.secret:
            for name, value in list(env.items()):
                if isinstance(value, str) and self.secret in value:
                    env.pop(name, None)
        return env

    def _run_process(self, argv, timeout=None):
        limit = self.timeout if timeout is None else timeout
        env = self._child_env()
        process = subprocess.Popen(argv, cwd=self.root,
                                   env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        captured = bytearray()
        reason = None
        start = time.monotonic()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while selector.get_map():
                if time.monotonic() - start > limit:
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
                    process.wait(timeout=max(0.01, limit - (time.monotonic() - start)))
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
