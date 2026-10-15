#!/usr/bin/env python3
"""Public-only SSH registry and validated config writer; not a privilege boundary."""
import argparse
import base64
import binascii
import datetime as dt
import fnmatch
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import fcntl
from types import SimpleNamespace

os.umask(0o077)
SEGMENT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
HOST = re.compile(r"[a-zA-Z0-9]+(?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\Z")
VAULT_REF = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}\Z")
BACKENDS = ('bitwarden', 'keepassxc', 'apple-keychain')
APPROVAL_SWIFT = Path(__file__).with_name('biometric-approve.swift')

class Denied(Exception):
    pass

def require(condition, message):
    if not condition:
        raise Denied(message)

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def home():
    return Path.home()

def state_dir():
    return Path(os.environ.get('HERMES_HOME') or home() / '.hermes') / 'state'

def secure_dir(path):
    if path.is_symlink():
        raise Denied('state directory is a symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.stat()
    require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700,
            'state directory must be owned by caller and mode 0700')

def check_regular(path, max_bytes=1_000_000):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
            not stat.S_IMODE(st.st_mode) & 0o077 and st.st_size <= max_bytes,
            f'{path.name} must be owned regular file, mode 0600 or stricter, and size-bounded')
    return st

def read_safe(path):
    if not path.exists() and not path.is_symlink():
        return ''
    check_regular(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.read(fd, 1_000_001).decode('utf-8')
    finally:
        os.close(fd)

def append_event(path, obj):
    if path.exists() or path.is_symlink():
        check_regular(path)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (json.dumps(obj, sort_keys=True, separators=(',', ':')) + '\n').encode())
        os.fsync(fd)
    finally:
        os.close(fd)

def lock_state():
    d = state_dir()
    secure_dir(d)
    lock = d / 'ssh-keys.lock'
    if lock.exists() or lock.is_symlink():
        check_regular(lock)
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd

def registry():
    text = read_safe(state_dir() / 'ssh-keys.jsonl')
    try:
        return [json.loads(x) for x in text.splitlines() if x.strip()]
    except (ValueError, TypeError) as e:
        raise Denied('registry is malformed; do not mutate it') from e

def active(rows):
    result = {}
    for row in rows:
        if row['status'] == 'active':
            result[row['name']] = row
        elif row['status'] == 'retired':
            result.pop(row['name'], None)
        else:
            raise Denied('unknown registry status')
    return result

def valid_name(client, app, host):
    require(all(SEGMENT.fullmatch(v) and len(v) <= 32 for v in (client, app, host)),
            'client/app/host must be lowercase alphanumerics or internal hyphens (max 32)')
    return f'id_ed25519_{client}_{app}_{host}'

def fingerprint(blob):
    digest = hashlib.sha256(blob).digest()
    return 'SHA256:' + base64.b64encode(digest).decode().rstrip('=')

def parse_public(text):
    require(len(text) < 8192 and '\x00' not in text and '\r' not in text, 'invalid public key')
    lines = text.splitlines()
    require(len(lines) == 1, 'public file must contain one key line')
    fields = lines[0].split(maxsplit=2)
    require(len(fields) >= 2 and fields[0] == 'ssh-ed25519', 'only an Ed25519 public key is accepted')
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except binascii.Error as e:
        raise Denied('malformed public key encoding') from e
    # SSH wire format: string("ssh-ed25519"), string(32-byte public key).
    require(blob[:4] == b'\x00\x00\x00\x0b' and blob[4:15] == b'ssh-ed25519' and
            blob[15:19] == b'\x00\x00\x00\x20' and len(blob) == 51,
            'malformed Ed25519 SSH public key')
    comment = fields[2] if len(fields) == 3 else ''
    require(len(comment) <= 250 and all(32 <= ord(c) < 127 for c in comment),
            'public key comment must be printable ASCII')
    return fingerprint(blob), 'ssh-ed25519 ' + fields[1] + ((' ' + comment) if comment else ''), comment

def bitwarden_socket_paths():
    """Documented desktop-agent socket paths; never accept an arbitrary agent as Bitwarden."""
    paths = [home() / '.bitwarden-ssh-agent.sock']
    if sys.platform == 'darwin':
        paths.append(home() / 'Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock')
    elif sys.platform == 'linux':
        paths.extend((home() / 'snap/bitwarden/current/.bitwarden-ssh-agent.sock',
                      home() / '.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock'))
    return tuple(paths)

def socket_path(backend='bitwarden'):
    sock = os.environ.get('SSH_AUTH_SOCK', '')
    if not sock:
        return None
    path = Path(sock)
    if not path.is_absolute() or path.is_symlink():
        return None
    if backend == 'bitwarden':
        if path not in bitwarden_socket_paths():
            return None
    elif backend == 'apple-keychain':
        if sys.platform != 'darwin':
            return None
    elif backend != 'keepassxc':
        return None
    try:
        st = path.stat()
        return path if stat.S_ISSOCK(st.st_mode) and st.st_uid == os.getuid() else None
    except OSError:
        return None

def offered_fingerprints(backend='bitwarden'):
    sock = socket_path(backend)
    if sock is None:
        return set()
    try:
        p = subprocess.run(['ssh-add', '-L'], env={**os.environ, 'SSH_AUTH_SOCK': str(sock)},
                           capture_output=True, text=True, timeout=10, check=True)
        return {parse_public(x)[0] for x in p.stdout.splitlines() if x.startswith('ssh-ed25519 ')}
    except (OSError, subprocess.SubprocessError, Denied):
        return set()

def approval_available():
    if sys.platform == 'darwin':
        return bool(shutil.which('swift')) and APPROVAL_SWIFT.is_file()
    return bool(shutil.which('zenity')) and bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))

def approve(operation, name, fingerprint_value, *, detail=''):
    """Prompt out of process, returning only public approval metadata (not a sandbox)."""
    require(approval_available(), 'no interactive approval UI available; denied')
    require(len(detail) <= 512 and all(32 <= ord(c) < 127 for c in detail),
            'approval detail must be bounded printable ASCII')
    reason = f'Hermes SSH {operation}: {name} ({fingerprint_value})' + (f'\n{detail}' if detail else '')
    if sys.platform == 'darwin':
        cmd = ['swift', str(APPROVAL_SWIFT), reason]
        method = 'touch-id'
    else:
        cmd = ['zenity', '--question', '--no-wrap', '--title=Hermes SSH approval',
               '--text=' + html.escape(reason), '--timeout=600']
        method = 'local-gui'
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=600, check=False)
        require(p.returncode == 0, 'human denied, cancelled, or timed out')
        return {'method': method, 'request_id': str(uuid.uuid4())}
    except (OSError, subprocess.SubprocessError) as e:
        raise Denied('approval UI failed or timed out') from e

def audit(operation, name, fp, approval, *, outcome='success', command_sha256=None):
    event = {
        'at': now(), 'operation': operation, 'name': name, 'fingerprint': fp,
        'initiating_profile_claim': os.environ.get('HERMES_PROFILE', 'unknown'),
        'approval_method_claim': approval['method'], 'approval_request_id': approval['request_id'],
        'outcome': outcome}
    if command_sha256 is not None:
        event['command_sha256'] = command_sha256
    append_event(state_dir() / 'ssh-audit.jsonl', event)

def register(args):
    name = valid_name(args.client, args.app, args.host)
    expected = home() / '.ssh' / (name + '.pub')
    require(args.public_file is not None and args.vault_ref is not None,
            'generate the key in the selected vault UI, then supply --public-file, --vault-ref, and --backend')
    require(args.backend in BACKENDS, 'unsupported backend')
    require(args.backend != 'apple-keychain' or sys.platform == 'darwin', 'Apple Keychain is macOS-only')
    require(VAULT_REF.fullmatch(args.vault_ref) is not None, 'vault ref must be an opaque, nonsecret identifier')
    require(Path(args.public_file).is_absolute() and Path(args.public_file) == expected,
            f'public key must be exported to {expected} (no private file)')
    require(not expected.is_symlink(), 'public key may not be a symlink')
    check_regular(expected, 8192)
    fp, public, comment = parse_public(read_safe(expected))
    require(fp in offered_fingerprints(args.backend), 'public key is not offered by the selected SSH agent')
    private_path = home() / '.ssh' / name
    if args.backend == 'apple-keychain':
        require(not private_path.is_symlink(), 'private key path may not be a symlink')
        check_regular(private_path, 65536)
        # An empty passphrase is not a secret; success means this key is unencrypted.
        probe = subprocess.run(['ssh-keygen', '-y', '-P', '', '-f', str(private_path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        require(probe.returncode != 0, 'Apple Keychain backend requires a passphrase-encrypted private file')
    else:
        require(not private_path.exists() and not private_path.is_symlink(),
                'matching local private-key file exists; selected vault backend should not use it')
    fd = lock_state()
    try:
        require(name not in active(registry()), 'key name already registered; never overwrite')
        consent = approve('register-key', name, fp)
        row = {'name': name, 'fingerprint': fp, 'comment': comment, 'vault_ref': args.vault_ref,
               'backend': args.backend, 'path': str(expected), 'created_at': now(), 'rotated_from': None,
               'targets': [], 'status': 'active'}
        append_event(state_dir() / 'ssh-keys.jsonl', row)
        audit('register-key', name, fp, consent)
        return {'path': str(expected), 'fingerprint': fp, 'public_key': public,
                'vault_ref': args.vault_ref, 'backend': args.backend}
    finally:
        os.close(fd)

def search(args):
    if args.doctor:
        return {'platform': sys.platform, 'backend': args.backend,
                'bitwarden_desktop_executable': bool(shutil.which('bitwarden')),
                'bitwarden_cli_installed': bool(shutil.which('bw')),
                'keepassxc_installed': bool(shutil.which('keepassxc')),
                'supported_agent_socket_paths': [str(path) for path in bitwarden_socket_paths()]
                if args.backend == 'bitwarden' else [],
                'selected_agent_socket': socket_path(args.backend) is not None,
                'interactive_approval_ui': approval_available(),
                'vault_ui_generation_required': True, 'tailscale_bootstrap': False}
    if not state_dir().exists():
        return []
    loaded = {backend: offered_fingerprints(backend) for backend in BACKENDS}
    return [{'name': row['name'], 'fingerprint': row['fingerprint'],
             'comment': row['comment'], 'vault_ref': row['vault_ref'],
             'backend': row.get('backend', 'bitwarden'), 'targets': row['targets'],
             'agent_loaded': row['fingerprint'] in loaded.get(row.get('backend', 'bitwarden'), set())}
            for row in active(registry()).values() if args.query in row['name']]

def validate_host(value, field):
    require(len(value) <= 253 and HOST.fullmatch(value) and '..' not in value and
            not value.startswith(('-', '.')) and not value.endswith(('-', '.')) and
            all(not label.startswith('-') and not label.endswith('-') and len(label) <= 63
                for label in value.split('.')), f'invalid {field}')

def config_text(alias, dns, public_path, agent, backend='bitwarden'):
    identity_path = str(public_path).removesuffix('.pub') if backend == 'apple-keychain' else str(public_path)
    apple_options = '    UseKeychain yes\n    AddKeysToAgent yes\n' if backend == 'apple-keychain' else ''
    return (f'\nHost {alias}\n    HostName {dns}\n    IdentityFile {identity_path}\n'
            f'    IdentityAgent {agent}\n    IdentitiesOnly yes\n' + apple_options +
            '    PreferredAuthentications publickey\n    PasswordAuthentication no\n'
            '    KbdInteractiveAuthentication no\n    BatchMode yes\n'
            '    ControlMaster no\n    ControlPath none\n')

def check_host_config(text, alias, allow_exact_alias=False):
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        parts = stripped.split()
        keyword = parts[0].lower()
        require(keyword not in ('include', 'match', 'proxycommand', 'permitlocalcommand',
                                'localcommand', 'proxyjump', 'canonicalizehostname',
                                'knownhostscommand'),
                'potentially executable or indirection directive in SSH config: manual review required')
        if keyword == 'host':
            require(len(parts) > 1 and not any(
                fnmatch.fnmatchcase(alias.lower(), pattern.lower().lstrip('!')) and
                not (allow_exact_alias and len(parts) == 2 and pattern.lower() == alias.lower())
                for pattern in parts[1:]), 'matching Host pattern already exists; refused')

def write_atomic(path, data):
    fd, temp = tempfile.mkstemp(prefix='.ssh-config-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
        dirfd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(dirfd)
        finally: os.close(dirfd)
    finally:
        if os.path.exists(temp): os.unlink(temp)

def configure(args):
    validate_host(args.alias, 'alias')
    validate_host(args.hostname, 'hostname')
    sshdir = home() / '.ssh'
    require(not sshdir.is_symlink() and sshdir.is_dir() and
            sshdir.stat().st_uid == os.getuid() and stat.S_IMODE(sshdir.stat().st_mode) == 0o700,
            '~/.ssh must be owned by caller and mode 0700')
    fd = lock_state()
    try:
        rows = active(registry())
        require(args.name in rows, 'key is not registered')
        row = rows[args.name]
        require(row['fingerprint'] in offered_fingerprints(row.get('backend', 'bitwarden')),
                'key is not offered by selected SSH agent')
        keypath = Path(row['path'])
        require(keypath == sshdir / (args.name + '.pub'), 'registry public path mismatch')
        check_regular(keypath, 8192)
        require(parse_public(read_safe(keypath))[0] == row['fingerprint'], 'public key fingerprint mismatch')
        conf = sshdir / 'config'
        before = read_safe(conf)
        require(not any(c.isspace() for c in str(keypath)), 'SSH public key path cannot contain whitespace')
        agent_socket = socket_path(row.get('backend', 'bitwarden'))
        require(agent_socket is not None, 'selected SSH agent socket unavailable')
        agent_value = str(agent_socket) if row.get('backend', 'bitwarden') == 'bitwarden' else 'SSH_AUTH_SOCK'
        require(not any(c.isspace() for c in str(agent_socket)), 'SSH agent socket path cannot contain whitespace')
        block = config_text(args.alias, args.hostname, keypath, agent_value,
                            backend=row.get('backend', 'bitwarden'))
        # Validate *before* checking idempotence: a later malicious directive is never ignored.
        for line in before.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                keyword = stripped.split()[0].lower()
                require(keyword not in ('include', 'match', 'proxycommand', 'permitlocalcommand',
                                        'localcommand', 'proxyjump', 'canonicalizehostname',
                                        'knownhostscommand'), 'unsafe existing SSH config directive')
        if block.strip() in before:
            check_host_config(before, args.alias, allow_exact_alias=True)
            header = 'Host ' + args.alias + '\n'
            require(before.count(header) == 1, 'existing Host block is not unique')
            fragment = before.split(header, 1)[1].split('\nHost ', 1)[0]
            require((header + fragment).strip() == block.strip(),
                    'existing Host block differs from validated template')
            return {'status': 'unchanged', 'alias': args.alias, 'fingerprint': row['fingerprint']}
        check_host_config(before, args.alias)
        consent = approve('config-append', args.alias, row['fingerprint'])
        # Recheck source for concurrent non-skill edits; never overwrite them.
        require(read_safe(conf) == before, 'SSH config changed while awaiting approval')
        updated = before.rstrip('\n') + '\n' + block if before else block.lstrip('\n')
        write_atomic(conf, updated)
        audit('config-append', args.alias, row['fingerprint'], consent)
        append_event(state_dir() / 'ssh-keys.jsonl', {**row, 'targets': sorted(set(row['targets'] + [args.alias]))})
        return {'status': 'appended', 'alias': args.alias, 'fingerprint': row['fingerprint']}
    finally:
        os.close(fd)

def ssh_check(args):
    """Exercise plain OpenSSH publickey auth; discard remote output and diagnostic stderr."""
    validate_host(args.alias, 'alias')
    rows = active(registry()) if state_dir().exists() else {}
    candidates = [row for row in rows.values() if args.alias in row['targets']]
    require(len(candidates) == 1, 'alias must map to exactly one registered key')
    row = candidates[0]
    backend = row.get('backend', 'bitwarden')
    sock = socket_path(backend)
    require(sock is not None and row['fingerprint'] in offered_fingerprints(backend),
            'selected agent is unavailable or does not offer the registered key')
    conf = home() / '.ssh' / 'config'
    config = read_safe(conf)
    check_host_config(config, args.alias, allow_exact_alias=True)
    header = 'Host ' + args.alias + '\n'
    require(config.count(header) == 1, 'registered Host block not unique')
    body = config.split(header, 1)[1].split('\nHost ', 1)[0]
    hostname_match = re.search(r'(?m)^    HostName ([a-zA-Z0-9.-]+)$', body)
    require(hostname_match is not None, 'HostName missing from registered block')
    hostname = hostname_match.group(1)
    validate_host(hostname, 'hostname')
    agent_value = str(sock) if backend == 'bitwarden' else 'SSH_AUTH_SOCK'
    require((header + body).strip() ==
            config_text(args.alias, hostname, Path(row['path']), agent_value, backend=backend).strip(),
            'SSH config block differs from validated template')
    consent = approve('ssh-check', args.alias, row['fingerprint'])
    require(read_safe(conf) == config, 'SSH config changed during approval')
    with tempfile.NamedTemporaryFile(prefix='ssh-client-log-', mode='w+b') as diagnostic:
        cmd = ['ssh', '-vv', '-E', diagnostic.name, '-F', str(conf), '-T',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
               '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
               '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o',
               'KbdInteractiveAuthentication=no', args.alias, 'true']
        try:
            p = subprocess.run(cmd, env={**os.environ, 'SSH_AUTH_SOCK': str(sock)},
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=45, check=False)
        except (OSError, subprocess.SubprocessError) as e:
            raise Denied('SSH connection failed or timed out') from e
        diagnostic.seek(0)
        client_log = diagnostic.read(65536)
    require(p.returncode == 0 and re.search(rb'Authenticated to .* using "publickey"', client_log),
            'SSH did not complete with public-key authentication (Tailscale SSH interception is possible)')
    fd = lock_state()
    try:
        audit('ssh-check', args.alias, row['fingerprint'], consent)
    finally:
        os.close(fd)
    return {'alias': args.alias, 'fingerprint': row['fingerprint'],
            'authenticated': True, 'method': 'publickey',
            'config_sha256': hashlib.sha256(config.encode()).hexdigest()}

_SECRET_ARGUMENT = re.compile(r'(?:password|passphrase|auth.?key|token|secret|bw_session|op://)', re.I)

def validate_remote_command(argv):
    """Quote individual remote argv values; no secrets in shell/process arguments."""
    require(1 <= len(argv) <= 32 and all(isinstance(x, str) for x in argv),
            'remote command requires 1-32 arguments')
    require(re.fullmatch(r'[A-Za-z0-9_./+-]+', argv[0]) and not argv[0].startswith('-'),
            'remote executable must be an ordinary command name or path')
    require(all(x and len(x) <= 256 and all(32 <= ord(c) < 127 for c in x)
                for x in argv) and sum(map(len, argv)) <= 512,
            'remote arguments must be bounded printable ASCII without controls')
    require(not any(_SECRET_ARGUMENT.search(x) for x in argv),
            'credential-looking arguments are forbidden; use an audited remote secret transport')
    return shlex.join(argv)

def ssh_exec(args):
    """Approval-gated remote command, status only: remote stdout/stderr never returned."""
    validate_host(args.alias, 'alias')
    command = validate_remote_command(args.command)
    conf = home() / '.ssh' / 'config'
    before = read_safe(conf)
    preflight = ssh_check(SimpleNamespace(alias=args.alias))
    require(preflight['authenticated'] is True and preflight['method'] == 'publickey' and
            preflight['config_sha256'] == hashlib.sha256(before.encode()).hexdigest() and
            read_safe(conf) == before, 'SSH config or authentication changed since preflight')
    rows = active(registry())
    candidates = [row for row in rows.values() if args.alias in row['targets']]
    require(len(candidates) == 1 and candidates[0]['fingerprint'] == preflight['fingerprint'],
            'SSH key registry changed since preflight')
    row = candidates[0]
    sock = socket_path(row.get('backend', 'bitwarden'))
    require(sock is not None and row['fingerprint'] in offered_fingerprints(row.get('backend', 'bitwarden')),
            'selected SSH agent no longer offers the key')
    consent = approve('ssh-exec', args.alias, row['fingerprint'], detail=command)
    require(read_safe(conf) == before, 'SSH config changed during command approval')
    digest = hashlib.sha256(command.encode()).hexdigest()
    fd = lock_state()
    try:
        audit('ssh-exec', args.alias, row['fingerprint'], consent,
              outcome='approved', command_sha256=digest)
    finally:
        os.close(fd)
    with tempfile.NamedTemporaryFile(prefix='ssh-exec-client-log-', mode='w+b') as diagnostic:
        cmd = ['ssh', '-vv', '-E', diagnostic.name, '-F', str(conf), '-T',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
               '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
               '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
               '-o', 'KbdInteractiveAuthentication=no', args.alias, command]
        try:
            p = subprocess.run(cmd, env={**os.environ, 'SSH_AUTH_SOCK': str(sock)},
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=args.timeout, check=False)
            diagnostic.seek(0)
            client_log = diagnostic.read(65536)
            authenticated = bool(re.search(rb'Authenticated to .* using "publickey"', client_log))
            success = p.returncode == 0 and authenticated
        except (OSError, subprocess.SubprocessError):
            success = False
    fd = lock_state()
    try:
        audit('ssh-exec', args.alias, row['fingerprint'], consent,
              outcome='success' if success else 'failed', command_sha256=digest)
    finally:
        os.close(fd)
    require(success, 'remote command failed, timed out, or did not authenticate with publickey')
    return {'status': 'completed', 'alias': args.alias, 'fingerprint': row['fingerprint'],
            'command_sha256': digest, 'exit_code': 0}

def rotation_plan(args):
    require(args.plan, 'rotation is plan-only: remote verification and revocation cannot be safely automated here')
    rows = active(registry()) if state_dir().exists() else {}
    require(args.old in rows and args.new in rows and args.old != args.new, 'two distinct registered keys required')
    return {'status': 'plan_only', 'old_fingerprint': rows[args.old]['fingerprint'],
            'new_fingerprint': rows[args.new]['fingerprint'], 'targets': rows[args.old]['targets'],
            'steps': ['install successor public key on each target', 'verify successor access from independent session',
                      'revoke predecessor on each target', 'prove old signature rejected on each target',
                      'archive predecessor in vault after verification; do not assume rm -P securely erases SSDs']}

def bootstrap_plan(args):
    require(args.plan, 'bootstrap execution disabled: no verified secret-safe remote auth-key transport or rollback')
    validate_host(args.target, 'target')
    return {'status': 'plan_only', 'target': args.target,
            'steps': ['verify existing bootstrap path and remote SSH host key',
                      'check target RunSSH=false and tailnet tag ownership plus network grants',
                      'mint tagged one-off non-ephemeral auth key with short expiry in trusted broker',
                      'install tailscaled and join without secret argv/log/transcript exposure',
                      'verify tag and plain OpenSSH over MagicDNS from another session',
                      'revoke bootstrap login key on host and test old key rejection',
                      'test denied access to a non-tagged host']}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='cmd', required=True)
    gen = sub.add_parser('register'); gen.add_argument('client'); gen.add_argument('app'); gen.add_argument('host')
    gen.add_argument('--public-file'); gen.add_argument('--vault-ref')
    gen.add_argument('--backend', choices=BACKENDS, default='bitwarden')
    searcher = sub.add_parser('search'); searcher.add_argument('query', nargs='?', default=''); searcher.add_argument('--doctor', action='store_true')
    searcher.add_argument('--backend', choices=BACKENDS, default='bitwarden')
    config = sub.add_parser('config'); config.add_argument('alias'); config.add_argument('hostname'); config.add_argument('name')
    check = sub.add_parser('ssh-check'); check.add_argument('alias')
    remote = sub.add_parser('ssh-exec'); remote.add_argument('alias')
    remote.add_argument('--timeout', type=int, default=60)
    remote.add_argument('command', nargs=argparse.REMAINDER)
    rotate = sub.add_parser('rotate'); rotate.add_argument('--plan', action='store_true'); rotate.add_argument('old'); rotate.add_argument('new')
    ts = sub.add_parser('bootstrap'); ts.add_argument('--plan', action='store_true'); ts.add_argument('target')
    args = p.parse_args()
    try:
        if args.cmd == 'ssh-exec':
            require(1 <= args.timeout <= 600, 'remote timeout must be 1-600 seconds')
            if args.command and args.command[0] == '--':
                args.command.pop(0)
        value = {'register': register, 'search': search, 'config': configure,
                 'ssh-check': ssh_check, 'ssh-exec': ssh_exec,
                 'rotate': rotation_plan, 'bootstrap': bootstrap_plan}[args.cmd](args)
        print(json.dumps(value, sort_keys=True))
    except (Denied, FileNotFoundError, PermissionError, UnicodeError, KeyError) as e:
        print(json.dumps({'error': str(e), 'denied': True}), file=sys.stderr)
        return 3
    return 0

if __name__ == '__main__':
    sys.exit(main())
