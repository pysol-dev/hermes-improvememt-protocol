#!/usr/bin/env python3
"""Run: python3 -m unittest discover -s scripts -p 'test_*.py' -v"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('ssh_lifecycle', Path(__file__).with_name('ssh_lifecycle.py'))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home / '.ssh').mkdir(mode=0o700)
        self.state = self.home / '.hermes' / 'state'
        self.home_patch = mock.patch.object(mod, 'home', lambda: self.home)
        self.home_patch.start(); self.addCleanup(self.home_patch.stop)
        self.env_patch = mock.patch.dict(os.environ, {'HERMES_HOME': str(self.home / '.hermes')})
        self.env_patch.start(); self.addCleanup(self.env_patch.stop)
        self.name = mod.valid_name('test', 'app', 'server')
        blob = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32))
        self.public = 'ssh-ed25519 ' + base64.b64encode(blob).decode() + ' test@host'
        self.fp, _, _ = mod.parse_public(self.public)
        self.pubpath = self.home / '.ssh' / (self.name + '.pub')
        self.pubpath.write_text(self.public + '\n'); self.pubpath.chmod(0o600)
        self.approval = {'method': 'human', 'request_id': 'test-human-confirmation'}

    def test_fingerprint_matches_openssh(self):
        actual = subprocess.run(['ssh-keygen', '-lf', str(self.pubpath), '-E', 'sha256'],
                                capture_output=True, text=True, check=True)
        self.assertIn(self.fp, actual.stdout)

    def test_parser_rejects_private_and_bogus_wire(self):
        for text in ('-' * 5 + 'BEGIN OPENSSH PRIVATE KEY' + '-' * 5, 'ssh-ed25519 AAAA',
                     self.public + '\n' + self.public, 'ssh-rsa ' + self.public.split()[1],
                     self.public + '\nProxyCommand evil'):
            with self.subTest(text=text[:25]), self.assertRaises(mod.Denied):
                mod.parse_public(text)

    def test_validation_rejects_injection_and_wildcards(self):
        for bad in ('a\nProxyCommand x', 'host*', '-host', 'a..b', 'host/other'):
            with self.subTest(bad=bad), self.assertRaises(mod.Denied):
                mod.validate_host(bad, 'host')
        for existing in ('Host *\n', 'Host test*\n', 'Include ~/conf\n', 'Match exec echo\n'):
            with self.subTest(existing=existing), self.assertRaises(mod.Denied):
                mod.check_host_config(existing, 'testhost')

    def test_denied_without_approval_ui_keeps_state_unchanged(self):
        args = SimpleNamespace(client='test', app='app', host='server', public_file=str(self.pubpath), vault_ref='vault/item', backend='bitwarden', auth_method=None)
        with mock.patch.object(mod, 'offered_fingerprints', return_value={self.fp}), \
             mock.patch.object(mod, 'socket_path', return_value=self.home / '.bitwarden-ssh-agent.sock'), \
             mock.patch.object(mod, 'approval_available', return_value=False), self.assertRaises(mod.Denied):
            mod.register(args)
        self.assertFalse((self.state / 'ssh-keys.jsonl').exists())
        self.assertFalse((self.state / 'ssh-audit.jsonl').exists())
        self.assertFalse((self.home / '.ssh' / self.name).exists())

    def test_register_and_config_with_mocked_external_consent(self):
        args = SimpleNamespace(client='test', app='app', host='server', public_file=str(self.pubpath), vault_ref='vault/item', backend='bitwarden', auth_method=None)
        cfg = SimpleNamespace(alias='server', hostname='server.tailnet.ts.net', name=self.name)
        with mock.patch.object(mod, 'offered_fingerprints', return_value={self.fp}), \
             mock.patch.object(mod, 'approve', return_value=self.approval) as approved, \
             mock.patch.object(mod, 'socket_path', return_value=self.home / '.bitwarden-ssh-agent.sock'):
            row = mod.register(args)
            self.assertEqual(row['fingerprint'], self.fp)
            self.assertEqual(mod.configure(cfg)['status'], 'appended')
            self.assertEqual(mod.configure(cfg)['status'], 'unchanged')
            self.assertEqual(approved.call_count, 2)
            # An apparent exact block must not mask a wildcard that overrides it.
            existing = (self.home / '.ssh/config')
            existing.write_text('Host *\n    IdentityAgent /other/agent.sock\n' + existing.read_text())
            with self.assertRaises(mod.Denied): mod.configure(cfg)
            existing.write_text(existing.read_text().split('Host *\n    IdentityAgent /other/agent.sock\n', 1)[1])
            bad = SimpleNamespace(alias='evil\nProxyCommand run', hostname=cfg.hostname, name=self.name)
            with self.assertRaises(mod.Denied): mod.configure(bad)
        content = (self.home / '.ssh/config').read_text()
        self.assertIn('IdentityAgent ' + str(self.home / '.bitwarden-ssh-agent.sock'), content)
        self.assertIn('ControlMaster no', content)
        effective = subprocess.run(['ssh', '-G', '-F', str(self.home / '.ssh/config'), cfg.alias],
                                   capture_output=True, text=True, check=True).stdout
        self.assertIn('identityagent ' + str(self.home / '.bitwarden-ssh-agent.sock'), effective)
        self.assertIn('identitiesonly yes', effective)
        self.assertIn('hostname server.tailnet.ts.net', effective)
        self.assertIn('IdentityFile ' + str(self.pubpath), content)
        self.assertNotIn('ProxyCommand', content)
        self.assertEqual(stat.S_IMODE((self.home / '.ssh/config').stat().st_mode), 0o600)
        entries = mod.registry(); self.assertEqual(len(entries), 2)
        self.assertEqual(entries[-1]['targets'], ['server'])
        self.assertEqual(entries[-1]['auth_method'], 'M9')
        self.assertTrue(entries[-1]['exportable'])
        self.assertFalse(entries[-1]['mac_bound'])
        self.assertEqual(entries[-1]['prompt_cadence'], 'vendor-configured')
        self.assertIsNone(entries[-1]['control_persist'])
        self.assertIsNone(entries[-1]['min_openssh_server'])
        audit = (self.state / 'ssh-audit.jsonl').read_text().splitlines()
        self.assertEqual(len(audit), 2)
        self.assertEqual([json.loads(x)['operation'] for x in audit], ['register-key', 'config-append'])
        self.assertNotIn('PRIVATE KEY', json.dumps(row) + content + ''.join(audit))
        self.assertFalse((self.home / '.ssh' / self.name).exists())

    def test_config_conflict_never_overwrites_existing_file(self):
        self.state.mkdir(parents=True, mode=0o700)
        mod.append_event(self.state / 'ssh-keys.jsonl', {'name': self.name, 'fingerprint': self.fp,
            'comment': '', 'vault_ref': 'vault/item', 'backend': 'bitwarden', 'path': str(self.pubpath), 'targets': [], 'status': 'active'})
        conf = self.home / '.ssh/config'
        conf.write_text('Host *\n  ProxyCommand echo injected\n'); conf.chmod(0o600)
        with mock.patch.object(mod, 'offered_fingerprints', return_value={self.fp}), \
             mock.patch.object(mod, 'approve', return_value=self.approval) as approval:
            with self.assertRaises(mod.Denied):
                mod.configure(SimpleNamespace(alias='server', hostname='server.tailnet.ts.net', name=self.name))
            approval.assert_not_called()
        self.assertEqual(conf.read_text(), 'Host *\n  ProxyCommand echo injected\n')

    def test_confirmation_denial_and_success(self):
        with mock.patch.object(mod, 'approval_available', return_value=True), \
             mock.patch.object(mod.sys, 'platform', 'linux'), \
             mock.patch.object(mod.subprocess, 'run', return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(mod.Denied): mod.approve('register-key', self.name, self.fp)
        with mock.patch.object(mod, 'approval_available', return_value=True), \
             mock.patch.object(mod.sys, 'platform', 'linux'), \
             mock.patch.object(mod.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(mod.approve('register-key', self.name, self.fp)['method'], 'local-gui')
            self.assertIn(self.fp, run.call_args.args[0][-2])

    def test_race_does_not_overwrite_config(self):
        self.state.mkdir(parents=True, mode=0o700)
        mod.append_event(self.state / 'ssh-keys.jsonl', {'name': self.name, 'fingerprint': self.fp,
            'comment': '', 'vault_ref': 'vault/item', 'backend': 'bitwarden', 'path': str(self.pubpath), 'targets': [], 'status': 'active'})
        conf = self.home / '.ssh/config'; conf.write_text('Host other\n  HostName other.test\n'); conf.chmod(0o600)
        def racing_approval(*_args):
            conf.write_text('Host other\n  HostName changed.test\n')
            return self.approval
        with mock.patch.object(mod, 'offered_fingerprints', return_value={self.fp}), \
             mock.patch.object(mod, 'approve', side_effect=racing_approval), \
             mock.patch.object(mod, 'socket_path', return_value=self.home / '.bitwarden-ssh-agent.sock'), \
             self.assertRaises(mod.Denied):
            mod.configure(SimpleNamespace(alias='server', hostname='server.tailnet.ts.net', name=self.name))
        self.assertNotIn('Host server', conf.read_text())

    def test_backend_socket_selection(self):
        path = self.home / '.bitwarden-ssh-agent.sock'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as agent:
            agent.bind(str(path))
            with mock.patch.dict(os.environ, {'SSH_AUTH_SOCK': str(path)}):
                self.assertEqual(mod.socket_path('bitwarden'), path)
                self.assertEqual(mod.socket_path('keepassxc'), path)
                with mock.patch.object(mod.sys, 'platform', 'linux'):
                    self.assertIsNone(mod.socket_path('apple-keychain'))
                with mock.patch.object(mod.sys, 'platform', 'darwin'):
                    self.assertEqual(mod.socket_path('apple-keychain'), path)
            with mock.patch.dict(os.environ, {'SSH_AUTH_SOCK': str(self.home / 'untrusted.sock')}):
                self.assertIsNone(mod.socket_path('bitwarden'))

    def test_bitwarden_linux_snap_and_flatpak_agent_paths(self):
        if sys.platform != 'linux':
            self.skipTest('Linux sandbox paths')
        for rel in ('snap/bitwarden/current/.bitwarden-ssh-agent.sock',
                    '.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock'):
            with self.subTest(path=rel):
                sock = self.home / rel
                sock.parent.mkdir(parents=True, exist_ok=True)
                with socket.socket(socket.AF_UNIX) as server:
                    server.bind(str(sock))
                    with mock.patch.dict(os.environ, {'SSH_AUTH_SOCK': str(sock)}):
                        self.assertEqual(mod.socket_path('bitwarden'), sock)
                sock.unlink()
        sock = self.home / 'snap/another-app/current/.bitwarden-ssh-agent.sock'
        sock.parent.mkdir(parents=True, exist_ok=True)
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(sock))
            with mock.patch.dict(os.environ, {'SSH_AUTH_SOCK': str(sock)}):
                self.assertIsNone(mod.socket_path('bitwarden'))

    def test_bitwarden_doctor_distinguishes_desktop_from_optional_cli(self):
        with mock.patch.object(mod.shutil, 'which', side_effect=lambda cmd: '/snap/bin/bitwarden' if cmd == 'bitwarden' else None):
            with mock.patch.dict(os.environ, {'SSH_AUTH_SOCK': ''}):
                result = mod.search(SimpleNamespace(backend='bitwarden', doctor=True))
        self.assertTrue(result['bitwarden_desktop_executable'])
        self.assertFalse(result['bitwarden_cli_installed'])
        self.assertFalse(result['selected_agent_socket'])
        if sys.platform == 'linux':
            self.assertIn(str(self.home / 'snap/bitwarden/current/.bitwarden-ssh-agent.sock'),
                          result['supported_agent_socket_paths'])

    def test_keepassxc_uses_current_agent_not_vault_dump(self):
        args = SimpleNamespace(client='test', app='app', host='server', public_file=str(self.pubpath),
                               vault_ref='entry-id', backend='keepassxc', auth_method='M2')
        cfg = SimpleNamespace(alias='server', hostname='server.tailnet.ts.net', name=self.name)
        with mock.patch.object(mod, 'offered_fingerprints', return_value={self.fp}), \
             mock.patch.object(mod, 'approve', return_value=self.approval), \
             mock.patch.object(mod, 'socket_path', return_value=self.home / 'agent.sock'):
            self.assertEqual(mod.register(args)['backend'], 'keepassxc')
            self.assertEqual(mod.configure(cfg)['status'], 'appended')
        self.assertEqual(mod.active(mod.registry())[self.name]['auth_method'], 'M2')
        block = (self.home / '.ssh/config').read_text()
        self.assertIn('IdentityAgent SSH_AUTH_SOCK', block)
        self.assertIn('IdentityFile ' + str(self.pubpath), block)
        self.assertFalse((self.home / '.ssh' / self.name).exists())

    def test_apple_config_uses_encrypted_private_path_and_keychain(self):
        block = mod.config_text('mac', 'mac.tailnet.ts.net', self.pubpath, 'SSH_AUTH_SOCK',
                                backend='apple-keychain')
        self.assertIn('IdentityFile ' + str(self.pubpath).removesuffix('.pub'), block)
        self.assertIn('UseKeychain yes', block)
        self.assertIn('AddKeysToAgent yes', block)

    def test_apple_backend_rejects_unencrypted_private_file(self):
        private = self.home / '.ssh' / self.name
        private.write_text('fake private material'); private.chmod(0o600)
        args = SimpleNamespace(client='test', app='app', host='server', public_file=str(self.pubpath),
                               vault_ref='keychain', backend='apple-keychain', auth_method='M4')
        with mock.patch.object(mod.sys, 'platform', 'darwin'), \
             mock.patch.object(mod, 'offered_fingerprints', return_value={self.fp}), \
             mock.patch.object(mod, 'socket_path', return_value=self.home / 'agent.sock'), \
             mock.patch.object(mod.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
             mock.patch.object(mod, 'approve') as approve, self.assertRaises(mod.Denied):
            mod.register(args)
        approve.assert_not_called()
        self.assertFalse((self.state / 'ssh-keys.jsonl').exists())

    def test_auth_method_selection_is_nonmutating_and_exposes_only_supported_config(self):
        args = SimpleNamespace(platform='darwin', multi_machine='yes', human_per_use='yes',
                               existing_key='no', tailnet_ssh='no', reduce_prompts='yes', choose='M9')
        value = mod.auth_method_select(args)
        self.assertEqual(value['chosen_method'], 'M9')
        self.assertEqual(value['recommended_method'], 'M9')
        self.assertEqual({m['id'] for m in value['candidates']}, {'M1', 'M9'})
        self.assertEqual(value['modifier_suggestion'], 'M10')
        self.assertTrue(any('IdentityAgent' in line for line in value['required_config']))
        self.assertTrue(any('ControlMaster no' in line for line in value['required_config']))
        self.assertFalse(self.state.exists())

    def test_auth_method_selection_rejects_mac_bound_portability_and_tailscale_ssh(self):
        args = SimpleNamespace(platform='darwin', multi_machine='yes', human_per_use='yes',
                               existing_key='no', tailnet_ssh='no', reduce_prompts='no', choose='M5')
        with self.assertRaises(mod.Denied): mod.auth_method_select(args)
        args.platform = 'linux'; args.multi_machine = 'no'; args.existing_key = 'yes'
        args.tailnet_ssh = 'yes'; args.choose = 'M9'
        with self.assertRaises(mod.Denied): mod.auth_method_select(args)
        args.choose = 'M12'
        result = mod.auth_method_select(args)
        self.assertEqual([item['id'] for item in result['candidates']], ['M12'])
        self.assertTrue(result['key_auth_inert_on_this_path'])

    def test_selector_marks_research_and_unknown_transport_without_claiming_configuration(self):
        args = SimpleNamespace(platform='darwin', multi_machine='no', human_per_use='yes',
                               existing_key='yes', tailnet_ssh='unknown', reduce_prompts='no', choose='M8')
        result = mod.auth_method_select(args)
        self.assertEqual(result['chosen_method'], 'M8')
        self.assertEqual(result['required_config'], [])
        self.assertEqual(next(m['status'] for m in result['candidates'] if m['id'] == 'M8'), 'research-only')
        self.assertTrue(any('Verify the target SSH auth method' in w for w in result['warnings']))
        self.assertFalse(self.state.exists())

    def test_search_reads_legacy_registry_without_attesting_a_prompt(self):
        self.state.mkdir(parents=True, mode=0o700)
        mod.append_event(self.state / 'ssh-keys.jsonl', {
            'name': self.name, 'fingerprint': self.fp, 'comment': '', 'vault_ref': 'item',
            'backend': 'bitwarden', 'path': str(self.pubpath), 'targets': [], 'status': 'active'})
        with mock.patch.object(mod, 'offered_fingerprints', return_value=set()):
            result = mod.search(SimpleNamespace(doctor=False, query='test'))
        self.assertEqual(result[0]['auth_method'], 'M9')
        self.assertEqual(result[0]['prompt_cadence'], 'unverified-legacy')

    def test_registration_rejects_method_backend_mismatch_before_approval(self):
        args = SimpleNamespace(client='test', app='app', host='server', public_file=str(self.pubpath),
                               vault_ref='vault/item', backend='bitwarden', auth_method='M4')
        with mock.patch.object(mod, 'approve') as approval, self.assertRaises(mod.Denied):
            mod.register(args)
        approval.assert_not_called()
        self.assertFalse((self.state / 'ssh-keys.jsonl').exists())

    def test_ssh_check_requires_publickey_and_redacts_diagnostics(self):
        self.state.mkdir(parents=True, mode=0o700)
        row = {'name': self.name, 'fingerprint': self.fp, 'comment': '', 'vault_ref': 'vault/item',
               'backend': 'bitwarden', 'path': str(self.pubpath), 'targets': ['server'], 'status': 'active'}
        mod.append_event(self.state / 'ssh-keys.jsonl', row)
        conf = self.home / '.ssh/config'
        sock = self.home / '.bitwarden-ssh-agent.sock'
        conf.write_text(mod.config_text('server', 'server.tailnet.ts.net', self.pubpath, str(sock)).lstrip('\n'))
        conf.chmod(0o600)
        args = SimpleNamespace(alias='server')
        with mock.patch.object(mod, 'socket_path', return_value=sock), \
             mock.patch.object(mod, 'offered_fingerprints', return_value={self.fp}), \
             mock.patch.object(mod, 'approve', return_value=self.approval), \
             mock.patch.object(mod.subprocess, 'run') as run:
            def fake_ssh(auth_method):
                def invoke(argv, **_kw):
                    Path(argv[argv.index('-E') + 1]).write_bytes(
                        f'Authenticated to server using "{auth_method}".\n'.encode())
                    return SimpleNamespace(returncode=0)
                return invoke
            run.side_effect = fake_ssh('none')
            with self.assertRaises(mod.Denied): mod.ssh_check(args)
            run.side_effect = fake_ssh('publickey')
            result = mod.ssh_check(args)
            self.assertEqual(result['method'], 'publickey')
            self.assertNotIn('Authenticated', json.dumps(result))
            self.assertIn('StrictHostKeyChecking=yes', run.call_args.args[0])
        self.assertEqual(len((self.state / 'ssh-audit.jsonl').read_text().splitlines()), 1)

    def test_remote_command_validation_quotes_arguments_and_rejects_secrets(self):
        self.assertEqual(mod.validate_remote_command(['printf', '%s', 'two words']),
                         "printf %s 'two words'")
        for argv in ([], ['-o'], ['sh', '-c', 'echo\nnext'],
                     ['tailscale', 'up', '--auth-key=tskey-example'],
                     ['env', 'BW_SESSION=value'], ['printf', 'op://vault/item/password']):
            with self.subTest(argv=argv), self.assertRaises(mod.Denied):
                mod.validate_remote_command(argv)

    def test_remote_exec_checks_publickey_and_suppresses_output(self):
        self.state.mkdir(parents=True, mode=0o700)
        row = {'name': self.name, 'fingerprint': self.fp, 'comment': '', 'vault_ref': 'vault/item',
               'backend': 'bitwarden', 'path': str(self.pubpath), 'targets': ['server'], 'status': 'active'}
        mod.append_event(self.state / 'ssh-keys.jsonl', row)
        conf = self.home / '.ssh/config'
        sock = self.home / '.bitwarden-ssh-agent.sock'
        conf.write_text(mod.config_text('server', 'server.tailnet.ts.net', self.pubpath, str(sock)).lstrip('\n'))
        conf.chmod(0o600)
        args = SimpleNamespace(alias='server', command=['printf', '%s', 'two words'], timeout=60)
        seen = []
        def fake_ssh(argv, **kw):
            seen.append((argv, kw))
            Path(argv[argv.index('-E') + 1]).write_bytes(
                b'Authenticated to server using "publickey".\n')
            return SimpleNamespace(returncode=0)
        with mock.patch.object(mod, 'socket_path', return_value=sock), \
             mock.patch.object(mod, 'offered_fingerprints', return_value={self.fp}), \
             mock.patch.object(mod, 'approve', return_value=self.approval) as approved, \
             mock.patch.object(mod, 'ssh_check', return_value={'authenticated': True,
                                                                  'method': 'publickey',
                                                                  'fingerprint': self.fp,
                                                                  'config_sha256': hashlib.sha256(conf.read_bytes()).hexdigest()}) as preflight, \
             mock.patch.object(mod.subprocess, 'run', side_effect=fake_ssh):
            result = mod.ssh_exec(args)
        preflight.assert_called_once()
        self.assertEqual(approved.call_args.kwargs['detail'], "printf %s 'two words'")
        self.assertEqual(result['status'], 'completed')
        self.assertNotIn('two words', json.dumps(result))
        self.assertEqual(seen[0][0][-1], "printf %s 'two words'")
        self.assertEqual(seen[0][1]['stdout'], subprocess.DEVNULL)
        self.assertEqual(seen[0][1]['stderr'], subprocess.DEVNULL)
        events = [json.loads(x) for x in (self.state / 'ssh-audit.jsonl').read_text().splitlines()]
        self.assertEqual(events[-1]['operation'], 'ssh-exec')
        self.assertEqual(events[-1]['outcome'], 'success')
        self.assertEqual(events[-1]['command_sha256'], result['command_sha256'])

    def test_remote_exec_records_failure_and_never_exposes_remote_stderr(self):
        self.state.mkdir(parents=True, mode=0o700)
        sock = self.home / '.bitwarden-ssh-agent.sock'
        conf = self.home / '.ssh/config'
        conf.write_text(mod.config_text('server', 'server.tailnet.ts.net', self.pubpath, str(sock)).lstrip('\n'))
        conf.chmod(0o600)
        mod.append_event(self.state / 'ssh-keys.jsonl', {
            'name': self.name, 'fingerprint': self.fp, 'comment': '', 'vault_ref': 'vault/item',
            'backend': 'bitwarden', 'path': str(self.pubpath), 'targets': ['server'], 'status': 'active'})
        def denied_ssh(argv, **_kw):
            Path(argv[argv.index('-E') + 1]).write_bytes(b'Authenticated to server using "none".\n')
            return SimpleNamespace(returncode=0, stderr=b'PRIVATE KEY SHOULD NEVER LEAK')
        with mock.patch.object(mod, 'socket_path', return_value=sock), \
             mock.patch.object(mod, 'offered_fingerprints', return_value={self.fp}), \
             mock.patch.object(mod, 'approve', return_value=self.approval), \
             mock.patch.object(mod, 'ssh_check', return_value={'authenticated': True,
                 'method': 'publickey', 'fingerprint': self.fp,
                 'config_sha256': hashlib.sha256(conf.read_bytes()).hexdigest()}), \
             mock.patch.object(mod.subprocess, 'run', side_effect=denied_ssh):
            with self.assertRaisesRegex(mod.Denied, 'did not authenticate') as denied:
                mod.ssh_exec(SimpleNamespace(alias='server', command=['hostname'], timeout=60))
        self.assertNotIn('PRIVATE KEY', str(denied.exception))
        events = [json.loads(x) for x in (self.state / 'ssh-audit.jsonl').read_text().splitlines()]
        self.assertEqual([event['outcome'] for event in events], ['approved', 'failed'])

    def test_nonplan_bootstrap_and_rotation_fail_closed(self):
        with self.assertRaises(mod.Denied): mod.bootstrap_plan(mock.Mock(plan=False, target='server'))
        with self.assertRaises(mod.Denied): mod.rotation_plan(mock.Mock(plan=False, old='a', new='b'))

if __name__ == '__main__': unittest.main()
