"""Installer boundaries and rollback behavior in temporary filesystems only."""
from contextlib import ExitStack, nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location('release_install', Path(__file__).parents[1] / 'install.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ReleaseInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.app, self.etc = self.root / 'app', self.root / 'etc'
        self.state, self.system = self.root / 'state', self.root / 'system'
        self.backups, self.stage = self.root / 'backups', self.root / 'stage'
        for directory in (self.app, self.etc, self.state, self.system, self.backups, self.stage):
            directory.mkdir()
        self.receipt = self.state / 'release.json'
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (('APP', self.app), ('ETC', self.etc), ('STATE', self.state),
                            ('RECEIPT', self.receipt), ('BACKUPS', self.backups)):
            self.stack.enter_context(patch.object(installer, name, value))
        self.stack.enter_context(patch.object(installer, 'destination', side_effect=self.destination))
        self.stack.enter_context(patch.object(installer.os, 'O_NOFOLLOW', getattr(installer.os, 'O_NOFOLLOW', 0), create=True))
        # No test may execute a real service, firewall or network command.
        self.run = self.stack.enter_context(patch.object(installer, 'run', side_effect=self.command))
        self.health = self.stack.enter_context(patch.object(installer, 'health'))
        self.stack.enter_context(patch.object(installer, 'validate_code'))
        self.stack.enter_context(patch.object(installer, 'assert_no_pairing'))

    @staticmethod
    def command(args, *, check=True, **kwargs):
        if not check:
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        return ''

    def destination(self, name):
        category, leaf = name.split('/')
        return {'app': self.app, 'system': self.system}[category] / leaf

    def release(self):
        required = {'install.py', 'README.md', 'app/geobox.py', 'app/ios_device_bridge.py',
                    'app/ios_pairing_worker.py', *('system/' + n for n in installer.SYSTEM),
                    *('app/' + n for n in installer.NETWORK)}
        files = {}
        for name in sorted(required):
            source = self.stage / name
            source.parent.mkdir(parents=True, exist_ok=True)
            data = ('synthetic ' + name + '\n').encode()
            source.write_bytes(data)
            files[name] = sha(data)
        manifest = {'format': 1, 'files': files}
        (self.stage / 'manifest.json').write_text(json.dumps(manifest))
        return manifest

    def installed(self):
        manifest = self.release()
        for name in manifest['files']:
            if name.startswith(('app/', 'system/')):
                self.destination(name).write_bytes((self.stage / name).read_bytes())
        self.receipt.write_text(json.dumps(manifest))
        return manifest

    def changed_release(self):
        old = self.installed()
        new = json.loads(json.dumps(old))
        for name, data in {'app/geobox.py': b'updated panel\n', 'app/new_feature.py': b'new feature\n'}.items():
            (self.stage / name).write_bytes(data)
            new['files'][name] = sha(data)
        (self.stage / 'manifest.json').write_text(json.dumps(new))
        return old, new

    def backup(self, old=b'old', new=b'new', fresh=False):
        (self.stage / 'install.py').write_text('# synthetic recovery entry point\n')
        existing, added = self.app / 'existing.py', self.app / 'added.py'
        existing.write_bytes(old)
        backup = installer.make_backup(self.stage, {existing: new, added: b'added'}, fresh, 'test-profile')
        existing.write_bytes(new)
        added.write_bytes(b'added')
        return backup, existing, added

    def test_valid_release_copied_and_verified_in_private_stage(self):
        expected = self.release()
        output = self.root / 'private-stage'
        output.mkdir()
        result = installer.copy_verified(self.stage, output)
        self.assertEqual(result, expected)
        self.assertEqual(installer.verify_release(output), expected)
        self.run.assert_not_called()

    def test_corrupt_payload_rejected(self):
        self.release()
        (self.stage / 'app/geobox.py').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            installer.verify_release(self.stage)

    def test_guide_images_are_copied_and_checksum_verified(self):
        manifest = self.release()
        for name in installer.GUIDE_ASSETS:
            path = self.stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic-image')
            manifest['files'][name] = sha(path.read_bytes())
        (self.stage / 'manifest.json').write_text(json.dumps(manifest))
        output = self.root / 'with-guides'
        output.mkdir()
        installer.copy_verified(self.stage, output)
        for name in installer.GUIDE_ASSETS:
            self.assertEqual((output / name).read_bytes(), b'synthetic-image')
        (self.stage / next(iter(installer.GUIDE_ASSETS))).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            installer.verify_release(self.stage)

    def test_guide_ancestor_symlink_is_rejected(self):
        manifest = self.release()
        name = 'docs/images/setup-en.png'
        outside = self.root / 'outside-docs'
        (outside / 'images').mkdir(parents=True)
        (outside / 'images/setup-en.png').write_bytes(b'synthetic-image')
        try:
            (self.stage / 'docs').symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('Host does not permit creating directory symlinks')
        manifest['files'][name] = sha(b'synthetic-image')
        (self.stage / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            installer.verify_release(self.stage)

    def test_incomplete_release_rejected(self):
        manifest = self.release()
        del manifest['files']['app/ios_device_bridge.py']
        (self.stage / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            installer.verify_release(self.stage)

    def test_manifest_path_traversal_and_unknown_system_file_rejected(self):
        for bad in ('app/../../secret.py', '/absolute.py', 'app/subdir/module.py',
                    'app/../x.py', 'system/ssh_config', 'app/remote_phone.plist',
                    'docs/images/other.png', 'docs/images/../../../secret.png',
                    'docs/images/setup-en.svg', 'docs/script.py'):
            with self.subTest(path=bad):
                manifest = self.release()
                manifest['files'][bad] = 'a' * 64
                (self.stage / 'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, 'Unexpected'):
                    installer.verify_release(self.stage)

    def test_release_symlink_rejected(self):
        self.release()
        original = self.stage / 'app/geobox.py'
        moved = self.root / 'external.py'
        original.rename(moved)
        try:
            original.symlink_to(moved)
        except OSError:
            self.skipTest('Host does not permit creating symlinks')
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            installer.verify_release(self.stage)

    def test_update_refuses_network_or_system_change(self):
        old = self.installed()
        for name in ('app/geobox.nft', 'app/net-up.sh', 'system/geobox-panel.service', 'system/geobox.conf'):
            with self.subTest(path=name):
                new = json.loads(json.dumps(old))
                new['files'][name] = 'b' * 64
                with self.assertRaisesRegex(RuntimeError, 'dedicated migration'):
                    installer.update_plan(new, old)

    def test_update_refuses_local_code_and_system_edits(self):
        for name in ('app/geobox.py', 'system/geobox.conf'):
            with self.subTest(path=name):
                old = self.installed()
                self.destination(name).write_bytes(b'local change')
                with self.assertRaisesRegex(RuntimeError, 'edited locally'):
                    installer.update_plan(old, old)

    def test_update_refuses_removing_module(self):
        old = self.installed()
        new = json.loads(json.dumps(old))
        del new['files']['app/ios_device_bridge.py']
        with self.assertRaisesRegex(RuntimeError, 'Removing installed modules'):
            installer.update_plan(new, old)

    def test_update_refuses_existing_untracked_new_module(self):
        old, new = self.changed_release()
        self.destination('app/new_feature.py').write_bytes(b'private locally maintained module')
        with self.assertRaises(RuntimeError):
            installer.update_plan(new, old)

    def test_update_preserves_configuration_pairing_and_network_files(self):
        old, new = self.changed_release()
        (self.etc / 'proxy.json').write_bytes(b'synthetic private credentials')
        records = self.state / 'ios'
        records.mkdir()
        (records / 'remote_synthetic.plist').write_bytes(b'synthetic pairing key')
        preserved = {p: p.read_bytes() for p in (self.etc / 'proxy.json', records / 'remote_synthetic.plist',
                                                self.app / 'geobox.nft', self.system / 'geobox.conf')}
        with patch.object(installer, 'mutation_guard', side_effect=nullcontext):
            installer.apply_release(self.stage, new)
        for path, content in preserved.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertEqual((self.app / 'geobox.py').read_bytes(), b'updated panel\n')
        self.assertEqual((self.app / 'new_feature.py').read_bytes(), b'new feature\n')
        self.assertEqual(json.loads(self.receipt.read_text()), new)
        self.assertTrue(any(self.backups.glob('release-*/COMMITTED')))
        commands = [call.args[0] for call in self.run.call_args_list]
        self.assertFalse(any(command[0] in ('nmcli', 'nft', 'ip', 'sysctl') for command in commands))

    def test_rollback_restores_previous_file_and_removes_new_file(self):
        backup, existing, added = self.backup()
        installer.restore(backup)
        self.assertEqual(existing.read_bytes(), b'old')
        self.assertFalse(added.exists())
        self.assertTrue((backup / 'ROLLED_BACK').exists())
        self.health.assert_called_once()

    def test_rollback_refuses_concurrent_change_before_stopping_services(self):
        backup, existing, added = self.backup()
        existing.write_bytes(b'new user edit')
        self.run.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'File changed'):
            installer.restore(backup)
        self.assertEqual(existing.read_bytes(), b'new user edit')
        self.assertTrue(added.exists())
        self.run.assert_not_called()

    def test_rollback_refuses_corrupt_backup_before_stopping_services(self):
        backup, existing, added = self.backup()
        (backup / 'files/0').write_bytes(b'corrupt')
        self.run.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'integrity'):
            installer.restore(backup)
        self.assertEqual(existing.read_bytes(), b'new')
        self.run.assert_not_called()

    def test_committed_fresh_install_cannot_be_uninstalled_by_rollback(self):
        backup, existing, added = self.backup(fresh=True)
        (backup / 'COMMITTED').write_text('ok')
        self.run.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'cannot be uninstalled'):
            installer.restore(backup)
        self.assertEqual(existing.read_bytes(), b'new')
        self.assertTrue(added.exists())
        self.run.assert_not_called()

    def test_automatic_recovery_ignores_committed_transaction(self):
        backup, existing, added = self.backup()
        (backup / 'COMMITTED').write_text('ok')
        self.run.reset_mock()
        installer.restore(backup, automatic=True)
        self.assertEqual(existing.read_bytes(), b'new')
        self.assertTrue(added.exists())
        self.run.assert_not_called()

    def test_failed_update_rolls_back_code_and_receipt(self):
        old, new = self.changed_release()
        old_panel = (self.app / 'geobox.py').read_bytes()
        old_receipt = self.receipt.read_bytes()
        self.health.side_effect = [RuntimeError('synthetic health failure'), None]
        with patch.object(installer, 'mutation_guard', side_effect=nullcontext):
            with self.assertRaisesRegex(RuntimeError, 'synthetic health failure'):
                installer.apply_release(self.stage, new)
        self.assertEqual((self.app / 'geobox.py').read_bytes(), old_panel)
        self.assertEqual(self.receipt.read_bytes(), old_receipt)
        self.assertFalse((self.app / 'new_feature.py').exists())
        self.assertTrue(any(self.backups.glob('release-*/ROLLED_BACK')))

    def test_busy_location_operation_refuses_mutation_and_closes_descriptor(self):
        (self.state / 'ios').mkdir()
        fake_fcntl = types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4,
                                          flock=Mock(side_effect=BlockingIOError()))
        with patch.dict(sys.modules, {'fcntl': fake_fcntl}):
            with patch.object(installer.os, 'close', wraps=installer.os.close) as close:
                with self.assertRaisesRegex(RuntimeError, 'location operation is active'):
                    with installer.mutation_guard():
                        self.fail('Busy operation was allowed through')
                close.assert_called_once()

    def test_busy_update_leaves_panel_code_and_receipt_untouched(self):
        _, new = self.changed_release()
        before = {p: p.read_bytes() for p in (self.app / 'geobox.py', self.receipt)}
        with patch.object(installer, 'mutation_guard', side_effect=RuntimeError('phone operation busy')), \
             patch.object(installer, 'atomic_write', wraps=installer.atomic_write) as write:
            with self.assertRaisesRegex(RuntimeError, 'phone operation busy'):
                installer.apply_release(self.stage, new)
            write.assert_not_called()
        self.health.assert_not_called()
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertFalse((self.app / 'new_feature.py').exists())
        self.assertTrue(any(self.backups.glob('release-*/ROLLED_BACK')))
        for call in self.run.call_args_list:
            args = call.args[0]
            self.assertFalse(args[:2] == ['systemctl', 'restart'])
            if args[:2] == ['systemctl', 'stop']:
                self.assertTrue(args[2].startswith('geobox-release-recover-'))
                self.assertTrue(args[2].endswith('.timer'))

    def profile_backup(self, current_uuid='test-profile'):
        (self.stage / 'install.py').write_text('# synthetic recovery entry point\n')
        target = self.root / 'geobox-ap.nmconnection'
        data = installer.profile_bytes('test-profile', 'GeoBox', 'synthetic pass', 'bg')
        backup = installer.make_backup(self.stage, {target: data}, True, 'test-profile')
        target.write_text('[connection]\nid=geobox-ap\nuuid=' + current_uuid +
                          '\nautoconnect=true\n[wifi]\nssid=GeoBox\n')
        return backup, target

    def test_fresh_rollback_accepts_networkmanager_normalization_for_same_uuid(self):
        backup, target = self.profile_backup()
        self.run.reset_mock()
        installer.restore(backup)
        self.assertFalse(target.exists())
        self.assertTrue((backup / 'ROLLED_BACK').exists())
        self.assertIn(['nmcli', 'connection', 'delete', 'uuid', 'test-profile'],
                      [call.args[0] for call in self.run.call_args_list])

    def test_fresh_rollback_refuses_foreign_profile_uuid_before_services_change(self):
        backup, target = self.profile_backup('foreign-profile')
        before = target.read_bytes()
        self.run.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'profile identity changed'):
            installer.restore(backup)
        self.assertEqual(target.read_bytes(), before)
        self.run.assert_not_called()

    def test_fresh_rollback_retains_firewall_when_profile_deletion_fails(self):
        backup, target = self.profile_backup()
        def command(args, *, check=True, **kwargs):
            if args == ['nmcli', '-g', 'UUID', 'connection', 'show']:
                return 'test-profile\n'
            return self.command(args, check=check)
        self.run.side_effect = command
        self.run.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'profile remains registered'):
            installer.restore(backup)
        self.assertTrue(target.exists())
        self.assertFalse((backup / 'ROLLED_BACK').exists())
        commands = [call.args[0] for call in self.run.call_args_list]
        self.assertFalse(any(args[0] in ('nft', 'ip', 'sysctl') for args in commands))
        self.assertNotIn(['systemctl', 'disable', '--now', *installer.UNITS], commands)

    def test_fresh_rollback_restores_prior_dnsmasq_disabled_inactive_state(self):
        backup, target = self.profile_backup()
        state_file = backup / 'state.json'
        meta = json.loads(state_file.read_text())
        meta['dnsmasq_enabled'], meta['dnsmasq_active'] = 'disabled', False
        state_file.write_text(json.dumps(meta))
        self.run.reset_mock()
        installer.restore(backup)
        commands = [call.args[0] for call in self.run.call_args_list]
        self.assertIn(['systemctl', 'disable', 'dnsmasq'], commands)
        self.assertNotIn(['systemctl', 'start', 'dnsmasq'], commands)

    def test_profile_encodes_ssid_and_escapes_password_without_running_command(self):
        password = ' leading\\slash ;#=tail '
        data = installer.profile_bytes('test-profile', 'Geo Бокс;=', password, 'a').decode()
        self.assertIn('ssid=' + ''.join(str(byte) + ';' for byte in 'Geo Бокс;='.encode()) + '\n', data)
        self.assertIn('psk=\\sleading\\\\slash\\s;#=tail\\s\n', data)
        self.assertIn('autoconnect=false\n', data)
        self.assertIn('never-default=true\n', data)
        self.run.assert_not_called()

    def test_fresh_install_password_never_appears_in_process_arguments(self):
        manifest = self.release()
        self.app.rmdir()
        self.etc.rmdir()
        password = ' private\\wifi;#=pass '
        panel_password = 'synthetic-panel-secret'
        original_path = Path
        original_temporary_directory = tempfile.TemporaryDirectory
        nm_file = self.root / 'NetworkManager/geobox-ap.nmconnection'
        dhcp_file = self.root / 'misc/geobox-dhcp-hosts'
        remap = {'/etc/NetworkManager/system-connections/geobox-ap.nmconnection': nm_file,
                 '/var/lib/misc/geobox-dhcp-hosts': dhcp_file}
        def local_path(*args):
            return remap.get(str(args[0]), original_path(*args)) if len(args) == 1 else original_path(*args)
        def temporary_directory(*args, **kwargs):
            if kwargs.get('dir') == '/run':
                kwargs['dir'] = self.root
            return original_temporary_directory(*args, **kwargs)
        def command(args, *, check=True, env=None, **kwargs):
            if args[-1] in ('set-password', 'render') and env:
                filename = 'panel.json' if args[-1] == 'set-password' else 'sing-box.json'
                (original_path(env['GEOBOX_ETC']) / filename).write_bytes(b'{}')
            return self.command(args, check=check)
        self.run.side_effect = command
        with patch.object(installer, 'clean_preflight'), \
             patch.object(installer, 'mutation_guard', side_effect=nullcontext), \
             patch.object(installer.getpass, 'getpass', side_effect=[password, password, panel_password, panel_password]), \
             patch.object(installer, 'Path', side_effect=local_path), \
             patch.object(installer.tempfile, 'TemporaryDirectory', side_effect=temporary_directory):
            installer.apply_release(self.stage, manifest, fresh=True, ssid='Test GeoBox')
        self.assertTrue(nm_file.exists())
        for call in self.run.call_args_list:
            args = call.args[0]
            self.assertFalse(any(password in arg or panel_password in arg for arg in args))
        self.assertEqual(nm_file.stat().st_mode & 0o777, 0o600 if sys.platform != 'win32' else 0o666)

    def test_stalled_recovery_ignores_reused_pid(self):
        backup, _, _ = self.backup()
        state_file = backup / 'state.json'
        meta = json.loads(state_file.read_text())
        meta['installer_pid'], meta['installer_stamp'] = 12345, 'old-start-time'
        state_file.write_text(json.dumps(meta))
        with patch.object(installer, 'process_stamp', return_value='different-start-time'), \
             patch.object(installer.os, 'kill') as kill:
            installer.recover_stalled_installer(backup)
            kill.assert_not_called()

    def test_stalled_recovery_requires_original_installer_to_exit(self):
        backup, _, _ = self.backup()
        state_file = backup / 'state.json'
        meta = json.loads(state_file.read_text())
        meta['installer_pid'], meta['installer_stamp'] = 12345, 'same-start-time'
        state_file.write_text(json.dumps(meta))
        with patch.object(installer, 'process_stamp', return_value='same-start-time'), \
             patch.object(installer.os, 'kill') as kill, \
             patch.object(installer.time, 'monotonic', side_effect=[0, 21]):
            with self.assertRaisesRegex(RuntimeError, 'has not exited'):
                installer.recover_stalled_installer(backup)
            kill.assert_called_once_with(12345, installer.signal.SIGTERM)


if __name__ == '__main__':
    unittest.main()
