import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import switching


class SwitchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Path(self.tmp.name) / 'sing-box.json'
        self.proxy = Path(self.tmp.name) / 'proxy.json'
        self.journal = Path(self.tmp.name) / 'switch-pending.json'
        self.cfg.write_bytes(b'{"old-config": true}')
        self.proxy.write_bytes(b'{"old-proxy": true}')
        self.old_cfg = self.cfg.read_bytes()
        self.old_proxy = self.proxy.read_bytes()
        self.new = {'server': 'example.test', 'password': 'DO-NOT-LEAK'}
        self.exit = {'ip': '203.0.113.1'}
        self.verify = Mock(return_value=self.exit)
        self.restart = Mock(return_value=True)
        self.stop = Mock(return_value=True)
        self.apply = Mock(side_effect=self.install)
        self.sw = switching.Switcher(str(self.cfg), str(self.proxy), str(self.journal),
                                     self.apply, self.verify, self.restart, self.stop)

    def install(self, new):
        # Simulate config replacement and check persistence order.
        self.assertEqual(self.proxy.read_bytes(), self.old_proxy)
        self.assertTrue(self.journal.exists())
        self.cfg.write_text(json.dumps({'new-config': new}))
        return True, 'ok'

    def assert_old(self):
        self.assertEqual(self.cfg.read_bytes(), self.old_cfg)
        self.assertEqual(self.proxy.read_bytes(), self.old_proxy)

    def test_commit_only_after_installed_exit_verified(self):
        def verify():
            self.assertEqual(self.proxy.read_bytes(), self.old_proxy)
            return self.exit
        self.verify.side_effect = verify
        result = self.sw.switch(self.new)
        self.assertTrue(result['ok'])
        self.assertEqual(json.loads(self.proxy.read_text()), self.new)
        self.assertFalse(self.journal.exists())
        self.restart.assert_not_called()

    def test_postcheck_failure_restores_exact_previous_bytes(self):
        self.verify.side_effect = [None, self.exit]
        result = self.sw.switch(self.new)
        self.assertFalse(result['ok'])
        self.assertEqual(result['status'], 'rolled_back')
        self.assertEqual(result['exit'], self.exit)
        self.assert_old()
        self.restart.assert_called_once()
        self.assertFalse(self.journal.exists())

    def test_apply_failure_rolls_back_before_reporting(self):
        self.apply.side_effect = lambda _: (False, 'error DO-NOT-LEAK')
        result = self.sw.switch(self.new)
        self.assert_old()
        self.assertEqual(result['status'], 'rolled_back')
        self.assertNotIn('DO-NOT-LEAK', json.dumps(result))

    def test_changed_exit_country_rolls_back_before_commit(self):
        self.verify.side_effect = [{'ip': '203.0.113.2', 'country': 'ES'}, self.exit]
        result = self.sw.switch(self.new, accept_exit=lambda info: info.get('country') == 'DE')
        self.assertFalse(result['ok'])
        self.assertEqual(result['status'], 'rolled_back')
        self.assert_old()
        self.assertFalse(self.journal.exists())

    def test_matching_exit_country_commits(self):
        self.verify.return_value = {'ip': '203.0.113.2', 'country': 'DE'}
        result = self.sw.switch(self.new, accept_exit=lambda info: info.get('country') == 'DE')
        self.assertTrue(result['ok'])
        self.assertEqual(json.loads(self.proxy.read_text()), self.new)

    def test_failed_rollback_stops_tunnel_and_keeps_recovery_journal(self):
        self.verify.return_value = None
        self.restart.return_value = False
        result = self.sw.switch(self.new)
        self.assert_old()
        self.assertEqual(result['status'], 'blocked')
        self.stop.assert_called_once()
        self.assertTrue(self.journal.exists())

    def test_stop_failure_does_not_claim_blocked(self):
        self.verify.return_value = None
        self.restart.return_value = False
        self.stop.return_value = False
        self.assertEqual(self.sw.switch(self.new)['status'], 'attention')

    def test_no_old_proxy_rollback_does_not_keep_candidate(self):
        self.proxy.unlink()
        def apply(_):
            self.cfg.write_bytes(b'candidate')
            return True, 'ok'
        self.apply.side_effect = apply
        self.verify.return_value = None
        result = self.sw.switch(self.new)
        self.assertEqual(result['status'], 'rolled_back')
        self.assertFalse(self.proxy.exists())
        self.assertEqual(self.cfg.read_bytes(), self.old_cfg)
        self.verify.assert_called_once()

    def test_disable_does_not_probe_or_leave_proxy_file(self):
        result = self.sw.switch(None)
        self.assertTrue(result['ok'])
        self.assertFalse(self.proxy.exists())
        self.verify.assert_not_called()

    def test_unavailable_old_exit_is_not_reported_as_working(self):
        self.verify.return_value = None
        result = self.sw.switch(self.new)
        self.assertEqual(result['status'], 'rolled_back')
        self.assertIsNone(result['exit'])
        self.assert_old()

    def test_crash_recovery_restores_config_and_selection(self):
        def crash(_):
            self.cfg.write_bytes(b'half-installed')
            raise KeyboardInterrupt()
        self.apply.side_effect = crash
        with self.assertRaises(KeyboardInterrupt):
            self.sw.switch(self.new)
        result = self.sw.recover()
        self.assertEqual(result['status'], 'rolled_back')
        self.assert_old()
        self.assertFalse(self.journal.exists())

    def test_corrupt_journal_blocks_without_overwriting_config(self):
        self.journal.write_text('{broken')
        result = self.sw.recover()
        self.assertEqual(result['status'], 'blocked')
        self.assert_old()
        self.apply.assert_not_called()

    def test_storage_error_before_apply_keeps_existing_connection(self):
        with patch.object(switching, 'private_write', side_effect=OSError('full')):
            result = self.sw.switch(self.new)
        self.assertEqual(result['status'], 'unchanged')
        self.assert_old()
        self.apply.assert_not_called()

    def test_proxy_persist_failure_rolls_back(self):
        real = switching.private_write
        def fail_commit(path, data):
            if path == str(self.proxy) and isinstance(data, str):
                raise OSError('full')
            return real(path, data)
        with patch.object(switching, 'private_write', side_effect=fail_commit):
            result = self.sw.switch(self.new)
        self.assertEqual(result['status'], 'rolled_back')
        self.assert_old()

    @unittest.skipIf(os.name == 'nt', 'Unix file modes')
    def test_sensitive_files_have_private_permissions(self):
        def crash(_):
            raise KeyboardInterrupt()
        self.apply.side_effect = crash
        with self.assertRaises(KeyboardInterrupt):
            self.sw.switch(self.new)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
