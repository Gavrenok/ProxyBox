"""Policy boundaries and honest capability reporting; no network required."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import failover_policy as policy
import proxy_checks
import setup_panel


class FailoverPolicyTests(unittest.TestCase):
    def test_group_filter_uses_fresh_country_not_saved_country(self):
        lib = {'failover_policy': policy.validate('reserve', 'DE', 300), 'items': [
            {'id': 'active', 'tags': ['reserve']},
            {'id': 'right', 'tags': ['Reserve'], 'check': {'ok': True, 'country': 'ES'}},
            {'id': 'wrong', 'tags': ['other'], 'check': {'ok': True, 'country': 'DE'}}]}
        self.assertEqual([it['id'] for it in policy.candidates(lib, 'active', now=1000)], ['right'])
        rules = policy.policy(lib)
        self.assertFalse(policy.allows_country({'country': 'ES'}, rules))
        self.assertFalse(policy.allows_country({}, rules))
        self.assertTrue(policy.allows_country({'country': 'DE'}, rules))

    def test_invalid_policy_and_clock_values_fail_closed(self):
        for raw in [None, [], False, {'country': 'Germany'}, {'cooldown': 0}]:
            lib = {'items': [{'id': 'spare'}], 'failover_policy': raw}
            self.assertIsNone(policy.policy(lib))
            self.assertEqual(policy.candidates(lib, 'active'), [])
        for last in ['broken', float('nan'), float('inf'), -1, 2000]:
            self.assertTrue(policy.cooling_down({'failover_last': last}, policy.validate(), now=1000))

    def test_history_bounded_and_cooldown_persisted(self):
        lib = {'items': []}
        for i in range(30):
            policy.record(lib, 'a', 'b', 'DE', now=1000 + i)
        self.assertEqual(len(lib['failover_history']), 25)
        self.assertTrue(policy.cooling_down(lib, policy.validate(), now=1328))
        self.assertFalse(policy.cooling_down(lib, policy.validate(), now=1329))
        self.assertEqual(set(lib['failover_history'][0]), {'time', 'from', 'to', 'country'})


class CapabilityTests(unittest.TestCase):
    def test_timeouts_are_inconclusive_and_dns_never_claimed(self):
        report = proxy_checks.measure({'outbound': {}, 'secrets': ['PRIVATE']},
            Mock(return_value=(None, 'PRIVATE error')),
            Mock(return_value={'code': 'timeout', 'detail': 'PRIVATE'}),
            Mock(return_value={'status': 'unknown'}))
        self.assertEqual(report['https'], 'unknown')
        self.assertEqual(report['udp'], 'unknown')
        self.assertEqual(report['ipv6'], 'unknown')
        self.assertEqual(report['dns'], 'not_tested')
        self.assertNotIn('PRIVATE', str(report))

    def test_rejected_command_differs_from_untested_protocol(self):
        for code, expected in [('supported', 'pass'), ('command_rejected', 'unsupported'),
                               ('unsupported_proxy', 'not_tested')]:
            report = proxy_checks.measure({'outbound': {}}, Mock(return_value=({'ip': '203.0.113.1'}, None)),
                Mock(return_value={'code': code}), Mock(return_value={'status': 'available'}))
            self.assertEqual(report['udp'], expected)
            self.assertEqual(report['https'], 'pass')
            self.assertEqual(report['ipv6'], 'pass')

    def test_bad_saved_report_does_not_break_panel(self):
        for report in ['broken', {'time': 'bad', 'udp': []}, {'time': float('inf')}]:
            self.assertIn('Proxy capabilities', proxy_checks.render({'capabilities': report}, 'en'))


class WizardTests(unittest.TestCase):
    def test_both_languages_all_steps_escape_inputs_and_hide_proxy_secret(self):
        for lang in ['ru', 'en']:
            for step in range(1, 5):
                result = setup_panel.render(lang, step, {'ssid': '<script>bad</script>', 'band': 'a'},
                    {'secrets': ['PRIVATE']}, {'capabilities': {}}, flash=('err', '<b>broken</b>'))
                self.assertNotIn('<script>bad', result)
                self.assertNotIn('PRIVATE', result)
                self.assertIn('lang=' + lang, result)
                if step == 4:
                    self.assertIn('not confirmed' if lang == 'en' else 'не подтверждён', result)


if __name__ == '__main__':
    unittest.main()
