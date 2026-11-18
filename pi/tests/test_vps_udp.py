"""UDP exit binding, device isolation, selector transitions and server rollback."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'app'))
import devices
import fastswitch
import geobox
import network_audit
import vps
import vps_udp
import vps_remote
import test_vps


def proxy():
    return {'origin': 'vps', 'outbound': {'type': 'shadowsocks', 'server': '8.8.8.8',
            'server_port': 32180, 'method': 'chacha20-ietf-poly1305', 'password': 'b'*43}}


def proof(ob):
    return {'status': 'pass', 'fingerprint': vps_udp.ipv6_probe.fingerprint(ob),
            'mapped_ip': ob['server'], 'checked_at': 1700000000}


class RoutingTests(unittest.TestCase):
    def config(self, assigned=None, ipv6=False):
        assigned = assigned or {}
        ext = devices.config_ext(assigned, {'other': {'outbound': {'type': 'http', 'server': '1.1.1.1', 'server_port': 8080}}})
        ext['has_overrides'] = bool(assigned)
        ext['udp_exclusions'] = vps_udp.exclusions(assigned)
        return fastswitch.configure(geobox.build_config(proxy(), ext, ipv6=ipv6, udp=True), proxy(), [], 'a'*32)

    def test_proof_bound_to_server_credentials_and_origin(self):
        p = proxy(); saved = {'proxy': p, 'udp': proof(p['outbound'])}
        self.assertTrue(vps_udp.enabled(saved, p))
        for change in ({'server': '1.1.1.1'}, {'password': 'different'}, {'network': 'tcp'}):
            changed = dict(p, outbound=dict(p['outbound'], **change))
            self.assertFalse(vps_udp.enabled(saved, changed))
        self.assertFalse(vps_udp.enabled(saved, dict(p, origin='imported')))
        for change in ({'status': 'unknown'}, {'mapped_ip': '1.1.1.1'}, {'checked_at': float('nan')}):
            self.assertFalse(vps_udp.enabled(dict(saved, udp=dict(saved['udp'], **change)), p))
        self.assertFalse(vps_udp.enabled({'proxy': p}, p))

    def test_dns_private_ipv6_guards_and_device_assignments_survive(self):
        for assigned, ipv6 in [({}, False), ({}, True),
                ({'x': {'mode': 'block', 'ip': '10.77.0.25'}}, False),
                ({'x': {'mode': 'proxy', 'ip': '10.77.0.25', 'item': 'other'}}, False)]:
            with self.subTest(assigned=assigned, ipv6=ipv6):
                config = self.config(assigned, ipv6)
                self.assertTrue(vps_udp.audited_exceptions(config, assigned))
                checks = network_audit._policy_checks(config, assigned)
                self.assertEqual([(c['id'], c['status']) for c in checks if c['status'] != 'pass'], [])
                rules = config['route']['rules']
                self.assertLess(rules.index({'protocol':'dns', 'action':'hijack-dns'}), rules.index(vps_udp.ALLOW))
                self.assertLess(rules.index({'ip_is_private':True, 'action':'reject'}), rules.index(vps_udp.ALLOW))
                if assigned:
                    guard = {'network':'udp', 'source_ip_cidr':['10.77.0.25/32'], 'action':'reject'}
                    self.assertLess(rules.index(guard), rules.index(vps_udp.ALLOW))

    def test_unknown_device_identity_disables_udp(self):
        for assigned in ({'x': {'mode': 'block'}}, {'x': {'mode': 'other', 'ip': '10.77.0.25'}}, {'x': []}):
            ext = {'has_overrides': True, 'udp_exclusions': vps_udp.exclusions(assigned)}
            config = geobox.build_config(proxy(), ext, udp=True)
            self.assertNotIn(vps_udp.ALLOW, config['route']['rules'])

    def test_switch_to_regular_proxy_requires_reload_and_closes_udp(self):
        active = self.config()
        rented = {'outbound': {'type':'http', 'server':'1.1.1.1', 'server_port':8080}}
        candidate = fastswitch.configure(geobox.build_config(rented, udp=True), rented, [proxy()], 'a'*32)
        self.assertNotIn(vps_udp.ALLOW, candidate['route']['rules'])
        self.assertFalse(fastswitch.compatible(active, candidate))
        closed = geobox.build_config(None, udp=True)
        self.assertNotIn(vps_udp.ALLOW, closed['route']['rules'])
        self.assertEqual(closed['route']['rules'][-1], {'action':'reject'})

    def test_audit_does_not_exempt_bypasses_or_a_different_exit(self):
        assigned = {'x': {'mode':'block', 'ip':'10.77.0.25'}}
        base = self.config(assigned)
        variants = []
        c = copy.deepcopy(base); c['route']['rules'].remove({'ip_is_private':True, 'action':'reject'}); variants.append(c)
        c = copy.deepcopy(base); c['route']['rules'].remove({'network':'udp', 'source_ip_cidr':['10.77.0.25/32'], 'action':'reject'}); variants.append(c)
        c = copy.deepcopy(base); c['outbounds'][-1]['server'] = '1.1.1.1'; variants.append(c)
        c = copy.deepcopy(base); c['route']['rules'].insert(0, c['route']['rules'].pop(c['route']['rules'].index(vps_udp.ALLOW))); variants.append(c)
        for config in variants:
            self.assertFalse(vps_udp.audited_exceptions(config, assigned))
            checks = network_audit._policy_checks(config, assigned)
            self.assertNotEqual(next(c['status'] for c in checks if c['id']=='config_udp'), 'pass')


class ProvisionTests(unittest.TestCase):
    fields = test_vps.VPSTests.fields
    ssh = test_vps.VPSTests.ssh
    def test_failed_udp_upgrade_restores_existing_tcp_service(self):
        module, _ = self.ssh()
        with patch.object(vps,'ssh_module',return_value=module), patch.object(vps.socket,'create_connection'), patch.object(vps,'remote',side_effect=[{'ok':True,'created':False,'port':32180,'udp':True,'udp_changed':True},{'ok':True}]) as remote:
            with self.assertRaisesRegex(vps.SetupError,'existing TCP service was restored'):
                vps.provision(self.fields(), {}, Mock(return_value=True), verify_udp=Mock(return_value={'status':'unknown'}))
            self.assertEqual(remote.call_args.args[2]['op'], 'rollback_udp')

    def test_success_commits_upgrade_only_after_real_exit_proof(self):
        module, _ = self.ssh()
        with patch.object(vps,'ssh_module',return_value=module), patch.object(vps.socket,'create_connection'), patch.object(vps,'remote',side_effect=[{'ok':True,'created':False,'port':32180,'udp':True,'udp_changed':True},{'ok':True}]) as remote:
            result = vps.provision(self.fields(), {}, Mock(return_value=True), verify_udp=proof)
            self.assertEqual(remote.call_args.args[2]['op'], 'commit_udp')
            self.assertTrue(vps_udp.enabled(vps.profile(result), result['proxy']))


class UpgradeTests(unittest.TestCase):
    setUp = test_vps.RemoteTests.setUp
    def test_upgrade_rolls_back_without_touching_other_service(self):
        vps_remote.install(self.data)
        cfg = self.root/'etc/geobox-egress'/('a'*24+'.json')
        old = json.loads(cfg.read_text())
        result = vps_remote.install(dict(self.data, udp=True))
        self.assertTrue(result['udp_changed'])
        self.assertEqual(json.loads(cfg.read_text())['mode'], 'tcp_and_udp')
        vps_remote.rollback_udp(self.data)
        self.assertEqual(json.loads(cfg.read_text()), old)
        self.assertFalse(cfg.with_suffix('.udp-backup').exists())
        self.assertEqual(self.original.read_text(), 'DO NOT TOUCH')

    def test_interrupted_upgrade_recovers_before_retry(self):
        vps_remote.install(self.data)
        vps_remote.install(dict(self.data, udp=True))
        result = vps_remote.install(dict(self.data, udp=True))
        self.assertTrue(result['udp_changed'])
        vps_remote.commit_udp(self.data)
        result = vps_remote.install(dict(self.data, udp=True))
        self.assertTrue(result['udp'])
        self.assertNotIn('udp_changed', result)

    def test_udp_port_collision_leaves_tcp_config_unchanged(self):
        vps_remote.install(self.data)
        cfg = self.root/'etc/geobox-egress'/('a'*24+'.json')
        old = cfg.read_bytes()
        with patch.object(vps_remote.socket, 'socket') as factory:
            factory.return_value.__enter__.return_value.bind.side_effect = OSError()
            with self.assertRaisesRegex(RuntimeError, 'udp_port_in_use'):
                vps_remote.install(dict(self.data, udp=True))
        self.assertEqual(cfg.read_bytes(), old)

    def test_new_install_uses_both_protocols_and_cleanup_removes_owned_rules_only(self):
        with patch.object(vps_remote.shutil, 'which', return_value='/usr/bin/tool'):
            self.command.return_value = Mock(stdout='Status: active\n', returncode=0)
            result = vps_remote.install(dict(self.data, udp=True))
        self.assertTrue(result['udp'])
        port = result['port']
        self.command.return_value = Mock(stdout='Status: active\n%d/tcp ALLOW Anywhere # unrelated\n%d/udp ALLOW Anywhere # geobox-%s\n' % (port, port, self.data['owner']), returncode=0)
        self.command.reset_mock()
        vps_remote.remove(self.data)
        self.command.assert_any_call(['ufw','--force','delete','allow', str(port)+'/udp'])
        self.assertNotIn((['ufw','--force','delete','allow', str(port)+'/tcp'],), [c.args for c in self.command.call_args_list])


if __name__ == '__main__':
    unittest.main()
