"""Integration of actual HTTP routes and switching, without external network."""
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import geobox as g


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for key, value in {'ETC': self.tmp.name, 'PROXY_FILE': self.tmp.name + '/proxy.json',
                           'SB_CONFIG': self.tmp.name + '/sing-box.json',
                           'SETTINGS_FILE': self.tmp.name + '/settings.json'}.items():
            self.patch(g, key, value)
        self.patch(g, 'state', {'exit': None, 'exit_time': 0, 'down_since': None,
                    'wifi_error': None, 'fails': 0, 'failover_note': None, 'speed': None,
                    'notified_down': False, 'switch': None})
        self.patch(g, 'sessions', {'local-test': {'exp': time.time() + 300}})
        self.patch(g, 'status_dict', return_value={'singbox': 'active', 'wifi': 'Test WiFi', 'proxy': '',
                   'exit': None, 'exit_age': None, 'clients': [], 'down_since': None, 'wifi_error': None})
        self.patch(g, 'wifi_settings', return_value={'ssid': 'Test WiFi', 'band': 'a'})
        self.patch(g.trmod, 'update', return_value=None)
        self.patch(g.trmod, 'summary', return_value={})
        self.notify = self.patch(g, 'tg_event')
        self.server = g.ThreadingHTTPServer(('127.0.0.1', 0), g.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def patch(self, obj, name, *args, **kwargs):
        p = patch.object(obj, name, *args, **kwargs)
        result = p.start()
        self.addCleanup(p.stop)
        return result

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.notify.assert_not_called()

    def request(self, path, fields=None, authenticated=True, origin=None, extra_headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        headers = {'Cookie': 'gbs=local-test'} if authenticated else {}
        if origin:
            headers['Origin'] = origin
        headers.update(extra_headers or {})
        body = urllib.parse.urlencode(fields) if fields is not None else None
        if body is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        conn.request('POST' if body is not None else 'GET', path, body, headers)
        res = conn.getresponse()
        result = res.status, dict(res.getheaders()), res.read().decode('utf-8')
        conn.close()
        return result

    def test_locale_defaults_to_english_and_switch_preserves_library_context(self):
        _, headers, body = self.request('/', authenticated=False)
        self.assertIn('<html lang="en">', body)
        self.assertIn('Panel password', body)
        status, headers, _ = self.request('/language', {'lang':'ru'}, extra_headers={
            'Referer': 'http://127.0.0.1/?tab=proxies&p=3&selected=abc&q=DE&next=https://evil.test'})
        self.assertEqual(status, 303)
        self.assertIn('gb_lang=ru', headers['Set-Cookie'])
        self.assertIn('p=3', headers['Location'])
        self.assertIn('selected=abc', headers['Location'])
        self.assertNotIn('evil.test', headers['Location'])
        _, _, body = self.request('/', authenticated=False, extra_headers={'Cookie':'gb_lang=ru'})
        self.assertIn('<html lang="ru">', body)
        self.assertEqual(self.request('/language', {'lang':'en'}, origin='https://evil.test')[0], 403)

    def test_vps_setup_requires_login_and_same_origin_and_does_not_echo_secret(self):
        fields = {'host':'8.8.8.8', 'ssh_password':'SSH-SECRET'}
        entered = threading.Event()
        def setup(data):
            data['ssh_password'] = ''
            entered.set()
            return ('ok', 'Server configured')
        action = self.patch(g, 'action_vps_setup', side_effect=setup)
        self.assertEqual(self.request('/vps/setup', fields, authenticated=False)[0], 303)
        self.assertEqual(self.request('/vps/setup', fields, origin='https://evil.test')[0], 403)
        action.assert_not_called()
        status, headers, _ = self.request('/vps/setup', fields)
        self.assertEqual((status, headers['Location']), (303, '/?tab=server'))
        self.assertTrue(entered.wait(1))
        job = g.sessions['local-test']['job']
        _, _, body = self.request('/api/job?id=' + job['id'])
        self.assertNotIn('SSH-SECRET', body)
        _, _, body = self.request('/?tab=server')
        self.assertNotIn('SSH-SECRET', body)

    def test_settings_actions_return_to_their_section(self):
        self.patch(g, 'action_tg', return_value=('ok','Saved'))
        _, headers, _ = self.request('/tg', {'op':'save'})
        self.assertEqual(headers['Location'], '/?tab=settings&section=notifications')

    def test_all_tabs_render_and_mimic_script_requires_login(self):
        for tab in g.TAB_NAMES:
            status, headers, body = self.request('/?tab=' + tab)
            self.assertEqual(status, 200)
            self.assertIn('GeoBox', body)
            if tab == 'mimic':
                self.assertIn('127.0.0.1', body)
                self.assertIn('/mimic.js', body)
                self.assertIn("script-src 'self'", headers['Content-Security-Policy'])
        self.assertEqual(self.request('/mimic.js', authenticated=False)[0], 401)
        self.assertEqual(self.request('/mimic.js')[0], 200)

    def test_radio_action_requires_login_and_same_origin_and_uses_actual_peer(self):
        fields = {'op': 'confirm', 'token': 'test', 'peer': '10.77.0.20'}
        with patch.object(g, 'action_radio', return_value=('ok', 'Test only')) as action:
            self.assertEqual(self.request('/wifi/radio', fields, authenticated=False)[0], 303)
            self.assertEqual(self.request('/wifi/radio', fields, origin='https://foreign.example')[0], 403)
            action.assert_not_called()
            self.assertEqual(self.request('/wifi/radio', fields)[0], 303)
            for _ in range(100):
                if action.called:
                    break
                time.sleep(.01)
            action.assert_called_once_with(fields, '127.0.0.1')

    def test_batch_route_large_input_no_activation_and_safe_flash(self):
        text = '\n'.join('socks5://user:SECRET%s@example.test:%d' % ('x'*400, 10000+i) for i in range(60))
        with patch.object(g, 'apply') as apply, patch.object(g, 'probe') as probe:
            status, _, _ = self.request('/lib/import', {'proxies': text, 'tags': 'Работа, EU'})
            self.assertEqual(status, 303)
            apply.assert_not_called()
            probe.assert_not_called()
        self.assertEqual(len(g.libmod.load(g.ETC)['items']), 60)
        self.assertFalse(Path(g.PROXY_FILE).exists())
        status, _, body = self.request('/?tab=proxies')
        self.assertEqual(status, 200)
        self.assertIn('Добавлено: 60', body)
        self.assertNotIn('SECRET', body)

    def test_metadata_and_get_filters_end_to_end(self):
        self.request('/lib/import', {'proxies': 'socks5://u:pw@example.test:1080'})
        item = g.libmod.load(g.ETC)['items'][0]
        self.assertEqual(self.request('/lib/meta', {'id': item['id'], 'name': 'Рабочий', 'tags': 'EU', 'favorite': '1'})[0], 303)
        stored = g.libmod.load(g.ETC)['items'][0]
        self.assertTrue(stored['favorite'])
        self.assertEqual(stored['tags'], ['EU'])
        self.assertEqual(stored['outbound'], item['outbound'])
        _, _, body = self.request('/?tab=proxies&q=nomatch')
        self.assertNotIn('name="id" value="' + item['id'] + '"', body)
        _, _, body = self.request('/?tab=proxies&favorite=1&tag=EU')
        self.assertIn('Рабочий', body)

    def test_import_unauthenticated_or_cross_origin_cannot_mutate(self):
        data = {'proxies': 'socks5://u:pw@example.test:1080'}
        self.assertEqual(self.request('/lib/import', data, authenticated=False)[0], 303)
        self.assertEqual(self.request('/lib/import', data, origin='https://evil.example')[0], 403)
        self.assertEqual(g.libmod.load(g.ETC)['items'], [])

    def test_manual_switch_failed_postcheck_is_error_and_rolls_back(self):
        old = {'kind': 'socks5', 'server': 'old.example', 'port': 1080, 'outbound': {'type': 'socks'}}
        Path(g.PROXY_FILE).write_text(json.dumps(old))
        Path(g.SB_CONFIG).write_bytes(b'previous-config')
        info = {'ip': '203.0.113.1', 'country': 'GE', 'city': '', 'org': ''}
        self.patch(g, 'probe', return_value=('socks5', {'type': 'socks', 'server': 'new.example', 'server_port': 1080}, info, []))
        def apply(_):
            Path(g.SB_CONFIG).write_bytes(b'candidate-config')
            return True, 'ok'
        self.patch(g, 'apply', side_effect=apply)
        self.patch(g, 'verify_switch_exit', side_effect=[None, info])
        self.patch(g, '_restart_tunnel', return_value=True)
        self.patch(g, '_stop_tunnel', return_value=True)
        result = g.action_set_proxy('socks5://u:pw@new.example:1080')
        self.assertEqual(result[0], 'err')
        self.assertEqual(g.load_proxy(), old)
        self.assertEqual(Path(g.SB_CONFIG).read_bytes(), b'previous-config')
        self.assertEqual(g.state['switch']['status'], 'rolled_back')
        self.assertEqual(g.libmod.load(g.ETC)['items'], [])

    def test_failed_device_apply_restores_assignment_and_dhcp(self):
        self.request('/lib/import', {'proxies': 'socks5://u:pw@example.test:1080'})
        item = g.libmod.load(g.ETC)['items'][0]
        hosts = self.tmp.name + '/hosts'
        self.patch(g.devmod, 'HOSTS_FILE', hosts)
        Path(hosts).write_bytes(b'old-hosts')
        Path(g.SB_CONFIG).write_bytes(b'old-config')
        info = {'ip': '203.0.113.1', 'country': 'GE', 'city': '', 'org': ''}
        self.patch(g, 'probe_outbound', return_value=(info, None))
        self.patch(g, 'apply', return_value=(False, 'rejected'))
        self.patch(g, '_restart_tunnel', return_value=True)
        self.patch(g, 'run', return_value=(0, '', ''))
        result = g.action_device('00:11:22:33:44:55', '10.77.0.10', item['id'], 'Phone')
        self.assertEqual(result[0], 'err')
        self.assertEqual(g.devmod.load(g.ETC), {})
        self.assertEqual(Path(hosts).read_bytes(), b'old-hosts')
        self.assertEqual(Path(g.SB_CONFIG).read_bytes(), b'old-config')

    def test_healthy_proxy_not_overridden_by_stale_failover(self):
        self.request('/lib/import', {'proxies': 'socks5://u:pw@example.test:1080'})
        lib = g.libmod.load(g.ETC)
        lib['failover'] = True
        g.libmod.save(g.ETC, lib)
        self.patch(g, 'probe_outbound', return_value=({'ip': '203.0.113.1'}, None))
        switch = self.patch(g, 'switch_proxy')
        g.state['fails'] = 0
        g.failover()
        switch.assert_not_called()

    def test_setup_requires_login_and_renders_both_languages(self):
        self.assertEqual(self.request('/setup', authenticated=False)[0], 303)
        self.assertEqual(self.request('/setup', {'op': 'proxy'}, authenticated=False)[0], 303)
        for lang in ['ru', 'en']:
            for step in range(1, 5):
                status, headers, body = self.request('/setup?lang=%s&step=%d' % (lang, step))
                self.assertEqual(status, 200)
                self.assertIn('lang="%s"' % lang, body)
                self.assertIn("script-src 'self'", headers['Content-Security-Policy'])
        self.assertEqual(self.request('/setup', {'op': 'check'}, origin='https://evil.test')[0], 403)

    def test_failover_preferences_validate_without_enabling(self):
        status, _, _ = self.request('/lib/failover', {'tag': 'spare', 'country': 'de', 'cooldown': '600'})
        self.assertEqual(status, 303)
        lib = g.libmod.load(g.ETC)
        self.assertEqual(lib['failover_policy'], {'tag': 'spare', 'country': 'DE', 'cooldown': 600})
        self.assertFalse(lib['failover'])
        self.request('/lib/failover', {'tag': '', 'country': 'Germany', 'cooldown': '0'})
        self.assertEqual(g.libmod.load(g.ETC)['failover_policy'], lib['failover_policy'])

    def test_capabilities_save_no_secrets_and_never_activate(self):
        self.request('/lib/import', {'proxies': 'socks5://u:SECRET@example.test:1080'})
        item = g.libmod.load(g.ETC)['items'][0]
        self.patch(g, 'probe_outbound', return_value=({'ip': '203.0.113.1'}, None))
        self.patch(g.udpmod, 'probe', return_value={'code': 'supported'})
        self.patch(g.ip6probe, 'probe', return_value={'status': 'available'})
        switch = self.patch(g, 'switch_proxy')
        self.assertEqual(g.action_lib('capabilities', item['id'])[0], 'ok')
        report = g.libmod.load(g.ETC)['items'][0]['capabilities']
        self.assertEqual(report['udp'], 'pass')
        self.assertNotIn('SECRET', json.dumps(report))
        switch.assert_not_called()

    def test_failover_rejects_fresh_wrong_country_and_ignores_cached_success(self):
        self.request('/lib/import', {'proxies': 'socks5://u:pw@example.test:1080'})
        lib = g.libmod.load(g.ETC)
        lib.update(failover=True, failover_policy=g.failpolicy.validate(country='DE'))
        lib['items'][0]['check'] = {'ok': True, 'country': 'DE'}
        g.libmod.save(g.ETC, lib)
        self.patch(g, 'probe_outbound', return_value=({'ip': '203.0.113.1', 'country': 'ES'}, None))
        self.patch(g, 'tg_event')  # No message is actually sent; this test expects the event.
        switch = self.patch(g, 'switch_proxy')
        g.state['fails'] = 2
        g.failover()
        switch.assert_not_called()

    def test_failover_policy_changed_during_probe_aborts_switch(self):
        self.request('/lib/import', {'proxies': 'socks5://u:pw@example.test:1080'})
        lib = g.libmod.load(g.ETC)
        lib.update(failover=True, failover_policy=g.failpolicy.validate(country='DE'))
        g.libmod.save(g.ETC, lib)
        def probe(*args):
            changed = g.libmod.load(g.ETC)
            changed['failover_policy']['country'] = 'ES'
            g.libmod.save(g.ETC, changed)
            return {'ip': '203.0.113.1', 'country': 'DE'}, None
        self.patch(g, 'probe_outbound', side_effect=probe)
        switch = self.patch(g, 'switch_proxy')
        g.state['fails'] = 2
        g.failover()
        switch.assert_not_called()

    def test_slow_action_returns_immediately_and_tabs_remain_responsive(self):
        release, entered = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def slow():
            entered.set()
            release.wait(3)
            return ('ok', 'Готово')
        self.patch(g, 'action_speed_current', side_effect=slow)
        t = time.monotonic()
        self.assertEqual(self.request('/speed', {})[0], 303)
        self.assertLess(time.monotonic() - t, 0.5)
        self.assertTrue(entered.wait(1))
        job = g.sessions['local-test']['job']
        self.assertEqual(job['status'], 'running')
        status, _, body = self.request('/?tab=proxies')
        self.assertEqual(status, 200)
        self.assertIn('panel-job', body)
        status, _, body = self.request('/api/job?id=' + job['id'])
        self.assertEqual(json.loads(body)['status'], 'running')
        self.assertEqual(self.request('/api/job?id=wrong')[0], 404)
        self.assertEqual(self.request('/api/job?id=' + job['id'], authenticated=False)[0], 401)
        # Second click must not enqueue another operation for this session.
        self.request('/speed', {})
        g.action_speed_current.assert_called_once()
        release.set()
        for _ in range(100):
            if job['status'] != 'running':
                break
            time.sleep(0.005)
        self.assertEqual(job['status'], 'done')

    def test_get_never_waits_for_library_write_lock_or_runs_system_commands(self):
        entered, release = threading.Event(), threading.Event()
        def hold():
            with g.lib_lock:
                entered.set()
                release.wait(3)
        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(entered.wait(1))
        try:
            run = self.patch(g, 'run', side_effect=AssertionError('GET called OS command'))
            for tab in g.TAB_NAMES:
                t = time.monotonic()
                self.assertEqual(self.request('/?tab=' + tab)[0], 200)
                self.assertLess(time.monotonic()-t, 0.5)
            run.assert_not_called()
            g.trmod.update.assert_not_called()
            g.trmod.summary.assert_not_called()
            g.wifi_settings.assert_not_called()
        finally:
            release.set()
            thread.join()

    def restore_fixture(self):
        root = Path(self.tmp.name)
        self.patch(g.devmod, 'HOSTS_FILE', str(root / 'dhcp-hosts'))
        self.patch(g, 'run', return_value=(0, '', ''))
        restart = self.patch(g, '_restart_tunnel', return_value=True)
        old = {'kind': 'socks5', 'server': 'old.example', 'port': 1080,
               'outbound': {'type': 'socks', 'server': 'old.example', 'server_port': 1080}}
        new = dict(old, server='new.example', outbound=dict(old['outbound'], server='new.example'))
        files = {'proxy.json': json.dumps(old).encode(), 'sing-box.json': b'{"old":true}',
                 'library.json': b'{"items":[],"failover":false}', 'devices.json': b'{}',
                 'settings.json': b'{"tg":{"token":"OLD-TOKEN"}}', 'dhcp-hosts': b''}
        for name, raw in files.items():
            (root / name).write_bytes(raw)
        backup = {'geobox_backup': 1, 'proxy': new,
                  'library': {'items': [dict(new, id='11223344')]},
                  'devices': {'00:11:22:33:44:55': {'mode': 'proxy', 'ip': '10.77.0.25', 'item': '11223344'}},
                  'settings': {'tg': {'token': 'NEW-TOKEN'}}}
        return root, files, json.dumps(backup).encode(), restart

    def test_restore_api_failure_restores_all_files(self):
        root, files, backup, restart = self.restore_fixture()
        def apply(_):
            self.assertEqual((root / 'proxy.json').read_bytes(), files['proxy.json'])
            (root / 'sing-box.json').write_bytes(b'{"candidate":true}')
            return False, 'ambiguous API failure'
        self.patch(g, 'apply', side_effect=apply)
        self.patch(g, 'verify_switch_exit', return_value={'ip': '203.0.113.1'})
        self.assertEqual(g.action_restore(backup, False)[0], 'err')
        for name, raw in files.items():
            self.assertEqual((root / name).read_bytes(), raw, name)
        restart.assert_called_once()
        self.assertFalse((root / 'switch-pending.json').exists())

    def test_restore_server_is_transactional_and_backup_excludes_ssh_password(self):
        root, _, backup, _ = self.restore_fixture()
        server = {'host':'8.8.8.8','ssh_port':22,'user':'root','owner':'a'*24,'fingerprint':'SHA256:'+'a'*43,
                  'ssh_password':'NEVER-EXPORT', 'proxy':{'origin':'vps','outbound':{'type':'shadowsocks',
                    'server':'8.8.8.8','server_port':32180,'method':'chacha20-ietf-poly1305','password':'b'*43}}}
        (root / 'vps.json').write_text(json.dumps(server))
        exported = g.export_backup()
        self.assertNotIn('NEVER-EXPORT', exported)
        self.assertEqual(json.loads(exported)['vps']['proxy']['outbound']['password'], 'b'*43)
        original = (root / 'vps.json').read_bytes()
        restore = json.loads(backup)
        restore['vps'] = {}
        self.patch(g, 'apply', return_value=(False,'failed'))
        self.patch(g, 'verify_switch_exit', return_value={'ip':'203.0.113.1'})
        self.assertEqual(g.action_restore(json.dumps(restore).encode(), False)[0], 'err')
        self.assertEqual((root / 'vps.json').read_bytes(), original)

    def test_backup_cannot_replace_pinned_server_identity(self):
        root, _, backup, _ = self.restore_fixture()
        restore = json.loads(backup)
        restore['vps'] = {'host':'8.8.8.8','ssh_port':22,'user':'root','owner':'a'*24,
                         'fingerprint':'SHA256:'+'a'*43, 'proxy':{'origin':'vps','outbound':{
                         'type':'shadowsocks','server':'8.8.8.8','server_port':32180,
                         'method':'chacha20-ietf-poly1305','password':'b'*43}}}
        (root / 'vps-hosts.json').write_text(json.dumps({'8.8.8.8:22':'SHA256:DIFFERENT'}))
        apply = self.patch(g, 'apply')
        self.assertEqual(g.action_restore(json.dumps(restore).encode(), False)[0], 'err')
        apply.assert_not_called()

    def test_restore_failed_exit_restores_all_files(self):
        root, files, backup, restart = self.restore_fixture()
        self.patch(g, 'apply', return_value=(True, 'selector'))
        self.patch(g, 'verify_switch_exit', side_effect=[None, {'ip': '203.0.113.1'}])
        self.assertEqual(g.action_restore(backup, False)[0], 'err')
        for name, raw in files.items():
            self.assertEqual((root / name).read_bytes(), raw, name)
        restart.assert_called_once()

    def test_restore_interrupted_prepare_recovers_library_and_settings(self):
        root, files, backup, restart = self.restore_fixture()
        self.patch(g, 'apply', side_effect=KeyboardInterrupt())
        self.patch(g, 'verify_switch_exit', return_value={'ip': '203.0.113.1'})
        with self.assertRaises(KeyboardInterrupt):
            g.action_restore(backup, False)
        self.assertTrue((root / 'switch-pending.json').exists())
        self.assertNotEqual((root / 'library.json').read_bytes(), files['library.json'])
        self.assertEqual(g.switcher().recover()['status'], 'rolled_back')
        for name, raw in files.items():
            self.assertEqual((root / name).read_bytes(), raw, name)

    def test_restore_success_commits_after_exit_check(self):
        root, files, backup, restart = self.restore_fixture()
        self.patch(g, 'apply', return_value=(True, 'selector'))
        def verify():
            self.assertEqual((root / 'proxy.json').read_bytes(), files['proxy.json'])
            return {'ip': '203.0.113.2'}
        self.patch(g, 'verify_switch_exit', side_effect=verify)
        self.assertEqual(g.action_restore(backup, False)[0], 'ok')
        self.assertEqual(json.loads((root / 'proxy.json').read_text())['server'], 'new.example')
        self.assertEqual(json.loads((root / 'settings.json').read_text())['tg']['token'], 'NEW-TOKEN')
        self.assertFalse((root / 'switch-pending.json').exists())
        restart.assert_not_called()

    def test_router_audit_is_async_authenticated_and_session_scoped(self):
        entered, release = threading.Event(), threading.Event()
        def audit(*args, **kwargs):
            entered.set()
            release.wait(3)
            return {'scope': 'router', 'status': 'pass', 'checked_at': time.time(),
                    'checks': [{'id': 'config_udp', 'title': 'UDP', 'status': 'pass', 'detail': 'SESSION_REPORT'}],
                    'limitations': []}
        check = self.patch(g.auditmod, 'audit', side_effect=audit)
        self.assertEqual(self.request('/diagnostics', {}, authenticated=False)[0], 303)
        self.assertEqual(self.request('/diagnostics', {}, origin='https://foreign.example')[0], 403)
        check.assert_not_called()
        try:
            start = time.monotonic()
            self.assertEqual(self.request('/diagnostics', {})[0], 303)
            self.assertLess(time.monotonic() - start, .5)
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.request('/diagnostics', {})[0], 303)
            self.assertEqual(self.request('/?tab=proxies')[0], 200)
            self.assertEqual(check.call_count, 1)
        finally:
            release.set()
        for _ in range(100):
            if g.sessions['local-test'].get('job', {}).get('status') != 'running':
                break
            time.sleep(.01)
        self.assertIn('SESSION_REPORT', self.request('/?tab=mimic')[2])
        self.assertIsNone(g.session_audit({'exp': time.time() + 60}))
        self.assertFalse(g.session_audit(g.sessions['local-test'])['stale'])
        Path(g.SB_CONFIG).write_text('{}')
        self.assertTrue(g.session_audit(g.sessions['local-test'])['stale'])

    def test_router_audit_does_not_read_half_applied_configuration(self):
        audit = self.patch(g.auditmod, 'audit')
        with g.apply_lock:
            self.assertEqual(g.action_diagnostics(g.sessions['local-test'])[0], 'warn')
        audit.assert_not_called()

    def test_ipv6_route_is_authenticated_background_action_and_settings_stays_responsive(self):
        entered, release = threading.Event(), threading.Event()
        def change(mode):
            entered.set()
            release.wait(2)
            return ('ok', 'IPv6_RESULT')
        action = self.patch(g, 'action_ipv6', side_effect=change)
        self.assertEqual(self.request('/ipv6', {'mode': 'proxy'}, authenticated=False)[0], 303)
        self.assertEqual(self.request('/ipv6', {'mode': 'proxy'}, origin='https://foreign.example')[0], 403)
        action.assert_not_called()
        try:
            status, headers, _ = self.request('/ipv6', {'mode': 'proxy'})
            self.assertEqual(status, 303)
            self.assertEqual(headers['Location'], '/?tab=settings')
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.request('/?tab=settings')[0], 200)
        finally:
            release.set()
        for _ in range(100):
            if g.sessions['local-test'].get('job', {}).get('status') != 'running':
                break
            time.sleep(.01)
        action.assert_called_once_with('proxy')

    def test_udp_profile_comes_from_peer_and_report_expires(self):
        global_proxy = {'kind': 'socks5', 'server': 'global.example', 'port': 1080,
                        'outbound': {'type': 'socks', 'server': 'global.example'}}
        per_device = dict(global_proxy, server='device.example', outbound={'type': 'socks', 'server': 'device.example'})
        Path(g.PROXY_FILE).write_text(json.dumps(global_proxy))
        g.libmod.save(g.ETC, {'items': [dict(per_device, id='11223344')], 'failover': False})
        g.devmod.save(g.ETC, {'00:11:22:33:44:55': {'ip': '10.77.0.25', 'mode': 'proxy', 'item': '11223344'},
                              '00:11:22:33:44:66': {'ip': '10.77.0.26', 'mode': 'block'}})
        self.assertEqual(g.client_proxy('10.77.0.25'), (per_device, 'device_proxy'))
        self.assertEqual(g.client_proxy('10.77.0.26'), (None, 'blocked'))
        self.assertEqual(g.client_proxy('10.77.0.27'), (global_proxy, 'global_proxy'))
        probe = self.patch(g.udpmod, 'probe', return_value={'status': 'pass', 'checked_at': time.time(), 'detail': 'UDP_REPORT', 'mapped_ip': '8.8.4.4'})
        self.assertEqual(self.request('/diagnostics/udp', {}, authenticated=False)[0], 303)
        self.assertEqual(self.request('/diagnostics/udp', {}, origin='https://foreign.example')[0], 403)
        probe.assert_not_called()
        self.assertEqual(self.request('/diagnostics/udp', {'client_ip': '10.77.0.25'})[0], 303)
        for _ in range(100):
            if g.sessions['local-test'].get('job', {}).get('status') != 'running':
                break
            time.sleep(.01)
        probe.assert_called_once_with(global_proxy)  # The real HTTP peer is loopback, not the form value.
        self.assertFalse(g.session_udp_probe(g.sessions['local-test'], '127.0.0.1')['stale'])
        self.assertTrue(g.session_udp_probe(g.sessions['local-test'], '10.77.0.25')['stale'])
        with patch.object(g.time, 'time', return_value=time.time() + 301):
            self.assertTrue(g.session_udp_probe(g.sessions['local-test'], '127.0.0.1')['stale'])


if __name__ == '__main__':
    unittest.main()
