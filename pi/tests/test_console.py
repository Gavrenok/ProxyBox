"""Pagination, locale isolation, and default exit controls (no network)."""
import html
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).parents[1] / 'app'))
import geobox as g
import library_panel as library
import i18n
import vps


class ConsoleTests(unittest.TestCase):
    def items(self, size=46):
        return [{'id': str(n), 'name': 'Item %02d' % n, 'server': '192.0.2.%d' % (n+1),
                 'port': 1080, 'kind': 'socks5', 'tags': ['DE' if n % 2 else 'PH'],
                 'outbound': {'password': 'SECRET'}, 'secrets': ['SECRET']} for n in range(size)]

    def test_library_bounds_and_selected_details(self):
        lib = {'items': self.items()}
        page = library.render_library(lib, filters={'p':'2', 'selected':'19'})
        self.assertEqual(page.count('class="proxy-title"'), 15)
        self.assertIn('16–30 из 46', page)
        self.assertIn('name="id" value="19"', page)
        self.assertNotIn('name="id" value="18"', page)
        self.assertNotIn('SECRET', page)
        self.assertIn('p=3', page)
        self.assertIn('name="p" value="2"', page)
        self.assertEqual(page.count('value="delete"'), 1)

    def test_filter_then_page_and_clamp(self):
        lib = {'items': self.items()}
        items = library.filter_items(lib, {'tag':'DE'})
        self.assertEqual(len(items), 23)
        visible, number, pages, start = library.page_items(items, '9999999')
        self.assertEqual((len(visible), number, pages, start), (8, 2, 2, 15))
        for invalid in ('-1','nonsense',None,'9'*5000):
            visible, number, _, _ = library.page_items(items, invalid)
            self.assertGreaterEqual(number, 1)
            self.assertLessEqual(len(visible), 15)
        self.assertEqual(library.page_items([], '500'), ([], 1, 1, 0))

    def test_navigation_whitelist_and_xss(self):
        lib = {'items': self.items(1)}
        lib['items'][0]['name'] = '<script>bad()</script>'
        page = library.render_library(lib, filters={'q':'"><script>x</script>', 'selected':'bad'})
        self.assertNotIn('<script>', page)
        url = library.view_url({'q':'a & b','next':'https://evil.test','p':'2','selected':'0'})
        self.assertTrue(url.startswith('/?tab=proxies&'))
        self.assertNotIn('evil.test', url)
        self.assertIn('q=a+%26+b', url)

    def test_translation_preserves_user_data_and_markup(self):
        raw = '<html lang="ru"><body><h1>Прокси</h1><b translate="no">Работает</b><input value="Прокси" placeholder="пароль панели"><textarea>Прокси &lt;x&gt;</textarea><script>const x="Прокси";</script><p>&lt;img&gt;</p></body></html>'
        rendered = i18n.document(raw, 'en')
        self.assertIn('<html lang="en">', rendered)
        self.assertIn('<h1>Proxies</h1>', rendered)
        self.assertIn('<b translate="no">Работает</b>', rendered)
        self.assertIn('value="Прокси"', rendered)
        self.assertIn('placeholder="Panel password"', rendered)
        self.assertIn('const x="Прокси";', rendered)
        self.assertIn('<textarea>Прокси &lt;x&gt;</textarea>', rendered)
        self.assertNotIn('<img>', rendered)

    def test_english_is_default_and_ru_remains_available(self):
        self.assertEqual(g.setup_panel.language(None), 'en')
        self.assertEqual(i18n.text('Страница 3 из 4'), 'Page 3 of 4')
        self.assertEqual(i18n.text('Прокси', 'ru'), 'Прокси')
        self.assertEqual(i18n.javascript("x.textContent='Неверный пароль';", 'en'), 'x.textContent="Incorrect password";')

    def test_manual_proxy_off_uses_only_configured_server(self):
        profile = {'outbound':{'type':'shadowsocks'}, 'origin':'vps'}
        with patch.object(g.vpsmod, 'load', return_value={'proxy':profile}), patch.object(g, 'switch_proxy', return_value={'ok':True}) as switch:
            self.assertEqual(g.action_proxy_off()[0], 'ok')
            switch.assert_called_once_with(profile)
        with patch.object(g.vpsmod, 'load', return_value={}), patch.object(g, 'switch_proxy', return_value={'ok':True}) as switch:
            g.action_proxy_off()
            switch.assert_called_once_with(None)

    def test_job_language_and_javascript_protocol_tokens(self):
        raw = '<div id="panel-job" data-lang="ru"></div>'
        self.assertIn('data-lang="en"', i18n.document(raw, 'en'))
        script = "if(state==='error'||state==='cancelled'){label='ошибка';}"
        self.assertEqual(i18n.javascript(script, 'ru'), script)
        translated = i18n.javascript(script, 'en')
        self.assertIn("state==='error'", translated)
        self.assertIn("state==='cancelled'", translated)
        self.assertIn('label="error"', translated)

    def test_server_failure_does_not_autoswitch_to_rented_proxy(self):
        with patch.object(g.libmod,'load', return_value={'failover':True,'items':[]}), patch.object(g,'load_proxy',return_value={'origin':'vps'}), patch.object(g,'probe_outbound') as probe:
            g.failover()
            probe.assert_not_called()

    def test_setup_failure_keeps_previous_route_and_erases_password(self):
        fields = {'ssh_password':'secret'}
        with tempfile.TemporaryDirectory() as directory, patch.object(g,'ETC',directory), patch.object(g,'recover_before_mutation', return_value=''), patch.object(g.vpsmod,'provision',side_effect=vps.SetupError('Connection failed')), patch.object(g,'switch_proxy') as switch:
            self.assertEqual(g.action_vps_setup(fields), ('err','Connection failed'))
            switch.assert_not_called()
            self.assertEqual(fields['ssh_password'], '')
            self.assertFalse((Path(directory)/'vps.json').exists())

    def test_setup_standby_does_not_switch_active_proxy(self):
        candidate = {'proxy':{'origin':'vps','outbound':{'type':'shadowsocks'}}, 'host':'1.1.1.1'}
        with tempfile.TemporaryDirectory() as directory, patch.object(g,'ETC',directory), patch.object(g,'recover_before_mutation',return_value=''), patch.object(g.vpsmod,'provision',return_value=candidate), patch.object(g,'load_proxy',return_value={'outbound':{'type':'socks'}}), patch.object(g,'switch_proxy') as switch:
            fields={'ssh_password':'PRIVATE'}
            self.assertEqual(g.action_vps_setup(fields)[0], 'ok')
            switch.assert_not_called()
            saved=(Path(directory)/'vps.json').read_text()
            self.assertNotIn('PRIVATE', saved)
            self.assertEqual(json.loads(saved),candidate)


if __name__ == '__main__':
    unittest.main()
