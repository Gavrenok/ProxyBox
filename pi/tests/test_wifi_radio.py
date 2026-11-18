"""Hardware-independent policy, framing and recovery tests; no radio emissions."""
from contextlib import ExitStack
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import lan
import wifi_radio as radio


class RadioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for obj, key, value in ((lan, 'ETC', root / 'etc'), (lan, 'RUN', root / 'run'),
                                (radio, 'ROOT', root / 'transition')):
            self.stack.enter_context(patch.object(obj, key, value))
        self.command = self.stack.enter_context(patch.object(lan, 'command'))

    def device(self, name, **changes):
        return dict(dict(interface=name, phy=name, address='02:00:00:00:00:01',
                         driver='test', usb=True, mode='managed', idle=True,
                         ap=True, monitor=True, bands=['bg', 'a'], channels={1: 2412, 6: 2437, 36: 5180}), **changes)

    def test_invalid_persisted_interface_never_falls_back(self):
        self.assertEqual(lan.ap_interface(), 'wlan0')
        for value in ('eth0', '../wlan1', 'wlan0;reboot', '', 'x' * 32):
            radio.save(lan.ETC / 'wifi-radio.json', {'interface': value})
            with self.assertRaises(ValueError):
                lan.ap_interface()

    def test_selected_interface_used_by_firewall_and_dhcp(self):
        source = (Path(__file__).parents[1] / 'app/geobox.nft').read_text(encoding='utf-8')
        rendered = lan.firewall(source, 'wlan2')
        self.assertNotIn('"wlan0"', rendered)
        self.assertIn('iifname "wlan2" oifname "sbtun"', rendered)
        self.assertIn('policy drop;', rendered)
        self.assertIn('interface=wlan2\n', lan.dhcp('wlan2'))
        self.assertIn('ra-param=wlan2,30,90', lan.dhcp('wlan2'))

    def test_unsupported_or_occupied_radios_refused(self):
        current = self.device('wlan0', usb=False, mode='AP', idle=False)
        for target in (self.device('wlan1', bands=['bg']), self.device('wlan1', idle=False)):
            with self.assertRaises(ValueError):
                radio.select_device([current, target], 'wlan1', 'ap', band='a')
        for target in (self.device('wlan1', phy='wlan0'), self.device('wlan1', usb=False),
                       self.device('wlan1', monitor=False), self.device('wlan1', channels={6: 2437})):
            with self.assertRaises(ValueError):
                radio.select_device([current, target], 'wlan1', 'beacons')
        with self.assertRaises(ValueError):
            radio.select_device([current], 'wlan0', 'beacons')

    def test_only_locally_allowed_non_dfs_transmit_channels(self):
        caps = '* 2412.0 MHz [1] (20.0 dBm)\n* 2437 MHz [6] (disabled)\n* 5180.0 MHz [36] (no IR)\n* 5260 MHz [52] (radar detection)'
        self.assertEqual(radio.channels(caps), {1: 2412})

    def test_dataset_is_bounded_and_rejects_invalid_mac_and_ssid(self):
        one = {'bssid': '02:00:00:00:00:01', 'ssid': 'PB-Test'}
        self.assertEqual(radio.validate_dataset([one]), [one])
        for value in ([], [one] * 41, [one, one], [{'bssid': 'ff:ff:ff:ff:ff:ff', 'ssid': 'bad'}],
                      [dict(one, ssid='x' * 33)], [dict(one, ssid='\n')], [dict(one, latitude=1)]):
            with self.assertRaises(ValueError):
                radio.validate_dataset(value)

    def test_beacon_addresses_sequence_tsf_and_ies(self):
        data = radio.beacon({'bssid': '02:00:00:00:00:01', 'ssid': 'Test'}, 6, 4097, 123456)
        self.assertEqual(struct.unpack_from('<H', data, 2)[0], 9)
        self.assertEqual(data[9:11], b'\x80\x00')
        self.assertEqual(data[13:19], b'\xff' * 6)
        self.assertEqual(data[19:25], bytes.fromhex('020000000001'))
        self.assertEqual(data[19:25], data[25:31])
        self.assertEqual(struct.unpack_from('<H', data, 31)[0], 16)
        self.assertEqual(struct.unpack_from('<QHH', data, 33), (123456, 100, 1))
        self.assertIn(b'\x03\x01\x06', data[45:])

    def test_boot_recovers_only_unfinished_previous_boot(self):
        meta = dict(boot='old', committed=False, restored=False, token='test')
        radio.save(radio.ROOT / 'journal.json', meta)
        with patch.object(radio, 'boot_id', return_value='new'), patch.object(radio, 'restore_files') as restore:
            radio.recover_boot()
            restore.assert_called_once_with(meta)
            radio.recover_boot()
            self.assertEqual(restore.call_count, 1)
            self.assertTrue(radio.read(radio.ROOT / 'journal.json')['restored'])

    def test_current_boot_or_committed_change_is_not_reverted(self):
        with patch.object(radio, 'boot_id', return_value='same'), patch.object(radio, 'restore_files') as restore:
            for meta in (dict(boot='same', committed=False, restored=False),
                         dict(boot='old', committed=True, restored=False)):
                radio.save(radio.ROOT / 'journal.json', meta)
                radio.recover_boot()
            restore.assert_not_called()

    def test_confirmation_requires_matching_job_and_lan_client(self):
        radio.publish('awaiting_confirmation', kind='ap', busy=True, token='fresh')
        for token, peer in (('stale', '10.77.0.44'), ('fresh', '192.0.2.1')):
            self.assertEqual(radio.action('confirm', {'token': token}, peer)[0], 'err')
        self.assertFalse((lan.RUN / 'wifi-confirm.json').exists())
        self.assertEqual(radio.action('confirm', {'token': 'fresh'}, '10.77.0.44')[0], 'ok')
        self.assertEqual(radio.read(lan.RUN / 'wifi-confirm.json'), {'token': 'fresh'})

    def test_failed_rollback_keeps_journal_pending(self):
        meta = dict(boot='same', committed=False, restored=False, token='fresh')
        radio.save(radio.ROOT / 'journal.json', meta)
        radio.publish('error', kind='ap', busy=True, token='fresh')
        with patch.object(radio, 'restore_files', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                radio.cleanup_ap()
        self.assertFalse(radio.read(radio.ROOT / 'journal.json')['restored'])
        self.assertTrue(radio.busy())

    def test_exec_stop_post_preserves_rollback_result(self):
        radio.save(radio.ROOT / 'journal.json', dict(committed=False, restored=True, token='test'))
        radio.publish('rolled_back', kind='ap', busy=False, token='test')
        radio.cleanup_ap()
        self.assertEqual(radio.status()['phase'], 'rolled_back')

    def test_ui_never_calls_hardware_or_claims_location_success(self):
        radio.publish('transmitting_unverified', submitted=100, busy=True, kind='beacons')
        result = radio.card([self.device('wlan0'), self.device('wlan1', driver='<script>')])
        self.assertIn('не подтверждена', result)
        self.assertIn('untested', result)
        self.assertNotIn('<script>', result)
        self.command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
