"""SSH identity, secret lifetime, remote rollback, isolated server install."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'app'))
import vps
import vps_remote as remote


class VPSTests(unittest.TestCase):
    def fields(self):
        return {'host':'8.8.8.8','ssh_port':'22','user':'root','ssh_password':'SSH_SECRET','port':''}

    def ssh(self):
        module=Mock()
        transport=module.Transport.return_value
        transport.get_remote_server_key.return_value.asbytes.return_value=b'host-key'
        return module, transport

    def test_rejects_shell_payload_private_host_invalid_port(self):
        for key,value in [('host','127.0.0.1'),('host','8.8.8.8; id'),('user','root; id'),('port','22'),('ssh_port','70000')]:
            fields=self.fields(); fields[key]=value
            with self.assertRaises(vps.SetupError): vps.validate(fields)

    def test_changed_key_never_sends_password_or_executes(self):
        module,transport=self.ssh()
        fields=self.fields()
        with patch.object(vps,'ssh_module',return_value=module), patch.object(vps.socket,'create_connection'), patch.object(vps,'remote') as execute:
            with self.assertRaisesRegex(vps.SetupError,'host key changed'):
                vps.provision(fields,{},Mock(),{'8.8.8.8:22':'SHA256:WRONG'})
            transport.auth_password.assert_not_called()
            execute.assert_not_called()
            transport.close.assert_called_once()
            self.assertEqual(fields['ssh_password'],'')

    def test_failed_exit_removes_new_owned_service(self):
        module,_=self.ssh()
        fields=self.fields(); remember=Mock()
        with patch.object(vps,'ssh_module',return_value=module), patch.object(vps.socket,'create_connection'), patch.object(vps,'remote',side_effect=[{'ok':True,'created':True,'port':32180},{'ok':True,'removed':True}]) as execute:
            with self.assertRaisesRegex(vps.SetupError,'new service was removed'):
                vps.provision(fields,{},Mock(return_value=False),remember=remember)
            self.assertEqual(execute.call_args.args[2]['op'],'remove')
            self.assertEqual(execute.call_args.args[2]['owner'],remember.call_args.args[0]['owner'])
            self.assertNotIn('SSH_SECRET',json.dumps(remember.call_args.args[0]))

    def test_existing_service_never_removed_on_failed_probe(self):
        module,_=self.ssh()
        with patch.object(vps,'ssh_module',return_value=module), patch.object(vps.socket,'create_connection'), patch.object(vps,'remote',return_value={'ok':True,'created':False,'port':32180}) as execute:
            with self.assertRaisesRegex(vps.SetupError,'left unchanged'):
                vps.provision(self.fields(),{},Mock(return_value=False))
            self.assertEqual(execute.call_count,1)

    def test_success_returns_only_independent_connection_credentials(self):
        module,transport=self.ssh()
        fields=self.fields()
        with patch.object(vps,'ssh_module',return_value=module), patch.object(vps.socket,'create_connection'), patch.object(vps,'remote',return_value={'ok':True,'created':True,'port':32180}):
            value=vps.provision(fields,{},Mock(return_value=True))
        self.assertEqual(value['proxy']['origin'],'vps')
        self.assertEqual(value['proxy']['outbound']['method'],'chacha20-ietf-poly1305')
        self.assertNotIn('SSH_SECRET',json.dumps(value))
        self.assertEqual(fields['ssh_password'],'')
        transport.close.assert_called_once()

    def test_validation_failure_also_discards_password(self):
        fields=self.fields(); fields['host']='bad'
        with self.assertRaises(vps.SetupError): vps.provision(fields,{},Mock())
        self.assertEqual(fields['ssh_password'],'')

    def test_saved_profile_validation_rejects_arbitrary_outbounds_and_strips_extras(self):
        sample = {'host':'8.8.8.8','ssh_port':22,'user':'root','owner':'a'*24,
                  'fingerprint':'SHA256:'+'a'*43,'ssh_password':'PRIVATE',
                  'proxy':{'origin':'vps','outbound':{'type':'shadowsocks','server':'8.8.8.8',
                    'server_port':32180,'method':'chacha20-ietf-poly1305','password':'b'*43}}}
        self.assertNotIn('PRIVATE', json.dumps(vps.profile(sample)))
        for bad in ([], 'bad', {'proxy':{}}, dict(sample, host='127.0.0.1'), dict(sample, owner='../x')):
            with self.assertRaises(vps.SetupError): vps.profile(bad)
        sample['proxy']['outbound']['type'] = 'direct'
        with self.assertRaises(vps.SetupError): vps.profile(sample)

    def test_render_never_echoes_connection_secrets(self):
        saved={'host':'<svg>','proxy':{'port':1234,'outbound':{'password':'TUNNEL_SECRET'}},'ssh_password':'SSH_SECRET','fingerprint':'SHA256:<bad>'}
        result=vps.card(saved,None)
        self.assertNotIn('SSH_SECRET',result)
        self.assertNotIn('TUNNEL_SECRET',result)
        self.assertNotIn('<svg>',result)


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'etc/systemd/system').mkdir(parents=True)
        (self.root/'etc/os-release').write_text('ID=debian\n')
        self.original=self.root/'etc/systemd/system/important.service'
        self.original.write_text('DO NOT TOUCH')
        patches=[patch.object(remote,'Path',side_effect=lambda path:self.root/str(path).lstrip('/')),
                 patch.object(remote.os,'geteuid',return_value=0,create=True),
                 patch.object(remote.shutil,'which',side_effect=lambda name:'/usr/bin/ss-server' if name=='ss-server' else None),
                 patch.object(remote,'command',return_value=Mock(stdout='',returncode=0))]
        self.command=None
        for p in patches:
            value=p.start(); self.addCleanup(p.stop); self.command=value
        self.data={'owner':'a'*24,'secret':'b'*43,'port':0}

    def test_install_is_isolated_idempotent_and_removable(self):
        result=remote.install(self.data)
        self.assertTrue(result['created'])
        self.assertEqual(remote.install(self.data)['created'],False)
        config=self.root/'etc/geobox-egress'/('a'*24+'.json')
        self.assertEqual(json.loads(config.read_text())['method'],'chacha20-ietf-poly1305')
        self.assertTrue(remote.remove(self.data)['removed'])
        self.assertEqual(self.original.read_text(),'DO NOT TOUCH')
        self.assertFalse(config.exists())
        calls=' '.join(str(c.args) for c in self.command.call_args_list)
        self.assertNotIn('iptables',calls); self.assertNotIn('nft',calls); self.assertNotIn('flush',calls)

    def test_failed_service_start_rolls_back_only_owned_files(self):
        def run(args,**kw):
            if args[:2]==['systemctl','enable']: raise RuntimeError('command_failed:systemctl')
            return Mock(stdout='',returncode=0)
        self.command.side_effect=run
        with self.assertRaises(RuntimeError): remote.install(self.data)
        self.assertEqual(self.original.read_text(),'DO NOT TOUCH')
        self.assertFalse((self.root/'etc/geobox-egress'/('a'*24+'.json')).exists())

    def test_remove_refuses_wrong_secret(self):
        remote.install(self.data)
        with self.assertRaisesRegex(RuntimeError,'ownership_not_confirmed'):
            remote.remove(dict(self.data,secret='wrong'))
        self.assertTrue((self.root/'etc/geobox-egress'/('a'*24+'.json')).exists())


if __name__=='__main__': unittest.main()
