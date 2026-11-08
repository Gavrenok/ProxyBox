"""Local sing-box selector: stable nodes, guarded API changes, no public control port.

The surrounding Switcher transaction owns the durable journal and rollback.
Neither controller secrets nor proxy credentials are returned to the browser.
"""
import copy
import hashlib
import http.client
import json

PORT = 9091
TAG = 'proxy'


def node_tag(outbound):
    normalized = {k: v for k, v in outbound.items() if k != 'tag'}
    raw = json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()
    return 'node-' + hashlib.sha256(raw).hexdigest()[:24]


def controller(config):
    api = config.get('experimental', {}).get('clash_api', {}) if isinstance(config, dict) else {}
    if api.get('external_controller') != '127.0.0.1:%d' % PORT:
        return None
    secret = api.get('secret')
    return secret if isinstance(secret, str) and len(secret) >= 32 else None


def selector(config):
    if not isinstance(config, dict):
        return None
    return next((ob for ob in config.get('outbounds', [])
                 if ob.get('tag') == TAG and ob.get('type') == 'selector'), None)


def configure(base, proxy, items, secret):
    """Keep DNS/device/kill-switch policy intact; replace only the global outbound."""
    config = copy.deepcopy(base)
    if not proxy:
        return config
    nodes = {}
    for item in list(items) + [proxy]:
        ob = item.get('outbound')
        if isinstance(ob, dict) and ob:
            tag = node_tag(ob)
            nodes[tag] = dict(ob, tag=tag)
    chosen = node_tag(proxy['outbound'])
    group = {'type': 'selector', 'tag': TAG, 'outbounds': sorted(nodes),
             'default': chosen, 'interrupt_exist_connections': True}
    config['outbounds'] = [group] + [nodes[k] for k in sorted(nodes)] + [
        ob for ob in config['outbounds'] if ob.get('tag') != TAG]
    config.setdefault('experimental', {})['clash_api'] = {
        'external_controller': '127.0.0.1:%d' % PORT, 'secret': secret,
        'access_control_allow_origin': ['http://127.0.0.1'],
        'access_control_allow_private_network': False}
    return config


def compatible(old, new):
    """Only selection may differ. Added nodes or changed routing require a reload."""
    if not controller(old) or controller(old) != controller(new):
        return False
    left, right = copy.deepcopy(old), copy.deepcopy(new)
    a, b = selector(left), selector(right)
    if not a or not b or not a.get('interrupt_exist_connections') or not b.get('interrupt_exist_connections'):
        return False
    if a.get('default') not in a.get('outbounds', []) or b.get('default') not in a.get('outbounds', []):
        return False
    a.pop('default', None)
    b.pop('default', None)
    return left == right


class ControllerError(RuntimeError):
    pass


class Client:
    def __init__(self, config):
        self.secret = controller(config)
        if not self.secret:
            raise ControllerError('Local controller is not configured')

    def request(self, method, path, data=None):
        connection = http.client.HTTPConnection('127.0.0.1', PORT, timeout=3)
        try:
            body = json.dumps(data) if data is not None else None
            connection.request(method, path, body, {
                'Authorization': 'Bearer ' + self.secret, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(1024 * 1024 + 1)
            if not 200 <= response.status < 300 or len(raw) > 1024 * 1024:
                raise ControllerError('Controller rejected request')
            return json.loads(raw) if raw else {}
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise ControllerError('Local controller did not respond correctly') from None
        finally:
            connection.close()

    def matches(self, config):
        expected = selector(config)
        try:
            actual = self.request('GET', '/proxies/' + TAG)
            return (bool(expected) and isinstance(actual, dict)
                    and actual.get('now') == expected['default']
                    and set(actual.get('all', [])) == set(expected['outbounds']))
        except (ControllerError, TypeError, KeyError):
            return False

    def select(self, config):
        expected = selector(config)
        self.request('PUT', '/proxies/' + TAG, {'name': expected['default']})
        if not self.matches(config):
            raise ControllerError('Selected node was not confirmed')
        # Avoid reusing GeoDNS answers from the previous exit.
        self.request('POST', '/cache/dns/flush')
