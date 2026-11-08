#!/usr/bin/env python3
"""Private, bounded Wi-Fi pairing window. stdout is a sanitized JSONL protocol."""
import argparse
import asyncio
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import uuid

HOME = Path('/var/lib/geobox/ios')
STATE = Path('/run/geobox-ios-pairing-worker.json')
LOCK = Path('/run/geobox-ios-pairing-worker.lock')
HELPER = '/opt/geobox/ios_pairing_worker.py'
PYTHON = '/opt/geobox-ios/venv/bin/python'
NFT = '/usr/sbin/nft'
CHAIN = 'ios_pair_setup'
GUARD = 'geobox_ios_pair_setup_guard'
TAG = 'geobox-ios-pair-setup'
PORT = 50521
TIMEOUT = 300
TOKEN_RE = re.compile(r'[0-9a-f]{32}\Z')


class WorkerError(Exception):
    def __init__(self, code):
        self.code = code


def emit(stream, event, **values):
    allowed = ('ready', 'pin', 'paired', 'timeout', 'cancelled', 'error')
    if event not in allowed:
        raise WorkerError('invalid_event')
    result = {'event': event}
    if event == 'pin':
        value = str(values.get('pin', ''))
        if not re.fullmatch(r'[0-9]{6}', value):
            raise WorkerError('invalid_pin')
        result['pin'] = value
    if event == 'error':
        code = values.get('error')
        safe = {'busy', 'dependency_version', 'firewall_unavailable', 'cleanup_failed',
                'timer_unavailable', 'advertisement_failed', 'pairing_failed',
                'storage_unavailable', 'root_required', 'invalid_pin', 'invalid_arguments'}
        result['error'] = code if code in safe else 'pairing_failed'
    stream.write(json.dumps(result) + '\n')
    stream.flush()


def command(*args, input=None):
    try:
        result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        raise WorkerError('firewall_unavailable') from None
    if result.returncode:
        raise WorkerError('firewall_unavailable')
    return result.stdout


@contextmanager
def state_lock():
    import fcntl
    descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def read_state():
    try:
        return json.loads(STATE.read_text())
    except FileNotFoundError:
        return {}


def save_state(state):
    temporary = STATE.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, STATE)


def process_stamp(pid):
    try:
        # comm can contain spaces/parentheses; starttime is field 22.
        return Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def stop_recorded_process(record):
    pid, stamp = record.get('pid'), record.get('stamp')
    if isinstance(pid, int) and pid > 1 and pid != os.getpid() and stamp and process_stamp(pid) == stamp:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def close_window(token):
    """Token and process start times prevent old cleanup from touching a new job."""
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise WorkerError('invalid_arguments')
    with state_lock():
        state = read_state()
        if state.get('token') != token:
            return
        for process in state.get('children', []):
            stop_recorded_process(process)
        stop_recorded_process(state.get('worker', {}))
        rules = json.loads(command(NFT, '-j', '-a', 'list', 'ruleset'))['nftables']
        commands = []
        for item in rules:
            rule = item.get('rule', {})
            if (rule.get('family'), rule.get('table'), rule.get('chain'), rule.get('comment')) == (
                    'inet', 'geobox', 'input', TAG):
                commands.append(f'delete rule inet geobox input handle {int(rule["handle"])}')
        if any(item.get('chain', {}).get('family') == 'inet' and
               item['chain'].get('table') == 'geobox' and item['chain'].get('name') == CHAIN for item in rules):
            commands.extend([f'flush chain inet geobox {CHAIN}', f'delete chain inet geobox {CHAIN}'])
        if any(item.get('table', {}).get('family') == 'inet' and
               item['table'].get('name') == GUARD for item in rules):
            commands.append(f'delete table inet {GUARD}')
        if commands:
            command(NFT, '-f', '-', input='\n'.join(commands) + '\n')
        # Keep the state + recovery timer if firewall removal failed.
        STATE.unlink(missing_ok=True)
        try:
            command('/usr/bin/systemctl', 'stop', 'geobox-ios-pair-clean-' + token + '.timer')
        except WorkerError:
            pass  # Stale timer now has no matching token and is harmless.


class Window:
    def __init__(self):
        self.token = uuid.uuid4().hex

    def open(self):
        with state_lock():
            if read_state():
                raise WorkerError('busy')
            command(NFT, 'list', 'chain', 'inet', 'geobox', 'input')
            save_state({'token': self.token, 'worker': {'pid': os.getpid(), 'stamp': process_stamp(os.getpid())},
                        'children': []})
            try:
                unit = 'geobox-ios-pair-clean-' + self.token
                try:
                    command('/usr/bin/systemd-run', '--quiet', '--unit=' + unit, '--on-active=6min',
                            '--property=Restart=on-failure', '--property=RestartSec=10s',
                            '--property=StartLimitBurst=3', PYTHON, HELPER, '--cleanup', self.token)
                    if command('/usr/bin/systemctl', 'is-active', unit + '.timer').strip() != 'active':
                        raise WorkerError('timer_unavailable')
                except WorkerError:
                    raise WorkerError('timer_unavailable') from None
                script = f'''add table inet {GUARD}
add chain inet {GUARD} input {{ type filter hook input priority -20; policy accept; }}
add rule inet {GUARD} input iifname "wlan0" ip saddr 10.77.0.0/24 ip daddr 10.77.0.1 tcp dport {PORT} accept
add rule inet {GUARD} input tcp dport {PORT} drop
add chain inet geobox {CHAIN}
add rule inet geobox {CHAIN} iifname "wlan0" ip saddr 10.77.0.0/24 ip daddr 10.77.0.1 tcp dport {PORT} accept
insert rule inet geobox input jump {CHAIN} comment "{TAG}"
'''
                command(NFT, '--check', '-f', '-', input=script)
                command(NFT, '-f', '-', input=script)
            except BaseException:
                # Caller performs cleanup outside this lock, including partially
                # successful timer/rule setup.
                raise

    def add_child(self, pid):
        with state_lock():
            state = read_state()
            if state.get('token') != self.token:
                raise WorkerError('advertisement_failed')
            state['children'].append({'pid': pid, 'stamp': process_stamp(pid)})
            save_state(state)

    def close(self):
        close_window(self.token)


class AvahiResponder:
    """PMD creates/starts the TCP listener BEFORE entering this responder."""
    def __init__(self, service_type, instance_name, port, properties, *, ready, child):
        self.service_type = service_type.removesuffix('.local.')
        self.instance_name, self.port, self.properties = instance_name, port, properties
        self.ready, self.child = ready, child
        self.processes = []

    async def start(self, *args):
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            env={**os.environ, 'LC_ALL': 'C'})
        self.processes.append(process)
        self.child(process.pid)
        async def registered():
            while True:
                line = await process.stderr.readline()
                if not line:
                    raise WorkerError('advertisement_failed')
                if b'Established under name' in line:
                    return
        await asyncio.wait_for(registered(), 10)

    async def __aenter__(self):
        try:
            await self.start('/usr/bin/avahi-publish-address', '-R', 'geobox-pair.local', '10.77.0.1')
            await self.start('/usr/bin/avahi-publish-service', '-H', 'geobox-pair.local',
                             self.instance_name, self.service_type, str(self.port),
                             *[f'{key}={value}' for key, value in self.properties.items()])
            self.ready()
            return self
        except BaseException:
            await self.__aexit__(None, None, None)
            raise

    async def __aexit__(self, *args):
        for process in reversed(self.processes):
            if process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    continue
                try:
                    await asyncio.wait_for(process.wait(), 3)
                except TimeoutError:
                    process.kill()
                    await asyncio.wait_for(process.wait(), 3)


def prepare_home():
    if HOME.is_symlink():
        raise WorkerError('storage_unavailable')
    HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    HOME.chmod(0o700)
    return HOME


def secure_record(path):
    path = Path(path)
    if path.parent.resolve() != HOME.resolve() or not re.fullmatch(r'remote_[A-Za-z0-9-]{8,80}\.plist', path.name):
        raise WorkerError('storage_unavailable')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


async def pair(window, output):
    if importlib.metadata.version('pymobiledevice3') != '11.49.0':
        raise WorkerError('dependency_version')
    from pymobiledevice3 import common
    common._HOMEFOLDER = HOME  # Must precede remote/pair_records imports.
    from pymobiledevice3.remote import tunnel_service
    previous = tunnel_service.MDNSResponder
    tunnel_service.MDNSResponder = lambda *args: AvahiResponder(
        *args, ready=lambda: output('ready'), child=window.add_child)
    try:
        result = await tunnel_service.serve_pairable_host(
            tunnel_service.PairableHostInfo(name='GeoBox', identifier=str(uuid.uuid4()).upper()),
            port=PORT, pin_callback=lambda pin: output('pin', pin=pin), timeout=TIMEOUT)
        secure_record(result.record_path)
    finally:
        tunnel_service.MDNSResponder = previous


async def session(output, *, pairing=pair, window_factory=Window):
    window = window_factory()
    try:
        window.open()
        await pairing(window, output)
    finally:
        window.close()


async def run_worker(output):
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)
    try:
        await asyncio.wait_for(session(output), TIMEOUT)
    except asyncio.CancelledError:
        output('cancelled')
    except TimeoutError:
        output('timeout')
    else:
        output('paired')  # Only after private record + firewall/Avahi cleanup.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run', action='store_true')
    group.add_argument('--cleanup')
    args = parser.parse_args(argv)
    output_stream = sys.stdout
    output = lambda event, **values: emit(output_stream, event, **values)
    logging.disable(logging.CRITICAL)
    os.umask(0o077)
    try:
        if os.geteuid() != 0:
            raise WorkerError('root_required')
        with open(os.devnull, 'w') as sink, redirect_stdout(sink), redirect_stderr(sink):
            if args.cleanup:
                close_window(args.cleanup)
            else:
                from ios_device_bridge import mutation_lock
                with mutation_lock(prepare_home()):
                    asyncio.run(run_worker(output))
    except Exception as exc:
        output('error', error=getattr(exc, 'code', 'pairing_failed'))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
