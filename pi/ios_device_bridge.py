#!/usr/bin/env python3
"""One-request, private Wi-Fi CoreDevice bridge (pymobiledevice3==11.49.0).

Only the service environment chooses the record directory; requests never contain
paths or endpoints. Acknowledgement does not prove the phone's observed location.
"""
import asyncio
from contextlib import asynccontextmanager, contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib.metadata
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import plistlib
import re
import signal
import stat
import sys

VERSION = "11.49.0"
FEATURE = "com.apple.coredevice.feature.simulatelocation"
ACTIONS = {"set": "setsimulatedlocation", "clear": "clearsimulatedlocation",
           "inspect": "availablelocationscenarios"}
GUARD_PATHS = {name: Path("/etc/geobox") / name for name in
               ("proxy.json", "devices.json", "library.json", "ios-location.json")}
ID_RE = re.compile(r"[A-Za-z0-9-]{8,80}\Z")
TOTAL_TIMEOUT = 140


class BridgeError(Exception):
    def __init__(self, code):
        self.code = code


def validate_request(request):
    if not isinstance(request, dict) or request.get("action") not in (
            "devices", "identify", "inspect", "set", "clear"):
        raise BridgeError("invalid_request")
    action = request["action"]
    allowed = {"action"}
    if action != "devices":
        allowed.add("device_id")
        if not isinstance(request.get("device_id"), str) or not ID_RE.fullmatch(request["device_id"]):
            raise BridgeError("invalid_device_id")
    if action in ("set", "clear"):
        allowed.update(("guard", "expected_ipv4"))
    result = dict(request)
    if action == "set":
        allowed.update(("latitude", "longitude"))
        for key, limit in (("latitude", 90), ("longitude", 180)):
            value = request.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise BridgeError("invalid_coordinates")
            try:
                value = float(value)
            except (ValueError, OverflowError):
                raise BridgeError("invalid_coordinates") from None
            if not math.isfinite(value) or not -limit <= value <= limit:
                raise BridgeError("invalid_coordinates")
            result[key] = value
    if set(request) - allowed:
        raise BridgeError("invalid_request")
    if "expected_ipv4" in request:
        value = request["expected_ipv4"]
        try:
            address = ipaddress.IPv4Address(value) if isinstance(value, str) else None
        except ipaddress.AddressValueError:
            address = None
        network = ipaddress.IPv4Network("10.77.0.0/24")
        if address is None or address not in network or address in (
                network.network_address, network.broadcast_address):
            raise BridgeError("invalid_expected_ipv4")
        result["expected_ipv4"] = str(address)
    if "guard" in request:
        guard = request["guard"]
        if not isinstance(guard, dict) or set(guard) != set(GUARD_PATHS):
            raise BridgeError("invalid_guard")
        if any(not isinstance(v, str) or (v != "missing" and not re.fullmatch(r"[0-9a-f]{64}", v))
               for v in guard.values()):
            raise BridgeError("invalid_guard")
    return result


def private_home():
    folder = Path(os.environ.get("GEOBOX_IOS_HOME", "/var/lib/geobox/ios"))
    if not folder.is_absolute() or folder.is_symlink():
        raise BridgeError("private_storage_unavailable")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(folder, 0o700)
    return folder.resolve()


def pair_records(folder):
    records = {}
    for path in folder.glob("remote_*.plist"):
        identifier = path.name[len("remote_"):-len(".plist")]
        if not ID_RE.fullmatch(identifier) or path.is_symlink():
            continue
        try:
            with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    continue
                data = stream.read(65537)
            if len(data) > 65536:
                continue
            record = plistlib.loads(data)
            if not isinstance(record, dict) or record.get("peer_udid", identifier) != identifier:
                continue
            if not record.get("private_key") or not record.get("public_key"):
                continue
            records[identifier] = record
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
    return records


def safe_name(value):
    return "".join(c for c in value if c.isprintable())[:80] if isinstance(value, str) else "iPhone"


@contextmanager
def mutation_lock(folder):
    import fcntl  # Linux-only CLI; import remains usable on test hosts.
    descriptor = os.open(folder / "bridge.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BridgeError("busy") from None
        yield
    finally:
        os.close(descriptor)


def check_guard(guard):
    if guard is None:
        return
    for name, expected in guard.items():
        try:
            actual = hashlib.sha256(GUARD_PATHS[name].read_bytes()).hexdigest()
        except FileNotFoundError:
            actual = "missing"
        if actual != expected:
            raise BridgeError("stale_request")


class PmdBackend:
    def __init__(self, folder, records):
        if importlib.metadata.version("pymobiledevice3") != VERSION:
            raise BridgeError("dependency_version")
        # 11.49.0 has XDG/legacy-home selection but no exact-folder env. Pin its
        # process-local common singleton BEFORE pair_records/remote imports.
        from pymobiledevice3 import common
        common._HOMEFOLDER = folder
        from pymobiledevice3.remote import tunnel_service
        self.ts = tunnel_service
        self.records = records

    async def discover(self, identifier):
        record = self.records[identifier]
        alt_irk = record.get(self.ts.PEER_ALT_IRK_KEY)
        if not isinstance(alt_irk, bytes):
            raise BridgeError("pairing_needs_refresh")
        answers = self.ts.iter_browse_remotepairing(timeout=8)
        try:
            async for answer in answers:
                if self.ts._match_remote_pair_record(answer, {identifier: alt_irk}) != identifier:
                    continue
                # Bonjour commonly emits separate IPv6 and IPv4 answers. Never
                # settle for the first IPv6 answer: routing policy needs the
                # authenticated LAN IPv4, so continue browsing until it arrives.
                for address in answer.addresses:
                    if ipaddress.ip_address(address.full_ip.split("%")[0]).version != 4:
                        continue
                    service = self.ts.RemotePairingTunnelService(identifier, address.full_ip, answer.port)
                    try:
                        await asyncio.wait_for(service.connect(autopair=False), 6)
                    except BaseException as exc:
                        # PMD's factory catches Exception, not cancellation;
                        # own the partially connected object so timeout closes it.
                        await asyncio.wait_for(service.close(), 5)
                        if isinstance(exc, (OSError, TimeoutError)):
                            continue
                        raise
                    if service.remote_identifier != identifier:
                        await service.close()
                        raise BridgeError("identity_mismatch")
                    return service
        finally:
            await answers.aclose()
        raise BridgeError("device_unavailable")

    @asynccontextmanager
    async def connection(self, identifier, *, tunnel):
        service = await asyncio.wait_for(self.discover(identifier), 22)
        try:
            address = ipaddress.ip_address(service.hostname.split("%")[0])
            details = {"device_id": identifier, "transport": "wifi",
                       "device_ipv4": str(address) if address.version == 4 else None}
            if not tunnel:
                yield details, None
                return
            from pymobiledevice3.remote.common import TunnelProtocol
            from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
            async with self.ts.start_tunnel(service, protocol=TunnelProtocol.TCP) as result:
                async with RemoteServiceDiscoveryService((result.address, result.port)) as rsd:
                    if rsd.udid != identifier:
                        raise BridgeError("identity_mismatch")
                    yield details, rsd
        finally:
            await asyncio.wait_for(service.close(), 5)

    async def ddi_ready(self, rsd):
        from pymobiledevice3.services.mobile_image_mounter import (
            MobileImageMounterService, image_type_for_device, uses_cryptex_image)
        if uses_cryptex_image(rsd):
            from pymobiledevice3.services.cryptexd import CryptexdService
            installed = await CryptexdService(rsd).copy_installed()
            if any(x.identifier == "com.apple.MobileAsset.DDI" for x in installed):
                return True
        async with MobileImageMounterService(rsd) as mounter:
            return await mounter.is_image_mounted(image_type_for_device(rsd))

    async def mount_ddi(self, rsd):
        from pymobiledevice3.services.mobile_image_mounter import auto_mount
        await auto_mount(rsd)

    @asynccontextmanager
    async def location(self, rsd):
        from pymobiledevice3.remote.core_device.location_service import LocationService
        service = LocationService(rsd)
        try:
            await service.connect()
            yield service
        finally:
            await asyncio.wait_for(service.close(), 5)


async def perform(request, backend, *, guard_check=check_guard):
    """Mocks inject only the transport; identity, guards and mutation order stay here."""
    sent = False
    accepted = None
    action = request["action"]
    async def operation():
        nonlocal sent, accepted
        async with backend.connection(request["device_id"], tunnel=action != "identify") as (details, rsd):
            if details.get("device_id") != request["device_id"]:
                raise BridgeError("identity_mismatch")
            if action == "identify":
                accepted = {"status": "ok", **details}
                return
            ready = await asyncio.wait_for(backend.ddi_ready(rsd), 12)
            if not ready:
                if action == "inspect":
                    accepted = {"status": "ok", **details, "ddi_ready": False}
                    return
                try:
                    await asyncio.wait_for(backend.mount_ddi(rsd), 65)
                except Exception:
                    # Cryptex install can succeed while its final acknowledgement
                    # times out. Never repeat the install; check actual state.
                    pass
                ready = await asyncio.wait_for(backend.ddi_ready(rsd), 12)
                if not ready:
                    raise BridgeError("ddi_unavailable")
            async with backend.location(rsd) as location:
                if action in ("set", "clear"):
                    guard_check(request.get("guard"))
                    if (request.get("expected_ipv4") is not None and
                            details.get("device_ipv4") != request["expected_ipv4"]):
                        raise BridgeError("stale_request")
                payload = ({"latitude": request["latitude"], "longitude": request["longitude"]}
                           if action == "set" else {})
                sent = action in ("set", "clear")
                response = await asyncio.wait_for(location.invoke(
                    FEATURE, payload, action_identifier="com.apple.coredevice.action." + ACTIONS[action]), 20)
                if not isinstance(response, dict):
                    raise BridgeError("invalid_response")
                accepted = {"status": "accepted" if sent else "ok", **details,
                            "ddi_ready": True, "location_verified": False}
    try:
        await asyncio.wait_for(operation(), TOTAL_TIMEOUT)
    except Exception as exc:
        if accepted is not None:
            accepted["cleanup_warning"] = True
        else:
            return {"ok": False, "status": "error", "error": exc.code if isinstance(exc, BridgeError) else
                    ("timeout" if isinstance(exc, TimeoutError) else "device_operation_failed"),
                    "outcome": "unknown" if sent else "not_sent", "action": action}
    return {"ok": True, "action": action, **accepted}


def run(request):
    request = validate_request(request)
    folder = private_home()
    records = pair_records(folder)
    if request["action"] == "devices":
        return {"ok": True, "status": "ok", "devices": [
            {"id": identifier, "name": safe_name(record.get("peer_name"))}
            for identifier, record in sorted(records.items())]}
    if request["device_id"] not in records:
        raise BridgeError("device_not_paired")
    # Serialize all connections too: concurrent tunnels use the same TUN name.
    with mutation_lock(folder):
        return asyncio.run(perform(request, PmdBackend(folder, records)))


def main():
    # Third-party log/print output can include credentials. No such output reaches
    # stdout/stderr. The parent must also enforce a process timeout when spawning.
    logging.disable(logging.CRITICAL)
    os.umask(0o077)
    def deadline(*_):
        os.write(1, b'{"ok":false,"status":"error","error":"deadline","outcome":"unknown"}\n')
        os._exit(124)
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(150)
    try:
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise BridgeError("invalid_request")
        request = json.loads(raw)
        with open(os.devnull, "w") as sink, redirect_stdout(sink), redirect_stderr(sink):
            result = run(request)
    except Exception as exc:
        result = {"ok": False, "status": "error", "error": exc.code if isinstance(exc, BridgeError) else
                  "bridge_unavailable", "outcome": "not_sent"}
    if hasattr(signal, "SIGALRM"):
        signal.alarm(0)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("status") in ("ok", "accepted") else 1


if __name__ == "__main__":
    sys.exit(main())
