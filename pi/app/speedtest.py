"""Bounded proxy downloads. HTTP errors and tiny samples are never throughput."""
from concurrent.futures import ThreadPoolExecutor
import json
import math
import os
import statistics
import subprocess
import time

METHOD = 'download-v2'
MAX_BYTES = 100_000_000
MIN_SAMPLE = 64 * 1024
SERVERS = (
    ('Cloudflare', 'https://speed.cloudflare.com/__down?bytes={limit}'),
    ('OVH', 'https://proof.ovh.net/files/100Mb.dat'),
    ('Hetzner', 'https://fsn1-speed.hetzner.com/100MB.bin'),
)
DEFAULT_URL = SERVERS[0][1].format(limit=MAX_BYTES)


def _run(cmd, data=None, timeout=30):
    try:
        p = subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or '', p.stderr or ''
    except (OSError, subprocess.TimeoutExpired):
        return 1, '', ''


def _curl_quote(v):
    return '"' + v.replace('\\', '\\\\').replace('"', '\\"').replace('\r', '\\r').replace('\n', '\\n') + '"'


def _sample(proxy_url, url, seconds, limit, run):
    cfg = 'proxy = %s\n' % _curl_quote(proxy_url)
    cmd = ['curl', '-q', '--silent', '--fail', '--output', os.devnull,
           '--max-time', str(seconds), '--connect-timeout', str(min(5, seconds)),
           '--max-filesize', str(limit), '--range', '0-%d' % (limit - 1),
           '--noproxy', '', '--proto', '=https', '-K', '-', '--write-out', '%{json}', url]
    began = time.monotonic()
    rc, out, _ = run(cmd, data=cfg, timeout=seconds + 5)
    try:
        metrics = json.loads(out)
        status = int(metrics['http_code'])
        if status not in (200, 206):
            return None, ('HTTP %d' % status) if status else 'нет HTTP-ответа'
        if rc not in (0, 28):
            return None, 'ошибка загрузки (%d)' % rc
        content_type = str(metrics.get('content_type') or '').split(';', 1)[0].strip().lower()
        if content_type not in ('application/octet-stream', 'binary/octet-stream'):
            return None, 'сервер вернул не тестовый файл'
        size = float(metrics['size_download'])
        total, first = float(metrics['time_total']), float(metrics['time_starttransfer'])
        if not all(math.isfinite(v) for v in (size, total, first)) or size < 0 or total <= 0 or first < 0 or first >= total:
            return None, 'некорректная статистика загрузки'
        if size < MIN_SAMPLE or size > limit or total - first < .05:
            return None, 'недостаточно данных для достоверного замера'
        if rc == 0 and size != limit:
            return None, 'тестовый файл имеет неожиданный размер'
        return {'bytes': int(size), 'first_at': began + first, 'end_at': began + total,
                'ttfb_ms': int(first * 1000)}, None
    except (ValueError, KeyError, TypeError, OverflowError):
        return None, 'не удалось прочитать статистику загрузки'


def speed_test(proxy_url, seconds=10, run=None, url=None, streams=4):
    """Up to 100 MB per server, bounded duration; credentials only in curl stdin.

    Uses the first server with valid samples, not the fastest result selected
    from multiple servers. This measures the router-to-server path, not Wi-Fi.
    """
    run = run or _run
    seconds = max(2, min(30, int(seconds)))
    streams = max(1, min(4, int(streams)))
    limit = MAX_BYTES // streams
    servers = (('Тестовый сервер', url),) if url else SERVERS
    attempts = []
    for source, template in servers:
        target = template.format(limit=limit)
        with ThreadPoolExecutor(max_workers=streams) as pool:
            futures = [pool.submit(_sample, proxy_url, target, seconds, limit, run) for _ in range(streams)]
            samples = [future.result() for future in futures]
        valid = [sample for sample, error in samples if sample]
        errors = sorted(set(error for sample, error in samples if error))
        if not valid:
            attempts.append({'source': source, 'error': '; '.join(errors)})
            continue
        elapsed = max(sample['end_at'] for sample in valid) - min(sample['first_at'] for sample in valid)
        size = sum(sample['bytes'] for sample in valid)
        return {'ok': True, 'method': METHOD, 'source': source, 'streams': len(valid), 'requested_streams': streams,
                'mbps': round(size * 8 / elapsed / 1e6, 2), 'bytes': size, 'secs': round(elapsed, 2),
                'latency_ms': int(statistics.median(sample['ttfb_ms'] for sample in valid)),
                'partial': len(valid) != streams, 'attempts': attempts}
    return {'ok': False, 'err': 'Замер не получен: ' + '; '.join(
        attempt['source'] + ' — ' + attempt['error'] for attempt in attempts), 'attempts': attempts}
