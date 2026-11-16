"""Conservative, persisted constraints for global-proxy failover."""
import time
import math


def policy(lib):
    raw = lib.get('failover_policy', {})
    try:
        return validate(raw.get('tag', ''), raw.get('country', ''), raw.get('cooldown', 300))
    except (ValueError, TypeError, AttributeError):
        # Invalid policy must never silently broaden the allowed destinations.
        return None


def validate(tag='', country='', cooldown=300):
    if not isinstance(tag, str) or len(tag.strip()) > 24:
        raise ValueError('Метка группы: до 24 символов.')
    country = str(country).strip().upper()
    if country and (len(country) != 2 or not country.isascii() or not country.isalpha()):
        raise ValueError('Страна: двухбуквенный код, например DE, ES или PR.')
    cooldown = int(cooldown)
    if not 60 <= cooldown <= 86400:
        raise ValueError('Пауза между автозаменами: от 60 до 86400 секунд.')
    return {'tag': ' '.join(tag.split()), 'country': country, 'cooldown': cooldown}


def in_group(item, rules):
    return rules is not None and (not rules['tag'] or rules['tag'].casefold() in
                                 [str(t).casefold() for t in item.get('tags', [])])


def allows_country(info, rules):
    return rules is not None and (not rules['country'] or
                                 str((info or {}).get('country', '')).upper() == rules['country'])


def cooling_down(lib, rules, now=None):
    if rules is None:
        return True
    now = time.time() if now is None else now
    try:
        last = float(lib.get('failover_last', 0))
        return not math.isfinite(last) or last < 0 or (last > 0 and now - last < rules['cooldown'])
    except (TypeError, ValueError):
        return True


def candidates(lib, current_id, now=None):
    rules = policy(lib)
    if cooling_down(lib, rules, now):
        return []
    items = [it for it in lib['items'] if it['id'] != current_id and in_group(it, rules)]
    # Saved country is just a hint. Every candidate must be probed again, and its
    # fresh exit country checked immediately before switching.
    return sorted(items, key=lambda it: (not bool((it.get('check') or {}).get('ok')),
                                        (it.get('check') or {}).get('ms') or 10**9))[:6]


def record(lib, old_id, new_id, country, now=None):
    now = time.time() if now is None else now
    lib['failover_last'] = now
    history = lib.get('failover_history') or []
    if not isinstance(history, list):
        history = []
    lib['failover_history'] = (history + [{'time': now, 'from': old_id,
                                          'to': new_id, 'country': country}])[-25:]
