"""Independent openphish.eu lookup and openphish.com Community Feed adapters.

Provider URLs are fixed trusted origins. Submitted destinations are never fetched.
Only hashed indicators and redacted cache records are persisted.
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from typing import Optional, Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError, model_validator
from .threat_store import ThreatStore
try:
    from ..engine import normalize_url
except ImportError:
    from engine import normalize_url

LOG = logging.getLogger('phishguardx.threats')
# HTTPX INFO logs include query strings; application events below never do.
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('httpcore').setLevel(logging.WARNING)
OFFICIAL_FEED = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'
NAMES = {'openphish': 'OpenPhish.eu URL API', 'openphish_feed': 'OpenPhish.com Community Feed',
         'phishtank': 'PhishTank', 'google_safe_browsing': 'Google Safe Browsing', 'urlhaus': 'URLhaus'}
Status = Literal['matched', 'unverified', 'not_found', 'disabled', 'not_configured', 'unavailable', 'rate_limited', 'stale', 'skipped']


def timestamp(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat()


def flag(name):
    return os.getenv(name, '').strip().lower() in ('true', '1', 'yes')


def number(name, default, minimum, maximum):
    try:
        value = float(os.getenv(name, str(default)))
        return max(minimum, min(maximum, value)) if value == value else default
    except ValueError:
        return default


@dataclass(frozen=True)
class OpenPhishSettings:
    api_enabled: bool = False
    api_url: str = 'https://openphish.eu/api/check'
    timeout: float = 10
    cache_ttl: int = 900
    api_hourly_limit: int = 90
    feed_enabled: bool = False
    feed_sync_enabled: bool = False
    feed_url: str = ''
    feed_permission: bool = False
    feed_interval: int = 43200
    feed_max_age: int = 129600

    @classmethod
    def from_env(cls):
        return cls(api_enabled=flag('OPENPHISH_API_ENABLED'), api_url=os.getenv('OPENPHISH_API_URL', cls.api_url),
                   timeout=number('OPENPHISH_TIMEOUT', 10, 1, 15), cache_ttl=int(number('OPENPHISH_CACHE_TTL', 900, 60, 3600)),
                   api_hourly_limit=int(number('OPENPHISH_API_HOURLY_LIMIT', 90, 1, 100)),
                   feed_enabled=flag('OPENPHISH_FEED_ENABLED'), feed_sync_enabled=flag('OPENPHISH_FEED_SYNC_ENABLED'),
                   feed_url=os.getenv('OPENPHISH_FEED_URL', '').strip(), feed_permission=flag('OPENPHISH_FEED_PERMISSION_CONFIRMED'),
                   feed_interval=int(number('OPENPHISH_FEED_INTERVAL_SECONDS', 43200, 43200, 604800)),
                   feed_max_age=int(number('OPENPHISH_FEED_MAX_AGE_SECONDS', 129600, 43200, 604800)))


class PhishRecord(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)
    id: Optional[int] = None
    url: str = Field(max_length=4096)
    status: str = Field(max_length=40)
    target_brand: Optional[str] = Field(default=None, max_length=200)
    verified_at: Optional[str] = Field(default=None, max_length=100)


class OpenPhishResponse(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)
    found: StrictBool
    phish: Optional[PhishRecord] = None

    @model_validator(mode='after')
    def consistent_match(self):
        if self.found and self.phish is None:
            raise ValueError('A found response requires phishing metadata.')
        if not self.found and self.phish is not None:
            raise ValueError('Conflicting response.')
        return self


class ProviderResult(BaseModel):
    source: str
    status: Status
    matched: bool = False
    confirmed: bool = False
    available: bool = False
    cached: bool = False
    checked_at: Optional[str] = None
    last_successful_check: Optional[str] = None
    retry_at: Optional[str] = None
    indicator: Optional[str] = None
    target_brand: Optional[str] = None
    record_status: Optional[str] = None
    threat_type: Optional[str] = None
    message: str


def result(provider, status, message, **kwargs):
    return ProviderResult(source=NAMES[provider], status=status, message=message, **kwargs)


def canonical_url(value):
    """Conservative exact-URL key: case-fold host/scheme, default port, empty path.

    Preserve path case, query order/values, escapes and non-default ports. Drop
    fragments (not sent in HTTP). Do not collapse hosts or match domain substrings.
    """
    _, parts, host, is_ip = normalize_url(value)
    if parts.username is not None:
        raise ValueError('URLs containing embedded credentials cannot be sent to reputation providers.')
    authority = '[' + host + ']' if ':' in host else host
    if parts.port is not None and parts.port != (443 if parts.scheme.lower() == 'https' else 80):
        authority += ':' + str(parts.port)
    return urlunsplit((parts.scheme.lower(), authority, parts.path or '/', parts.query, ''))


def external_eligible(url):
    host = urlsplit(url).hostname or ''
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return not (host.endswith(('.example', '.test', '.invalid', '.localhost', '.local', '.internal', '.home', '.lan', '.onion')) or host in ('example.com', 'example.net', 'example.org'))


def indicator_label(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, '[redacted]' if p.query else '', ''))


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def endpoint_valid(url):
    try:
        p = urlsplit(url)
        return p.scheme == 'https' and p.hostname == 'openphish.eu' and p.port in (None, 443) and p.path == '/api/check' and not (p.username or p.password or p.query or p.fragment)
    except ValueError:
        return False


class ProviderFailure(Exception):
    def __init__(self, code, retry_after=None):
        self.code, self.retry_after = code, retry_after


def retry_seconds(value, now):
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        try:
            seconds = parsedate_to_datetime(value).timestamp() - now
        except (TypeError, ValueError, OverflowError):
            seconds = 3600
    return max(60, min(86400, seconds))


async def request_bytes(client, method, endpoint, limit=262144, **kwargs):
    async with client.stream(method, endpoint, **kwargs) as response:
        if response.status_code in (429, 509):
            raise ProviderFailure('rate_limited', response.headers.get('retry-after'))
        if response.status_code != 200:
            raise ProviderFailure('http_error')
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > limit:
                raise ProviderFailure('response_too_large')
        return bytes(body)


class OpenPhishService:
    def __init__(self, settings=None, store=None, transport=None, clock=time.time):
        self.settings = settings or OpenPhishSettings.from_env()
        self.store = store or ThreatStore()
        self.transport = transport
        self.clock = clock

    def client(self):
        return httpx.AsyncClient(timeout=self.settings.timeout, follow_redirects=False, trust_env=False,
                                 transport=self.transport, headers={'User-Agent': 'PhishGuardX/1.1 (+https://github.com/aashleshshet/PhishGuardX)'})

    async def db(self, method, *args):
        return await asyncio.to_thread(getattr(self.store, method), *args)

    async def state(self, provider):
        try:
            return await self.db('get_meta', 'provider:' + provider)
        except Exception:
            return {'status': 'unavailable', 'message': 'Threat database is unavailable.'}

    async def call(self, provider, url, endpoint, method, parser, hourly_limit=90, cache_duration=None, **kwargs):
        """Shared bounded transport/cache/budget; never cache raw responses or URLs."""
        now = self.clock()
        key = provider + ':' + digest(endpoint + '\n' + url)
        try:
            cached = await self.db('cache_get', key, now)
            if cached:
                value = ProviderResult.model_validate(cached)
                return value.model_copy(update={'cached': True, 'indicator': indicator_label(url) if value.matched else None})
            state = await self.state(provider)
            if state.get('retry_until', 0) > now:
                return result(provider, state.get('status', 'unavailable'), state.get('message', 'Provider is cooling down.'),
                              retry_at=timestamp(state['retry_until']), last_successful_check=state.get('last_successful_check'))
            allowed, until = await self.db('reserve', 'budget:' + provider, 3600, hourly_limit, now)
            if not allowed:
                value = result(provider, 'rate_limited', 'Application request budget reached. Local checks remain available.', retry_at=timestamp(until), last_successful_check=state.get('last_successful_check'))
                await self.db('set_meta', 'provider:' + provider, {**state, **value.model_dump(), 'retry_until': until})
                return value
        except Exception:
            LOG.warning(json.dumps({'event': 'provider_failure', 'provider': provider, 'code': 'storage_unavailable'}))
            return result(provider, 'unavailable', 'Threat cache and request budget are unavailable; external requests were paused.')
        try:
            async with self.client() as client:
                raw = await asyncio.wait_for(request_bytes(client, method, endpoint, **kwargs), self.settings.timeout + 1)
            data = json.loads(raw)
            value = parser(data)
            value.checked_at = timestamp(now)
            value.last_successful_check = timestamp(now)
            value.available = True
            value.indicator = indicator_label(url) if value.matched else None
            safe = value.model_copy(update={'indicator': None}).model_dump()
            ttl = self.settings.cache_ttl if cache_duration is None else min(self.settings.cache_ttl, max(0, cache_duration(data)))
            if ttl:
                await self.db('cache_put', key, safe, now + ttl)
            await self.db('set_meta', 'provider:' + provider, {'status': 'available', 'last_successful_check': timestamp(now), 'message': 'Last request succeeded.'})
            return value
        except (httpx.TimeoutException, asyncio.TimeoutError):
            code, retry = 'timeout', 60
        except ProviderFailure as exc:
            code, retry = exc.code, retry_seconds(exc.retry_after, now) if exc.code == 'rate_limited' else 60
        except (ValidationError, ValueError, TypeError, KeyError):
            code, retry = 'invalid_response', 60
        except httpx.RequestError:
            code, retry = 'connection_error', 60
        except Exception:
            code, retry = 'storage_unavailable', 60
        messages = {'timeout': 'Provider timed out.', 'rate_limited': 'Provider rate limit reached.', 'http_error': 'Provider returned an HTTP error.',
                    'invalid_response': 'Provider returned an unexpected response.', 'connection_error': 'Provider could not be reached.',
                    'response_too_large': 'Provider response exceeded the size limit.', 'storage_unavailable': 'Threat database is unavailable.'}
        status = 'rate_limited' if code == 'rate_limited' else 'unavailable'
        value = result(provider, status, messages[code], checked_at=timestamp(now), retry_at=timestamp(now + retry), last_successful_check=state.get('last_successful_check'))
        LOG.warning(json.dumps({'event': 'provider_failure', 'provider': provider, 'code': code}))
        try:
            await self.db('set_meta', 'provider:' + provider, {**value.model_dump(), 'retry_until': now + retry})
        except Exception:
            pass
        return value

    async def check_api(self, value):
        url = canonical_url(value)
        s = self.settings
        if not s.api_enabled:
            return result('openphish', 'disabled', 'API lookups are disabled.')
        if not endpoint_valid(s.api_url):
            return result('openphish', 'not_configured', 'Configure the HTTPS openphish.eu /api/check endpoint.')
        if not external_eligible(url):
            return result('openphish', 'skipped', 'Private, reserved, or demonstration URLs are not sent to external providers.')

        def parse(data):
            response = OpenPhishResponse.model_validate(data)
            if not response.found:
                return result('openphish', 'not_found', 'No record found. This does not establish safety.')
            record = response.phish
            if canonical_url(record.url) != url:
                raise ValueError('Mismatched URL in provider response.')
            confirmed = record.status == 'verified'
            return result('openphish', 'matched' if confirmed else 'unverified',
                          'Verified phishing record found.' if confirmed else 'A community report exists but is not verified.',
                          matched=True, confirmed=confirmed, target_brand=record.target_brand,
                          record_status=record.status, threat_type='phishing')
        return await self.call('openphish', url, s.api_url, 'GET', parse, s.api_hourly_limit, params={'url': url})

    def feed_problem(self):
        s = self.settings
        if not s.feed_enabled:
            return 'disabled', 'Community Feed lookups are disabled.'
        if not s.feed_permission:
            return 'not_configured', 'Community Feed usage permission must be confirmed.'
        if s.feed_url != OFFICIAL_FEED:
            return 'not_configured', 'A valid official Community Feed source is required.'
        if not self.store.durable:
            return 'not_configured', 'Hosted feed synchronization requires a persistent threat database.'
        return None

    async def check_feed(self, value):
        url = canonical_url(value)
        problem = self.feed_problem()
        if problem:
            return result('openphish_feed', *problem)
        try:
            state, found = await self.db('feed_snapshot', digest(url))
        except Exception:
            return result('openphish_feed', 'unavailable', 'Community Feed database is unavailable.')
        last = state.get('last_success', 0)
        if not last:
            return result('openphish_feed', 'unavailable', state.get('message', 'No successful feed synchronization yet.'))
        fresh = self.clock() - last <= self.settings.feed_max_age
        return result('openphish_feed', ('matched' if found else 'not_found') if fresh else 'stale',
                      ('Exact URL matched the local Community Feed.' if found else 'No local feed match. This does not establish safety.') if fresh else 'The last feed snapshot is stale; live verification is still needed.',
                      matched=found, confirmed=found and fresh, available=fresh, cached=True, checked_at=timestamp(self.clock()),
                      last_successful_check=timestamp(last), indicator=indicator_label(url) if found else None, threat_type='phishing' if found else None)

    async def sync_feed(self):
        problem = self.feed_problem()
        if problem:
            return {'status': problem[0], 'message': problem[1]}
        if not self.settings.feed_sync_enabled:
            return {'status': 'disabled', 'message': 'Feed synchronization is disabled.'}
        now = self.clock()
        try:
            state = await self.db('get_meta', 'feed')
            if state.get('next_sync', 0) > now:
                return {'status': 'not_due', 'message': 'Feed refresh is not due yet.', 'next_sync_at': timestamp(state['next_sync'])}
            allowed, until = await self.db('reserve', 'feed_sync_budget', max(43200, self.settings.feed_interval), 1, now)
            if not allowed:
                return {'status': 'not_due', 'message': 'Feed refresh is not due yet.', 'next_sync_at': timestamp(until)}
            async with self.client() as client:
                raw = await asyncio.wait_for(request_bytes(client, 'GET', self.settings.feed_url, limit=8 * 1024 * 1024), self.settings.timeout + 1)
            lines = raw.decode('utf-8-sig').splitlines()
            if not lines or len(lines) > 100000:
                raise ValueError('Invalid feed size.')
            hashes = set()
            for line in lines:
                if not line.strip():
                    continue
                # Reject an invalid snapshot rather than replacing good data with an HTML error page.
                if not re.match(r'^https?://', line):
                    raise ValueError('Invalid feed indicator.')
                hashes.add(digest(canonical_url(line)))
            if not hashes:
                raise ValueError('Empty feed.')
            state = {'status': 'available', 'last_success': now, 'last_attempt': now, 'count': len(hashes),
                     'duplicates_removed': len([x for x in lines if x.strip()]) - len(hashes), 'next_sync': until, 'message': 'Feed synchronized successfully.'}
            await self.db('replace_feed', hashes, state)
            LOG.info(json.dumps({'event': 'feed_sync', 'provider': 'openphish_feed', 'count': len(hashes)}))
            return await self.feed_status()
        except Exception as exc:
            code = 'rate_limited' if isinstance(exc, ProviderFailure) and exc.code == 'rate_limited' else 'sync_failed'
            LOG.warning(json.dumps({'event': 'feed_failure', 'provider': 'openphish_feed', 'code': code}))
            try:
                state = await self.db('get_meta', 'feed')
                retry = retry_seconds(exc.retry_after, now) if code == 'rate_limited' else 0
                until = max(state.get('next_sync', 0), now + max(43200, self.settings.feed_interval, retry))
                await self.db('set_meta', 'feed', {**state, 'status': code, 'last_attempt': now, 'next_sync': until,
                                               'message': 'Feed synchronization failed. The last successful snapshot was retained.'})
            except Exception:
                pass
            return {'status': 'rate_limited' if code == 'rate_limited' else 'unavailable', 'message': 'Feed synchronization failed; existing indicators were retained.'}

    async def feed_status(self):
        problem = self.feed_problem()
        if problem:
            return {'source': NAMES['openphish_feed'], 'status': problem[0], 'message': problem[1], 'sync_enabled': False, 'count': 0}
        try:
            state = await self.db('get_meta', 'feed')
        except Exception:
            state = {'status': 'unavailable', 'message': 'Feed database is unavailable.'}
        last = state.get('last_success')
        status = state.get('status', 'awaiting_sync')
        if last and self.clock() - last > self.settings.feed_max_age:
            status = 'stale'
        return {'source': NAMES['openphish_feed'], 'status': status, 'message': state.get('message', 'Waiting for the first synchronization.'),
                'sync_enabled': self.settings.feed_sync_enabled, 'count': state.get('count', 0),
                'last_successful_sync': timestamp(last) if last else None,
                'last_attempt': timestamp(state['last_attempt']) if state.get('last_attempt') else None,
                'next_sync_at': timestamp(state['next_sync']) if state.get('next_sync') else None,
                'interval_seconds': max(43200, self.settings.feed_interval), 'storage': 'PostgreSQL' if self.store.dsn else 'SQLite'}
