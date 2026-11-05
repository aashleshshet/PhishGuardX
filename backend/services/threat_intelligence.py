"""Evidence-preserving orchestration. A missing record never establishes safety."""
import asyncio
import os
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from .openphish_service import (OpenPhishService, NAMES, canonical_url, external_eligible,
                               result, timestamp, flag, endpoint_valid)
try:
    from ..engine import analyze, normalize_url, signal, MODELS
except ImportError:
    from engine import analyze, normalize_url, signal, MODELS


class TankRecord(BaseModel):
    model_config = ConfigDict(extra='ignore')
    in_database: StrictBool
    url: Optional[str] = None
    verified: bool = False
    valid: bool = False

    @field_validator('verified', 'valid', mode='before')
    @classmethod
    def boolean(cls, value):
        if value is True or value in ('y', 'yes'):
            return True
        if value is False or value in ('n', 'no'):
            return False
        raise ValueError('Unknown verification value.')


class TankResponse(BaseModel):
    results: TankRecord


class SafeMatch(BaseModel):
    threatType: Literal['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION']
    threat: dict[str, str]
    cacheDuration: str = Field(default='0s', pattern=r'^\d+(\.\d+)?s$')


class SafeResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    matches: list[SafeMatch] = Field(default_factory=list, max_length=100)


class HausResponse(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)
    query_status: Literal['ok', 'no_results']
    url: Optional[str] = None
    url_status: Optional[str] = None
    threat: Optional[str] = None


class ThreatIntelligence:
    def __init__(self, openphish=None):
        self.openphish = openphish or OpenPhishService()

    def provider_config(self):
        return {
            'phishtank': (flag('PHISHTANK_ENABLED'), True),
            'google_safe_browsing': (flag('GOOGLE_SAFE_BROWSING_ENABLED'), bool(os.getenv('GOOGLE_SAFE_BROWSING_API_KEY'))),
            'urlhaus': (flag('URLHAUS_ENABLED'), bool(os.getenv('URLHAUS_AUTH_KEY'))),
        }

    async def other(self, provider, url):
        enabled, configured = self.provider_config()[provider]
        if not enabled:
            return result(provider, 'disabled', 'Provider is disabled.')
        if not configured:
            return result(provider, 'not_configured', 'Provider credentials are not configured.')
        if not external_eligible(url):
            return result(provider, 'skipped', 'Private, reserved, or demonstration URLs are not sent to providers.')
        service = self.openphish
        if provider == 'phishtank':
            def parse(data):
                record = TankResponse.model_validate(data).results
                if record.in_database and (not record.url or canonical_url(record.url) != url):
                    raise ValueError('Mismatched URL.')
                confirmed = record.in_database and record.verified and record.valid
                return result(provider, 'matched' if confirmed else 'unverified' if record.in_database else 'not_found',
                              'Verified phishing record found.' if confirmed else 'No verified phishing match; absence does not establish safety.',
                              matched=record.in_database, confirmed=confirmed, threat_type='phishing' if record.in_database else None)
            data = {'url': url, 'format': 'json'}
            if os.getenv('PHISHTANK_API_KEY'):
                data['app_key'] = os.environ['PHISHTANK_API_KEY']
            return await service.call(provider, url, 'https://checkurl.dev.phishtank.com/checkurl/', 'POST', parse, 10,
                                      data=data, headers={'User-Agent': 'phishtank/PhishGuardX'})
        if provider == 'google_safe_browsing':
            def parse(data):
                records = SafeResponse.model_validate(data).matches
                if any(canonical_url(r.threat.get('url', '')) != url for r in records):
                    raise ValueError('Mismatched URL.')
                return result(provider, 'matched' if records else 'not_found',
                              'Google Safe Browsing lists this URL as a threat.' if records else 'No list match. This does not establish safety.',
                              matched=bool(records), confirmed=bool(records), threat_type=', '.join(sorted({r.threatType for r in records})) or None)
            body = {'client': {'clientId': 'phishguardx', 'clientVersion': '1.1'},
                    'threatInfo': {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                                   'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'], 'threatEntries': [{'url': url}]}}
            return await service.call(provider, url, 'https://safebrowsing.googleapis.com/v4/threatMatches:find', 'POST', parse,
                                      cache_duration=lambda data: min([float(r.cacheDuration[:-1]) for r in SafeResponse.model_validate(data).matches] or [service.settings.cache_ttl]),
                                      params={'key': os.environ['GOOGLE_SAFE_BROWSING_API_KEY']}, json=body)
        def parse(data):
            record = HausResponse.model_validate(data)
            matched = record.query_status == 'ok'
            if matched and (not record.url or canonical_url(record.url) != url):
                raise ValueError('Mismatched URL.')
            return result(provider, 'matched' if matched else 'not_found',
                          'URLhaus has a malware URL record (not specifically a phishing verdict).' if matched else 'No malware URL record. This does not establish safety.',
                          matched=matched, confirmed=matched, record_status=record.url_status, threat_type='malware' if matched else None)
        return await service.call(provider, url, 'https://urlhaus-api.abuse.ch/v1/url/', 'POST', parse,
                                  data={'url': url}, headers={'Auth-Key': os.environ['URLHAUS_AUTH_KEY']})

    async def check(self, value, live=True):
        normalize_url(value)  # Invalid input is rejected before any provider or model work.
        try:
            url = canonical_url(value)
        except ValueError:
            return {p: result(p, 'skipped', 'Embedded credentials are not shared with reputation providers.') for p in NAMES}
        feed = await self.openphish.check_feed(url)
        providers = {'openphish_feed': feed}
        if not live:
            providers['openphish'] = result('openphish', 'skipped', 'Live reputation checks were turned off for this scan.')
        elif feed.confirmed:
            providers['openphish'] = result('openphish', 'skipped', 'A fresh local feed match avoided an additional API request.')
        else:
            providers['openphish'] = await self.openphish.check_api(url)
        others = list(self.provider_config())
        if live:
            responses = await asyncio.gather(*(self.other(p, url) for p in others))
        else:
            responses = [result(p, 'skipped', 'Live checks were turned off for this scan.') for p in others]
        providers.update(zip(others, responses))
        return providers

    async def analyze(self, kind, content, headers='', live=True):
        # Email/screenshot contents remain local to the analysis backend. Only explicit
        # URL and decoded QR scans invoke external reputation providers.
        if kind not in ('url', 'qr'):
            return await asyncio.to_thread(analyze, kind, content, headers)
        providers = await self.check(content, live)
        analysis = await asyncio.to_thread(analyze, kind, content, headers)
        try:
            normalized = canonical_url(content)
        except ValueError:
            normalized = None
        evidence = []
        for provider, entry in providers.items():
            if entry.matched:
                confirmed = entry.confirmed
                title = f'{entry.source}: {"confirmed threat match" if confirmed else "unconfirmed or stale report"}'
                detail = entry.message + (' Target: ' + entry.target_brand if entry.target_brand else '')
                item = signal('intel_' + provider, title, detail, 'danger' if confirmed else 'warning', entry.indicator or '')
                analysis['signals'].append(item)
                evidence.append({'source': entry.source, 'confirmed': confirmed, 'indicator': entry.indicator, 'description': detail})
        confirmed = any(r.confirmed for r in providers.values())
        if confirmed:
            analysis['risk'] = 'high'
            analysis['summary'] = 'A threat-intelligence provider confirmed a match for this exact URL. Do not proceed; verify through an independent channel.'
        elif evidence and analysis['risk'] == 'low':
            analysis['risk'] = 'review'
            analysis['summary'] = 'An unverified or stale threat report needs review. It is not a confirmed current detection.'
        available = any(r.available for r in providers.values())
        if available:
            analysis['unavailable'] = [x for x in analysis['unavailable'] if x != 'Live threat reputation']
        analysis['details']['reputation'] = 'Confirmed threat match' if confirmed else 'No confirmed match; safety unknown'
        analysis.update(url=normalized, verdict='phishing' if confirmed and any(r.confirmed and r.threat_type == 'phishing' for r in providers.values()) else 'high_risk' if analysis['risk'] == 'high' else 'suspicious' if analysis['risk'] == 'review' else 'unknown',
                        providers={p: r.model_dump() for p, r in providers.items()}, evidence=evidence, checked_at=timestamp())
        analysis['privacy']['reputationRequested'] = live
        analysis['method'] += ' Independent threat intelligence is included when available; no-match results never prove safety.'
        return analysis

    async def status(self):
        s = self.openphish.settings
        providers = {}
        config = {'openphish': (s.api_enabled, endpoint_valid(s.api_url)), **self.provider_config()}
        for p, (enabled, configured) in config.items():
            state = await self.openphish.state(p) if enabled and configured else {}
            status = state.get('status', 'not_checked') if enabled and configured else 'not_configured' if enabled else 'disabled'
            providers[p] = {'source': NAMES[p], 'status': status, 'enabled': enabled, 'configured': configured,
                            'last_successful_check': state.get('last_successful_check'),
                            'retry_at': state.get('retry_at'),
                            'message': state.get('message', 'Ready for the next URL check.' if enabled and configured else 'Enable and configure this provider to use it.')}
        return {'providers': providers, 'feed': await self.openphish.feed_status(), 'checked_at': timestamp(),
                'storage': 'PostgreSQL' if self.openphish.store.dsn else 'SQLite',
                'durable_storage': self.openphish.store.durable, 'model_available': all((MODELS / (k + '.json')).exists() for k in ('url', 'email'))}
