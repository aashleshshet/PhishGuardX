import asyncio
from dataclasses import replace
import json
import logging
import sqlite3

import httpx
import pytest
from fastapi.testclient import TestClient
from backend.app import app, intelligence
from backend.services.openphish_service import (OpenPhishService, OpenPhishSettings, OFFICIAL_FEED,
    canonical_url, digest, timestamp)
from backend.services.threat_store import ThreatStore
from backend.services.threat_intelligence import ThreatIntelligence

URL = 'https://suspicious-site.org/login?token=PRIVATE_TEST_VALUE'
NOW = 1800000000.0

def run(task):
    return asyncio.run(task)

@pytest.fixture
def make(tmp_path, monkeypatch):
    for key in ['THREAT_DATABASE_URL','THREAT_POSTGRES_URL','VERCEL','PHISHTANK_ENABLED','GOOGLE_SAFE_BROWSING_ENABLED','URLHAUS_ENABLED']:
        monkeypatch.delenv(key, raising=False)
    counter = 0
    def factory(handler, **config):
        nonlocal counter
        counter += 1
        store = ThreatStore(str(tmp_path / f'threats-{counter}.sqlite3'))
        settings = replace(OpenPhishSettings(api_enabled=True), **config)
        return OpenPhishService(settings, store, httpx.MockTransport(handler), clock=lambda: NOW)
    return factory

def found(url=URL, status='verified'):
    return {'found': True, 'phish': {'id': 123, 'url': url, 'status': status, 'target_brand': 'Fixture bank', 'verified_at': '2026-01-01T00:00:00Z'}}

def test_api_exact_match_cached_without_sensitive_url(make):
    calls = []
    def handler(request):
        calls.append(request)
        assert request.url.host == 'openphish.eu'
        assert request.method == 'GET'
        assert request.url.params['url'] == URL
        return httpx.Response(200, json=found())
    service = make(handler)
    first = run(service.check_api(URL))
    second = run(service.check_api(URL))
    assert first.confirmed and first.status == 'matched' and second.cached
    assert len(calls) == 1 and 'PRIVATE_TEST_VALUE' not in first.indicator
    assert first.last_successful_check == timestamp(NOW)
    data = open(service.store.path, 'rb').read()
    assert b'PRIVATE_TEST_VALUE' not in data and URL.encode() not in data

def test_unknown_does_not_become_safe(make):
    service = make(lambda r: httpx.Response(200, json={'found': False}))
    result = run(ThreatIntelligence(service).analyze('url', URL))
    assert result['providers']['openphish']['status'] == 'not_found'
    assert result['verdict'] != 'safe'
    assert not result['providers']['openphish']['matched']
    assert result['models']

def test_verified_phishing_overrides_low_model_verdict(make):
    service = make(lambda r: httpx.Response(200, json=found('https://www.wikipedia.org/')))
    r = run(ThreatIntelligence(service).analyze('url', 'https://www.wikipedia.org/'))
    assert r['risk'] == 'high' and r['verdict'] == 'phishing'
    assert r['evidence'][0]['confirmed'] is True
    assert any(s['code'] == 'intel_openphish' for s in r['signals'])

def test_unverified_report_not_a_confirmed_match(make):
    service = make(lambda r: httpx.Response(200, json=found(status='unverified')))
    r = run(service.check_api(URL))
    assert r.matched and not r.confirmed and r.status == 'unverified'

@pytest.mark.parametrize('url', ['file:///etc/passwd','javascript:alert(1)','https://','https://bad..org','https://evil.org\\@localhost','https://bad.org:bad','https://bad.org/\nsecret'])
def test_invalid_urls_never_send_requests(make, url):
    service = make(lambda r: pytest.fail('Unexpected network'))
    with pytest.raises(ValueError):
        run(service.check_api(url))

@pytest.mark.parametrize('url', ['http://127.0.0.1/admin','http://169.254.169.254/metadata','http://[::1]/','https://demo.example/login','https://corp.local/path'])
def test_private_and_reserved_destinations_are_not_shared(make, url):
    service = make(lambda r: pytest.fail('Unexpected network'))
    assert run(service.check_api(url)).status == 'skipped'

def test_credentials_preserve_heuristics_without_leaking(make):
    service = make(lambda r: pytest.fail('Unexpected network'))
    r = run(ThreatIntelligence(service).analyze('url', 'https://name:SECRET@attacker.org/login'))
    assert r['risk'] == 'high' and r['url'] is None
    assert all(p['status'] == 'skipped' for p in r['providers'].values())

def test_conservative_normalization():
    assert canonical_url('HTTPS://EXAMPLE.ORG:443#secret') == 'https://example.org/'
    assert canonical_url('https://example.org/A?x=1&x=2') != canonical_url('https://example.org/a?x=2&x=1')
    assert canonical_url('https://example.org/a%2Fb') != canonical_url('https://example.org/a/b')

@pytest.mark.parametrize('body', [{'found':'true'}, {'found':True}, {}, {'found':False,'phish':found()['phish']}, found('https://different.org/'), {'found':True,'phish':{'url':URL}}])
def test_malformed_api_response_unknown(make, body):
    service = make(lambda r: httpx.Response(200, json=body))
    assert run(service.check_api(URL)).status == 'unavailable'

@pytest.mark.parametrize('status', [400,401,403,404,500,503,302])
def test_http_errors_are_not_negative_results(make, status):
    service = make(lambda r: httpx.Response(status, headers={'location':'http://127.0.0.1/'}, json={'found':False}))
    r = run(service.check_api(URL))
    assert r.status == 'unavailable' and not r.available

def test_timeout_and_logs_do_not_expose_url(make, caplog):
    def handler(request):
        raise httpx.ReadTimeout(str(request.url), request=request)
    service = make(handler)
    with caplog.at_level(logging.INFO):
        r = run(service.check_api(URL))
    assert r.status == 'unavailable' and 'timed out' in r.message
    assert 'PRIVATE_TEST_VALUE' not in caplog.text and URL not in caplog.text
    assert 'timeout' in caplog.text

def test_rate_limit_retry_after_is_obeyed(make):
    calls=[]
    service = make(lambda r: (calls.append(r) or httpx.Response(429, headers={'retry-after':'120'})))
    a=run(service.check_api(URL)); b=run(service.check_api('https://other-site.org/'))
    assert a.status == b.status == 'rate_limited' and len(calls)==1
    assert a.retry_at == timestamp(NOW+120)

def test_hourly_budget_prevents_more_requests(make):
    calls=[]
    service = make(lambda r: (calls.append(r) or httpx.Response(200,json={'found':False})), api_hourly_limit=1)
    run(service.check_api(URL))
    assert run(service.check_api('https://another-site.org/')).status == 'rate_limited'
    assert len(calls)==1

def test_cache_expiration(make):
    calls=[]
    service = make(lambda r: (calls.append(r) or httpx.Response(200,json={'found':False})), cache_ttl=60)
    run(service.check_api(URL)); service.clock=lambda:NOW+61
    assert not run(service.check_api(URL)).cached
    assert len(calls)==2

@pytest.mark.parametrize('config', [{'api_enabled':False}, {'api_url':''}, {'api_url':'http://openphish.eu/api/check'}, {'api_url':'https://127.0.0.1/api/check'}, {'api_url':'https://openphish.eu/api/check?secret=x'}])
def test_missing_or_unsafe_configuration(make, config):
    service=make(lambda r:pytest.fail('Unexpected network'),**config)
    assert run(service.check_api(URL)).status in ('disabled','not_configured')

def feed_service(make, handler):
    return make(handler,feed_enabled=True,feed_sync_enabled=True,feed_permission=True,feed_url=OFFICIAL_FEED)

def test_feed_sync_duplicates_local_match_and_no_api(make):
    calls=[]
    service=feed_service(make,lambda r:(calls.append(r) or httpx.Response(200,text=URL+'\n'+URL+'#fragment\nhttps://another-site.org/\n')))
    synced=run(service.sync_feed())
    assert synced['count']==2
    assert service.store.get_meta('feed')['duplicates_removed']==1
    r=run(ThreatIntelligence(service).analyze('url',URL))
    assert r['providers']['openphish_feed']['confirmed'] and r['providers']['openphish']['status']=='skipped'
    assert len(calls)==1 and calls[0].url.host=='raw.githubusercontent.com'
    assert run(service.sync_feed())['status']=='not_due'
    assert run(service.check_feed('https://no-match.org/')).status=='not_found'

def test_feed_failure_preserves_previous_snapshot(make):
    service=feed_service(make,lambda r:httpx.Response(200,text=URL+'\n'))
    run(service.sync_feed());service.clock=lambda:NOW+43201
    service.transport=httpx.MockTransport(lambda r:httpx.Response(503,text='not a feed'))
    assert run(service.sync_feed())['status']=='unavailable'
    assert run(service.check_feed(URL)).matched
    assert service.store.get_meta('feed')['last_success']==NOW

@pytest.mark.parametrize('body',['','<html>not a feed</html>','https://good.org/\ninvalid line'])
def test_malformed_feed_does_not_replace_data(make,body):
    service=feed_service(make,lambda r:httpx.Response(200,text=body))
    assert run(service.sync_feed())['status']=='unavailable'
    assert run(service.check_feed(URL)).status=='unavailable'

def test_stale_feed_is_unconfirmed_and_queries_api(make):
    service=feed_service(make,lambda r:httpx.Response(200,text=URL+'\n'))
    run(service.sync_feed());service.clock=lambda:NOW+129601
    service.transport=httpx.MockTransport(lambda r:httpx.Response(200,json={'found':False}))
    r=run(ThreatIntelligence(service).analyze('url',URL))
    assert r['providers']['openphish_feed']['status']=='stale'
    assert not r['providers']['openphish_feed']['confirmed']
    assert r['providers']['openphish']['status']=='not_found'

def test_feed_requires_permission_source_and_persistent_hosted_db(make,monkeypatch):
    for config in [{'feed_url':''},{'feed_permission':False}]:
        service=feed_service(make,lambda r:pytest.fail('Unexpected network'))
        service.settings=replace(service.settings,**config)
        assert run(service.sync_feed())['status']=='not_configured'
    monkeypatch.setenv('VERCEL','1')
    assert run(feed_service(make,lambda r:pytest.fail('Unexpected network')).sync_feed())['status']=='not_configured'

def test_sync_rate_limits_and_interval_floor(make):
    service=feed_service(make,lambda r:httpx.Response(429,headers={'retry-after':'60'}))
    service.settings=replace(service.settings,feed_interval=1)
    assert run(service.sync_feed())['status']=='rate_limited'
    service.clock=lambda:NOW+61
    assert run(service.sync_feed())['status']=='not_due'

def test_opt_out_skips_all_external_requests(make):
    r=run(ThreatIntelligence(make(lambda r:pytest.fail('Unexpected network'))).analyze('url',URL,live=False))
    assert r['providers']['openphish']['status']=='skipped' and r['models']

def test_feed_sync_route_requires_secret(monkeypatch):
    monkeypatch.setenv('CRON_SECRET','fixture-secret')
    client=TestClient(app)
    assert client.post('/internal/feed-sync').status_code==401
    assert client.post('/internal/feed-sync',headers={'Authorization':'Bearer wrong'}).status_code==401

def test_other_provider_adapters(make,monkeypatch):
    for key in ['PHISHTANK_ENABLED','GOOGLE_SAFE_BROWSING_ENABLED','URLHAUS_ENABLED']:
        monkeypatch.setenv(key,'true')
    monkeypatch.setenv('GOOGLE_SAFE_BROWSING_API_KEY','fixture-gsb');monkeypatch.setenv('URLHAUS_AUTH_KEY','fixture-haus')
    def handler(r):
        if r.url.host=='checkurl.dev.phishtank.com':
            return httpx.Response(200,json={'results':{'url':URL,'in_database':True,'verified':'y','valid':'y'}})
        if r.url.host=='safebrowsing.googleapis.com':
            return httpx.Response(200,json={'matches':[{'threatType':'SOCIAL_ENGINEERING','threat':{'url':URL},'cacheDuration':'300s'}]})
        assert r.headers['Auth-Key']=='fixture-haus'
        return httpx.Response(200,json={'query_status':'ok','url':URL,'threat':'malware_download','url_status':'offline'})
    pipeline=ThreatIntelligence(make(handler))
    for provider in ['phishtank','google_safe_browsing','urlhaus']:
        assert run(pipeline.other(provider,URL)).confirmed

def test_missing_other_provider_credentials(make,monkeypatch):
    monkeypatch.setenv('URLHAUS_ENABLED','true');monkeypatch.delenv('URLHAUS_AUTH_KEY',raising=False)
    r=run(ThreatIntelligence(make(lambda r:pytest.fail('Unexpected network'))).other('urlhaus',URL))
    assert r.status=='not_configured'

def test_feed_long_retry_after_is_obeyed(make):
    calls=[]
    service=feed_service(make,lambda r:(calls.append(r) or httpx.Response(429,headers={'retry-after':'80000'})))
    run(service.sync_feed());service.clock=lambda:NOW+50000
    assert run(service.sync_feed())['status']=='not_due'
    assert len(calls)==1

def test_google_cache_duration_limits_retention(make,monkeypatch):
    monkeypatch.setenv('GOOGLE_SAFE_BROWSING_ENABLED','true')
    monkeypatch.setenv('GOOGLE_SAFE_BROWSING_API_KEY','fixture')
    calls=[]
    service=make(lambda r:(calls.append(r) or httpx.Response(200,json={'matches':[{'threatType':'MALWARE','threat':{'url':URL},'cacheDuration':'30s'}]})))
    pipeline=ThreatIntelligence(service)
    run(pipeline.other('google_safe_browsing',URL))
    assert run(pipeline.other('google_safe_browsing',URL)).cached
    service.clock=lambda:NOW+31
    assert not run(pipeline.other('google_safe_browsing',URL)).cached
    assert len(calls)==2
