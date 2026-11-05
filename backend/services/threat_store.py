"""Hash-only indicator/cache storage; SQLite locally, PostgreSQL on Vercel.

No submitted URL, query, credential or raw provider payload is persisted.
All operations run in a worker thread when invoked by the async service.
"""
from contextlib import contextmanager
from pathlib import Path
import json
import os
import sqlite3
import threading
import time


class ThreatStore:
    def __init__(self, path=None, dsn=None):
        self.dsn = dsn or os.getenv('THREAT_DATABASE_URL') or os.getenv('THREAT_POSTGRES_URL')
        self.path = path or os.getenv('OPENPHISH_DB_PATH') or ('/tmp/phishguardx-threats.sqlite3' if os.getenv('VERCEL') else '.data/threats.sqlite3')
        self._ready = False
        self._lock = threading.Lock()

    @property
    def durable(self):
        return bool(self.dsn) or not bool(os.getenv('VERCEL'))

    def sql(self, query):
        return query if self.dsn else query.replace('%s', '?')

    @contextmanager
    def connection(self):
        if self.dsn:
            import psycopg
            conn = psycopg.connect(self.dsn, connect_timeout=5)
            # Neon transaction pooling rejects statement_timeout startup options.
            conn.execute("SET LOCAL statement_timeout = '5s'")
        else:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, timeout=5)
        try:
            if not self._ready:
                with self._lock:
                    for query in [
                        'CREATE TABLE IF NOT EXISTS threat_meta (name TEXT PRIMARY KEY, data TEXT NOT NULL)',
                        'CREATE TABLE IF NOT EXISTS threat_cache (key TEXT PRIMARY KEY, expires DOUBLE PRECISION NOT NULL, data TEXT NOT NULL)',
                        'CREATE TABLE IF NOT EXISTS threat_indicators (hash TEXT PRIMARY KEY)',
                    ]:
                        conn.execute(query)
                    conn.commit()
                    self._ready = True
            if self.dsn:
                conn.execute("SET LOCAL statement_timeout = '5s'")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _write_meta(self, conn, name, data):
        conn.execute(self.sql('INSERT INTO threat_meta (name,data) VALUES (%s,%s) ON CONFLICT(name) DO UPDATE SET data=excluded.data'), (name, json.dumps(data)))

    def get_meta(self, name):
        with self.connection() as conn:
            row = conn.execute(self.sql('SELECT data FROM threat_meta WHERE name=%s'), (name,)).fetchone()
            return json.loads(row[0]) if row else {}

    def set_meta(self, name, data):
        with self.connection() as conn:
            self._write_meta(conn, name, data)

    def cache_get(self, key, now):
        with self.connection() as conn:
            row = conn.execute(self.sql('SELECT data FROM threat_cache WHERE key=%s AND expires>%s'), (key, now)).fetchone()
            return json.loads(row[0]) if row else None

    def cache_put(self, key, data, expires):
        with self.connection() as conn:
            conn.execute(self.sql('DELETE FROM threat_cache WHERE expires<%s'), (time.time(),))
            # Bounded storage even under high-cardinality abuse.
            if conn.execute('SELECT COUNT(*) FROM threat_cache').fetchone()[0] >= 10000:
                conn.execute('DELETE FROM threat_cache WHERE key IN (SELECT key FROM threat_cache ORDER BY expires LIMIT 1000)')
            conn.execute(self.sql('INSERT INTO threat_cache (key,expires,data) VALUES (%s,%s,%s) ON CONFLICT(key) DO UPDATE SET expires=excluded.expires,data=excluded.data'), (key, expires, json.dumps(data)))

    def reserve(self, name, interval, limit, now):
        """Atomically reserve budget/lease across processes; fixed window starts at first use."""
        with self.connection() as conn:
            if not self.dsn:
                conn.execute('BEGIN IMMEDIATE')
            conn.execute(self.sql('INSERT INTO threat_meta (name,data) VALUES (%s,%s) ON CONFLICT(name) DO NOTHING'), (name, '{}'))
            suffix = ' FOR UPDATE' if self.dsn else ''
            data = json.loads(conn.execute(self.sql('SELECT data FROM threat_meta WHERE name=%s') + suffix, (name,)).fetchone()[0])
            if data.get('until', 0) <= now:
                data = {'until': now + interval, 'count': 0}
            if data['count'] >= limit:
                return False, data['until']
            data['count'] += 1
            self._write_meta(conn, name, data)
            return True, data['until']

    def feed_snapshot(self, url_hash):
        with self.connection() as conn:
            # One statement reads metadata and membership from the same snapshot.
            row = conn.execute(self.sql('SELECT data, EXISTS(SELECT 1 FROM threat_indicators WHERE hash=%s) FROM threat_meta WHERE name=%s'), (url_hash, 'feed')).fetchone()
            state = json.loads(row[0]) if row else {}
            found = bool(row[1]) if row else False
            return state, found

    def replace_feed(self, hashes, state):
        # One transaction: a failed/partial download never removes the last good snapshot.
        with self.connection() as conn:
            conn.execute('DELETE FROM threat_indicators')
            with conn.cursor() if self.dsn else _cursor(conn) as cursor:
                cursor.executemany(self.sql('INSERT INTO threat_indicators (hash) VALUES (%s) ON CONFLICT(hash) DO NOTHING'), [(h,) for h in set(hashes)])
            self._write_meta(conn, 'feed', state)


@contextmanager
def _cursor(conn):
    cursor = conn.cursor()
    try:
        yield cursor
    finally:
        cursor.close()
