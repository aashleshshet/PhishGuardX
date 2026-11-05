from pathlib import Path
import os, json, hashlib, re, secrets
from functools import lru_cache
from typing import Literal
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
try:
    from .engine import analyze, MODELS
    from .services.threat_intelligence import ThreatIntelligence
except ImportError:
    from engine import analyze, MODELS
    from services.threat_intelligence import ThreatIntelligence

app=FastAPI(title='PhishGuardX Analysis API',version='1.0.0',description='Threat intelligence, URL heuristics and calibrated baseline models. Submitted destinations are never visited.')

@app.middleware('http')
async def bound_input(request:Request,call_next):
    if request.method in ('POST','PUT','PATCH'):
        size=0; chunks=[]
        async for chunk in request.stream():
            size+=len(chunk)
            if size>131072: return JSONResponse({'detail':'Request exceeds 128 KB.'},status_code=413)
            chunks.append(chunk)
        request._body=b''.join(chunks)
    response=await call_next(request)
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    return response

class Scan(BaseModel):
    kind:Literal['url','email','qr','screenshot']
    content:str=Field(min_length=1,max_length=30000)
    headers:str=Field(default='',max_length=20000)
    check_reputation:bool=True

@lru_cache(maxsize=1)
def intelligence():
    return ThreatIntelligence()

@app.get('/health')
def health():
    return {'status':'ok','models':all((MODELS/(k+'.json')).exists() for k in ('url','email')),'reputation':intelligence().openphish.settings.api_enabled or intelligence().openphish.settings.feed_enabled,'cloudHistory':bool(os.getenv('DATABASE_URL')),'externalAI':False}

@app.get('/models')
def models(): return json.loads((MODELS/'evaluation.json').read_text())

@app.post('/analyze')
async def scan(payload:Scan):
    try: return await intelligence().analyze(payload.kind,payload.content,payload.headers,payload.check_reputation)
    except ValueError as exc: raise HTTPException(422,str(exc))
    except FileNotFoundError: raise HTTPException(503,'Models are unavailable. Run the documented training pipeline.')

# Optional Postgres persistence accepts only metadata, never raw text, URLs or evidence.
class Record(BaseModel):
    id:str=Field(pattern=r'^[0-9a-f-]{36}$')
    kind:Literal['url','email','qr','screenshot']
    risk:Literal['low','review','high']
    signal_count:int=Field(ge=0,le=100)

def owner(token):
    if not token or not re.fullmatch(r'[a-f0-9]{64}',token): raise HTTPException(401,'A private history token is required.')
    return hashlib.sha256(token.encode()).hexdigest()

def database():
    if not os.getenv('DATABASE_URL'): raise HTTPException(503,'Cloud history is not configured. Browser-local history is available.')
    import psycopg
    return psycopg.connect(os.environ['DATABASE_URL'],connect_timeout=5)

@app.post('/history')
def save_history(record:Record,x_history_token:str=Header(default='')):
    identity=owner(x_history_token)
    with database() as conn:
        conn.execute('INSERT INTO scan_history (id,owner,kind,risk,signal_count) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (id,owner) DO NOTHING',(record.id,identity,record.kind,record.risk,record.signal_count))
    return {'saved':True}

@app.get('/history')
def get_history(x_history_token:str=Header(default='')):
    identity=owner(x_history_token)
    with database() as conn:
        rows=conn.execute('SELECT id,kind,risk,signal_count,created_at FROM scan_history WHERE owner=%s ORDER BY created_at DESC LIMIT 100',(identity,)).fetchall()
    return [{'id':r[0],'kind':r[1],'risk':r[2],'signal_count':r[3],'createdAt':r[4].isoformat()} for r in rows]

@app.delete('/history')
def delete_history(x_history_token:str=Header(default='')):
    identity=owner(x_history_token)
    with database() as conn: conn.execute('DELETE FROM scan_history WHERE owner=%s',(identity,))
    return {'deleted':True}

@app.get('/threat-intelligence')
async def threat_status():
    return await intelligence().status()

@app.post('/internal/feed-sync')
async def feed_sync(authorization:str=Header(default='')):
    secret=os.getenv('CRON_SECRET','')
    if not secret or not secrets.compare_digest(authorization, 'Bearer '+secret):
        raise HTTPException(401,'Authorized scheduler required.')
    return await intelligence().openphish.sync_feed()
