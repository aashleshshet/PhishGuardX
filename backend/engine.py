"""Offline, evidence-first analysis. This module never retrieves submitted URLs."""
from pathlib import Path
from functools import lru_cache
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from html import unescape
from urllib.parse import urlsplit, unquote
import ipaddress, json, math, re, uuid
import tldextract

MODELS=Path(__file__).parent/'models'
EXTRACT=tldextract.TLDExtract(suffix_list_urls=(),cache_dir=None)
BRANDS={'paypal':'paypal.com','microsoft':'microsoft.com','apple':'apple.com','google':'google.com','amazon':'amazon.com','netflix':'netflix.com','facebook':'facebook.com','instagram':'instagram.com'}

@lru_cache(maxsize=2)
def load_model(kind): return json.loads((MODELS/(kind+'.json')).read_text())

def sigmoid(value): return 1/(1+math.exp(-max(-700,min(700,value))))

def predict(text,kind):
    model=load_model(kind); text=text.lower()
    # Match sklearn's char analyzer whitespace normalization and word tokenization.
    lo,hi=model['ngram_range']; counts=Counter()
    if model['analyzer']=='char':
        text=re.sub(r'\s\s+',' ',text)
        for n in range(lo,hi+1): counts.update(text[i:i+n] for i in range(max(0,len(text)-n+1)))
    else:
        tokens=re.findall(r'(?u)\b\w\w+\b',text)
        for n in range(lo,hi+1): counts.update(' '.join(tokens[i:i+n]) for i in range(max(0,len(tokens)-n+1)))
    values=[]
    for feature,count in counts.items():
        params=model['features'].get(feature)
        if params: values.append((feature,(1+math.log(count))*params[0],params[1]))
    norm=math.sqrt(sum(v*v for _,v,_ in values)) or 1
    contributions=[(f,v/norm*w) for f,v,w in values]
    score=model['intercept']+sum(c for _,c in contributions)
    a,b=model['calibration']; probability=sigmoid(a*score+b)
    evidence=sorted(((f,round(c,4)) for f,c in contributions if c>0),key=lambda pair:pair[1],reverse=True)[:5]
    return {'name':'URL lexical classifier' if kind=='url' else 'Email spam classifier','version':model['version'],'probability':round(probability,6),'threshold':model['threshold'],'positiveClass':'phishing' if kind=='url' else 'spam','outOfDomain':False,'matchedFeatures':len(values),'features':[{'text':f,'contribution':c} for f,c in evidence]}

def signal(code,title,description,severity='warning',evidence=''):
    return {'code':code,'title':title,'description':description,'severity':severity,'evidence':evidence[:240]}

def registered(host):
    domain=EXTRACT(host).top_domain_under_public_suffix
    # Reserved example namespaces have no PSL entry; use their final two labels for demos.
    if not domain and host.rsplit('.',1)[-1] in ('example','test','invalid'):
        return '.'.join(host.split('.')[-2:])
    return domain or host

def normalize_url(value):
    value=value.strip()
    if not value or len(value)>4096 or re.search(r'[\x00-\x20\x7f\\]',value): raise ValueError('Enter one URL without spaces, control characters, or backslashes.')
    if not re.match(r'^https?://',value,re.I):
        if '://' in value or re.match(r'^[a-z][a-z0-9+.-]*:',value,re.I): raise ValueError('Only HTTP and HTTPS URLs can be analyzed.')
        value='https://'+value
    parts=urlsplit(value)
    if parts.scheme.lower() not in ('http','https') or not parts.hostname: raise ValueError('Enter a complete HTTP or HTTPS URL.')
    try: host=parts.hostname.encode('idna').decode('ascii').lower()
    except UnicodeError: raise ValueError('The URL contains an invalid domain.')
    try: is_ip=bool(ipaddress.ip_address(host))
    except ValueError: is_ip=False
    # Access port separately: malformed ports must not be swallowed as non-IP errors.
    try: port=parts.port
    except ValueError: raise ValueError('The URL port is invalid.')
    if not is_ip and ('.' not in host or len(host)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.'))):
        raise ValueError('Enter a valid public domain such as example.com.')
    return value,parts,host,is_ip

def url_analysis(value):
    url,parts,host,is_ip=normalize_url(value); domain=registered(host); findings=[]
    if parts.scheme=='http': findings.append(signal('unencrypted','Unencrypted connection','HTTP does not encrypt traffic. This is a warning sign, not proof of phishing.','warning',parts.scheme+'://'))
    if parts.username is not None: findings.append(signal('userinfo','Hidden destination in URL','Text before @ is user information, not the destination domain.','danger',host))
    if is_ip:
        findings.append(signal('ip_address','IP address as destination','This address uses an IP instead of a recognizable domain.','warning',host))
        if not ipaddress.ip_address(host).is_global: findings.append(signal('private_address','Local or reserved destination','This address refers to a private or reserved network. It was not contacted.','warning',host))
    if 'xn--' in host or any(ord(c)>127 for c in (parts.hostname or '')): findings.append(signal('idn','Internationalized domain','Unicode or Punycode can be legitimate, but visually similar characters can disguise a domain.','warning',host))
    for brand,official in BRANDS.items():
        decoded=unquote(host).replace('0','o').replace('1','l')
        if brand in decoded and domain!=official:
            findings.append(signal('brand_domain','Possible brand impersonation',f'The hostname references {brand.title()} but its registered domain is not {official}. Other domains may still be legitimate; verify independently.','danger',domain)); break
    if len(host.split('.'))>=5: findings.append(signal('subdomains','Deeply nested hostname','Many subdomains can make the actual registered domain difficult to spot.','warning',host))
    if len(url)>180: findings.append(signal('long_url','Unusually long URL','Long URLs can conceal the destination or tracking parameters.','info',str(len(url))+' characters'))
    if re.search(r'(?:redirect|url|next|continue|return)=https?%?[:3]',parts.query,re.I): findings.append(signal('redirect_parameter','Embedded redirect destination','A query parameter appears to contain another URL. Redirects were not followed.','warning'))
    if registered(host) in {'bit.ly','tinyurl.com','t.co','shorturl.at','is.gd'}: findings.append(signal('shortener','Shortened destination','The final destination is hidden. This scanner does not expand shortened URLs.','warning',host))
    model=predict(re.sub(r'^https?://','',url.lower()).rstrip('/'),'url')
    if model['probability']>=model['threshold']: findings.append(signal('url_model','Phishing-like URL patterns','The calibrated lexical model classified this URL above its validation-selected threshold. This is a statistical signal, not a reputation verdict.','warning'))
    return findings,model,{'hostname':host,'registeredDomain':domain,'protocol':parts.scheme.upper(),'visited':False,'reputation':'Not checked','redirects':'Not followed','dns':'Not queried','domainAge':'Not available'}

class HTMLText(HTMLParser):
    def __init__(self): super().__init__(); self.text=[]; self.links=[]; self.skip=0
    def handle_starttag(self,tag,attrs):
        if tag in ('script','style'): self.skip+=1
        if tag=='a':
            href=dict(attrs).get('href','')
            if re.match(r'https?://',href,re.I): self.links.append(href)
    def handle_endtag(self,tag):
        if tag in ('script','style'): self.skip=max(0,self.skip-1)
    def handle_data(self,data):
        if not self.skip: self.text.append(data)

def parse_email(raw,headers):
    full=headers+'\n\n'+raw if headers.strip() else raw
    is_message=bool(headers.strip() or re.match(r'^(?:from|to|subject|received|mime-version|return-path|authentication-results):',raw,re.I))
    msg=Parser(policy=policy.default).parsestr(full) if is_message else Parser(policy=policy.default).parsestr('\n'+raw)
    chunks=[str(msg.get('Subject',''))]; links=[]
    for part in msg.walk():
        if part.get_content_disposition()=='attachment': continue
        if part.get_content_type() in ('text/plain','text/html'):
            try: content=part.get_content()
            except (LookupError,UnicodeError): content=str(part.get_payload())
            if not isinstance(content,str): continue
            if part.get_content_type()=='text/html' or '<html' in content.lower() or '<a ' in content.lower():
                parser=HTMLText(); parser.feed(content); chunks.extend(parser.text); links.extend(parser.links)
            else: chunks.append(content)
    return re.sub(r'\s+',' ',' '.join(chunks)).strip()[:30000],msg,links

def analyze(kind,content,headers=''):
    if not content.strip(): raise ValueError('Add content before starting an analysis.')
    findings=[]; models=[]; details={}; urls=[]; authentication=[]; text=content
    if kind in ('url','qr'):
        findings,model,details=url_analysis(content); models.append(model)
    else:
        text,msg,html_links=parse_email(content,headers)
        model=predict(text,'email'); model['outOfDomain']=kind=='screenshot'; models.append(model)
        patterns=[('urgency','Pressure to act quickly',r'\b(urgent|immediately|within \d+ hours?|act now|final warning|last chance|suspend(?:ed)?|expire[sd]?)\b','A deadline or threat can pressure you into skipping verification.','warning'),('credentials','Request for sensitive information',r'\b(password|passcode|verification code|credit card|social security|seed phrase|bank details|login credentials)\b','Sensitive information is mentioned. Check whether the sender is asking you to disclose it.','warning'),('reward','Reward or prize language',r'\b(winner|won a|claim your|lottery|free money|guaranteed returns)\b','Unexpected rewards can be used to solicit payments or personal information.','warning'),('payment','Unusual payment request',r'\b(gift cards?|wire transfer|bitcoin|crypto wallet|processing fee)\b','Irreversible or unusual payment methods deserve independent verification.','warning')]
        for code,title,pattern,desc,severity in patterns:
            match=re.search(pattern,text,re.I)
            if match: findings.append(signal(code,title,desc,severity,text[max(0,match.start()-35):match.end()+55]))
        if model['probability']>=model['threshold']: findings.append(signal('spam_model','Spam-like language patterns','The email model detected patterns associated with historical spam. Spam is not the same as phishing.','warning'))
        urls=list(dict.fromkeys(html_links+re.findall(r'https?://[^\s<>"\)]+',text)))[:10]
        for url in urls:
            try:
                f,m,d=url_analysis(url.rstrip('.,;')); findings.extend(f); models.append(m)
                details.setdefault('destinations',[]).append(d)
            except ValueError: findings.append(signal('invalid_link','Malformed link','An extracted link could not be parsed reliably.','warning',url[:120]))
        if kind=='email':
            auth=' '.join(str(x) for x in msg.get_all('Authentication-Results',[]))
            for mechanism in ('spf','dkim','dmarc'):
                matches=re.findall(r'\b'+mechanism+r'\s*=\s*([a-z]+)',auth,re.I)
                value=', '.join(dict.fromkeys(m.lower() for m in matches)) if matches else 'unavailable'
                authentication.append({'name':mechanism.upper(),'result':value,'verified':False})
                if any(x.lower() in ('fail','softfail','permerror') for x in matches): findings.append(signal(mechanism+'_fail',mechanism.upper()+' failure reported','The pasted header reports a failure. Pasted authentication results are unverified and can be forged.','warning',value))
            sender=parseaddr(str(msg.get('From','')))[1].split('@')[-1].lower()
            reply=parseaddr(str(msg.get('Reply-To','')))[1].split('@')[-1].lower()
            if sender and reply and registered(sender)!=registered(reply): findings.append(signal('reply_mismatch','Different reply destination','Reply-To uses a different registered domain from From. This can be legitimate, but verify unexpected requests.','warning',reply))
            details['authentication']=authentication
        else: findings.append(signal('ocr_limit','Screenshot evidence is limited','OCR may miss or misread text. A screenshot cannot prove a website’s identity or authenticity.','info'))
    # Deduplicate repeated evidence codes and snippets, never add arbitrary numeric risk points.
    findings=list({(f['code'],f['evidence']):f for f in findings}.values())
    codes={f['code'] for f in findings}
    risk='high' if ('brand_domain' in codes or 'userinfo' in codes or {'credentials','urgency'}<=codes or {'payment','urgency'}<=codes) else ('review' if any(f['severity']!='info' for f in findings) else 'low')
    summary={'high':'Strong warning signs were detected. Verify through an independent channel before taking action.','review':'This content needs a closer look. Review the evidence and verify unexpected requests.','low':'Few warning signs were detected in the available evidence. This does not establish that the content is safe.'}[risk]
    unavailable=['Live threat reputation','Domain registration age','Redirect destinations','Website content']
    if kind=='email' and all(a['result']=='unavailable' for a in authentication): unavailable.append('Email authentication headers')
    if kind=='screenshot': unavailable.append('Visual brand verification')
    return {'id':str(uuid.uuid4()),'createdAt':datetime.now(timezone.utc).isoformat(),'kind':kind,'risk':risk,'summary':summary,'signals':findings,'models':models,'details':details,'links':urls,'unavailable':unavailable,'recommendations':['Open the organization’s official app or type its known address yourself.','Confirm unexpected requests using a trusted contact method.','Never share passwords, one-time codes, or recovery phrases in response to a message.'],'privacy':{'retained':False,'externalAI':False,'urlsVisited':False},'evidenceText':text if kind in ('email','screenshot') else '', 'method':'Calibrated baseline models + explicit evidence rules. Risk categories are not probabilities.'}
