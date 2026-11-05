"""Reproducible offline training; downloads only fixed, trusted dataset archives."""
from pathlib import Path
import csv, io, json, re, hashlib, tarfile, zipfile, urllib.request, sys
from email import policy
from email.parser import BytesParser
from html import unescape
from urllib.parse import urlsplit
import numpy as np
import pandas as pd
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, brier_score_loss, accuracy_score

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'ml/data'; DATA.mkdir(exist_ok=True)
OUT = ROOT / 'backend/models'; OUT.mkdir(exist_ok=True)
extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
SOURCES = {}

def download(name, url):
    path = DATA / name
    if not path.exists():
        req = urllib.request.Request(url, headers={'User-Agent':'PhishGuardX-research/1.0'})
        with urllib.request.urlopen(req, timeout=180) as response: path.write_bytes(response.read())
    SOURCES[name] = {'url':url, 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    return path

def email_text(data):
    msg = BytesParser(policy=policy.default).parsebytes(data)
    chunks = [str(msg.get('Subject',''))]
    for part in msg.walk():
        if part.get_content_type() in ('text/plain','text/html') and part.get_content_disposition() != 'attachment':
            raw = part.get_payload(decode=True)
            if raw:
                try: text = raw.decode(part.get_content_charset() or 'utf-8', errors='replace')
                except LookupError: text = raw.decode('utf-8', errors='replace')
                if part.get_content_type() == 'text/html': text = unescape(re.sub(r'<[^>]+>', ' ', text))
                chunks.append(text)
    return re.sub(r'\s+',' ', ' '.join(chunks)).strip()[:30000]

def load_emails():
    rows = []
    for name,label in [('20030228_easy_ham',0),('20030228_hard_ham',0),('20030228_spam',1),('20050311_spam_2',1)]:
        path = download(name+'.tar.bz2', 'https://spamassassin.apache.org/old/publiccorpus/'+name+'.tar.bz2')
        with tarfile.open(path,'r:bz2') as archive:
            for member in archive.getmembers():
                if member.isfile() and '/' in member.name and not member.name.endswith(('cmds','README')):
                    text = email_text(archive.extractfile(member).read())
                    if len(text)>15: rows.append({'text':text,'label':label})
    frame = pd.DataFrame(rows)
    # Collapse whitespace/digits/URLs to group common campaign templates together.
    frame['group'] = frame.text.map(lambda s: hashlib.sha256(re.sub(r'\d+','0',re.sub(r'https?://\S+','URL',re.sub(r'\s+',' ',s.lower()))).encode()).hexdigest())
    return frame.drop_duplicates('group').reset_index(drop=True)

def load_urls():
    path = download('phiusiil.zip', 'https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip')
    with zipfile.ZipFile(path) as archive:
        frame = pd.read_csv(archive.open(next(n for n in archive.namelist() if n.endswith('.csv'))), usecols=['URL','label'])
    frame['text'] = frame.URL.str.replace(r'^https?://','',regex=True).str.lower().str.rstrip('/')
    frame['label'] = 1-frame.label # Source: 1 legitimate, 0 phishing.
    frame = frame.drop_duplicates('text').sample(n=min(60000,len(frame)), random_state=42)
    def group(text):
        host = urlsplit('https://'+text).hostname or text
        domain = extract(host).top_domain_under_public_suffix
        return domain or host
    frame['group'] = frame.text.map(group)
    return frame[['text','label','group']].reset_index(drop=True)

def split(frame, fraction, seed):
    a,b=next(GroupShuffleSplit(n_splits=1,test_size=fraction,random_state=seed).split(frame,frame.label,frame.group))
    return frame.iloc[a],frame.iloc[b]

def metrics(y,p,threshold=.5):
    pred=p>=threshold
    return {'precision':float(precision_score(y,pred,zero_division=0)), 'recall':float(recall_score(y,pred,zero_division=0)), 'f1':float(f1_score(y,pred,zero_division=0)), 'accuracy':float(accuracy_score(y,pred)), 'brier':float(brier_score_loss(y,p)), 'confusion_matrix':confusion_matrix(y,pred,labels=[0,1]).tolist(), 'count':len(y)}

def train(kind, frame):
    remaining,test=split(frame,.2,42)
    fit,heldout=split(remaining,.25,43)
    validation,calibration=split(heldout,.5,44)
    groups=[set(x.group) for x in [fit,validation,calibration,test]]
    assert all(not groups[i]&groups[j] for i in range(4) for j in range(i+1,4))
    vectorizer=TfidfVectorizer(analyzer='char' if kind=='url' else 'word',ngram_range=(2,5) if kind=='url' else (1,2),max_features=18000,min_df=2,sublinear_tf=True)
    x=vectorizer.fit_transform(fit.text); v=vectorizer.transform(validation.text)
    lr=LogisticRegression(C=4,max_iter=500,random_state=42,solver='liblinear').fit(x,fit.label)
    nb=MultinomialNB(alpha=.5).fit(x,fit.label)
    comparison={'logistic_regression':metrics(validation.label,lr.predict_proba(v)[:,1]), 'naive_bayes':metrics(validation.label,nb.predict_proba(v)[:,1])}
    # Transparent linear model is the shipped baseline; NB is a documented comparator.
    calibration_scores=lr.decision_function(vectorizer.transform(calibration.text)).reshape(-1,1)
    calibrator=LogisticRegression(C=1000,random_state=42,solver='liblinear').fit(calibration_scores,calibration.label)
    probabilities=lambda text: calibrator.predict_proba(lr.decision_function(vectorizer.transform(text)).reshape(-1,1))[:,1]
    vp=probabilities(validation.text)
    choices=np.linspace(.1,.9,81)
    threshold=float(max(choices,key=lambda t:f1_score(validation.label,vp>=t)))
    test_p=probabilities(test.text)
    report=metrics(test.label,test_p,threshold)
    report.update({'kind':kind,'positive_class':'phishing' if kind=='url' else 'spam (not phishing)', 'threshold':threshold,'split_sizes':{'train':len(fit),'validation':len(validation),'calibration':len(calibration),'test':len(test)},'groups_disjoint':True,'comparison_validation':comparison,'false_positive_count':int(sum((test.label.to_numpy()==0)&(test_p>=threshold))),'false_negative_count':int(sum((test.label.to_numpy()==1)&(test_p<threshold)))})
    # No pickle at inference. A portable JSON vocabulary and linear coefficients.
    names=vectorizer.get_feature_names_out()
    model={'version':'1.0.0','kind':kind,'analyzer':vectorizer.analyzer,'ngram_range':list(vectorizer.ngram_range),'features':{str(n):[float(vectorizer.idf_[i]),float(lr.coef_[0][i])] for i,n in enumerate(names)},'intercept':float(lr.intercept_[0]),'calibration':[float(calibrator.coef_[0][0]),float(calibrator.intercept_[0])],'threshold':threshold,'metrics':report}
    (OUT/(kind+'.json')).write_text(json.dumps(model,separators=(',',':')))
    # Fixture parity protects the portable runtime against vectorization drift.
    fixture=[{'text':s,'probability':float(p)} for s,p in zip(test.text.head(5),probabilities(test.text.head(5)))]
    # Email fixture inputs are not redistributed; use authored texts for parity instead.
    sample=['Meeting notes: the next review is on Friday.','Urgent: verify your account password immediately to avoid suspension.'] if kind=='email' else ['example.org/help','paypal.verify-account.example/login?session=1','example.com/a/b']
    fixture=[{'text':s,'probability':float(p)} for s,p in zip(sample,probabilities(sample))]
    (OUT/(kind+'-parity.json')).write_text(json.dumps(fixture,indent=2))
    print(kind,json.dumps(report),flush=True)
    return report

if __name__=='__main__':
    reports={}
    for kind,loader in [('url',load_urls),('email',load_emails)]:
        print('Loading '+kind,flush=True); reports[kind]=train(kind,loader())
    (OUT/'evaluation.json').write_text(json.dumps({'seed':42,'sources':SOURCES,'models':reports,'limitations':['Historical datasets, not a prospective or temporal evaluation.','URL evaluation uses a deterministic 60,000-row sample and domain-disjoint splits.','Email model detects historical spam; it is not calibrated as a phishing probability.','No visual brand-recognition or LLM is used. OCR evidence is probabilistic.','Neither model verifies reputation or proves safety.']},indent=2))
