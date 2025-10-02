import joblib
import pandas as pd
import re
from urllib.parse import urlparse

# load models
rf_model  = joblib.load('rf_model.joblib')
xgb_model = joblib.load('xgb_model.joblib')

# your feature list in *exact* order*
FEATURES = [
    'use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
    'count_dir', 'count_embed_domian', 'short_url', 'count-https',
    'count-http', 'count%', 'count?', 'count-', 'count=',
    'url_length', 'hostname_length', 'sus_url', 'fd_length',
    'count-digits', 'count-letters'
]

# featurization (same as training)
def contains_ip_address(url):
    return 1 if re.search(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}'
                          r'([01]?\d\d?|2[0-4]\d|25[0-5])', url) else 0

def abnormal_url(url):
    h = urlparse(url).hostname or ''
    return 1 if h in url else 0

def count_char(url, ch): return url.count(ch)
def no_of_dir(url):    return urlparse(url).path.count('/')
def shortening_service(url):
    return 1 if re.search(r'bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co', url) else 0

def featurize(url):
    return {
        'use_of_ip': contains_ip_address(url),
        'abnormal_url': abnormal_url(url),
        'count.': url.count('.'),
        'count-www': url.count('www'),
        'count@': url.count('@'),
        'count_dir': no_of_dir(url),
        'count_embed_domian': urlparse(url).path.count('//'),
        'short_url': shortening_service(url),
        'count-https': url.count('https'),
        'count-http': url.count('http'),
        'count%': url.count('%'),
        'count?': url.count('?'),
        'count-': url.count('-'),
        'count=': url.count('='),
        'url_length': len(url),
        'hostname_length': len(urlparse(url).netloc),
        'sus_url': 1 if re.search(r'login|bank|free|update', url) else 0,
        'count-digits': sum(c.isdigit() for c in url),
        'count-letters': sum(c.isalpha() for c in url),
        'fd_length': (len(urlparse(url).path.split('/')[1])
                      if '/' in urlparse(url).path else 0)
    }

# prompt & featurize
test_url = input("Enter URL to classify: ").strip()
feat_dict = featurize(test_url)

# build DataFrame with correct columns/order
X_new = pd.DataFrame([feat_dict], columns=FEATURES)

# map back to labels
label_map = {0:'benign',1:'defacement',2:'phishing',3:'malware'}

# predict
rf_pred  = rf_model.predict(X_new)[0]
xgb_pred = xgb_model.predict(X_new)[0]

# optional probabilities
rf_proba  = rf_model.predict_proba(X_new)[0]
xgb_proba = xgb_model.predict_proba(X_new)[0]

print(f"RandomForest predicts: {label_map[rf_pred]} (probs: {rf_proba})")
print(f"XGBoost     predicts: {label_map[xgb_pred]} (probs: {xgb_proba})")
