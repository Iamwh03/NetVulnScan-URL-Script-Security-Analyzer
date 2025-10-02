# backend.py
# Final version of the complete backend engine.

import os
from thefuzz import fuzz
import shlex
import requests
import json
import base64
from datetime import datetime
import time
import warnings
import hashlib
import joblib
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse

warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')

# --- CONFIGURATION & SECURITY BEST PRACTICE ---
# Replace these placeholders with your new, secret API keys.
VIRUSTOTAL_API_KEY = "3d925e1ec3e8c639c107e46a718fe07835c7297a5d3f39b63418da3acba6a8e5"
URLSCAN_API_KEY = "0197a6f0-e575-7134-9f7f-64ac8ae6b892"


import os, requests
import logging

# Initialize logger
logging.basicConfig(
    filename="detection_logs.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def log_event(event_type, input_str, result):
    logging.info(f"{event_type.upper()} | INPUT: {input_str} | RESULT: {json.dumps(result)}")

# --- replace existing query_virustotal_api_url ---
def query_virustotal_api(url):

    api_key = VIRUSTOTAL_API_KEY
    if not api_key:
        return {"error": "VirusTotal API key not set."}

    headers = {"x-apikey": api_key}
    # 1) submit URL
    resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        data={"url": url},
        headers=headers
    )
    if resp.status_code != 200:
        return {"error": f"VT Error {resp.status_code}: {resp.text}"}

    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        return {"error": "VT: missing analysis ID in response."}

    # 2) fetch results
    resp2 = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )
    if resp2.status_code != 200:
        return {"error": f"VT Error {resp2.status_code}: {resp2.text}"}

    stats = resp2.json().get("data", {}).get("attributes", {}).get("stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.get(k, 0) for k in stats)
    link       = f"https://www.virustotal.com/gui/url/{analysis_id}/detection"

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "total_engines": total,
        "link": link
    }


# --- replace existing query_urlscan ---
def query_urlscan(url):
    """
    Query URLScan.io API to scan a URL.
    Catches HTTP 400 “blocked” errors and returns a clear message.
    Returns a dict with:
      - uuid: scan ID or None if blocked
      - api_status: status string or 'blocked'
      - urlscan_link: link or None
      - error: non‐None if something went wrong
    """
    api_key = URLSCAN_API_KEY
    headers = {"API-Key": api_key} if api_key else {}
    payload = {"url": url, "public": "on"}

    try:
        resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            json=payload,
            headers=headers,
            timeout=15
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        # Try to pull out a JSON error message
        try:
            err = e.response.json()
            detail = err.get("description") or err.get("message") or str(err)
        except ValueError:
            detail = e.response.text
        if status == 400:
            return {
                "uuid": None,
                "api_status": "blocked",
                "urlscan_link": None,
                "error": f"URLScan blocked this URL: {detail}"
            }
        return {"error": f"URLScan API Error {status}: {detail}"}

    # If we get here, the scan request succeeded
    data = resp.json()
    uuid = data.get("uuid")
    if not uuid:
        return {"error": "URLScan: missing UUID in response."}

    return {
        "uuid": uuid,
        "api_status": data.get("status", ""),
        "urlscan_link": f"https://urlscan.io/result/{uuid}/",
        "error": None
    }





def load_rules(rules_path="rules"):
    rules = {}
    try:
        if not os.path.isdir(rules_path): return None
        for filename in os.listdir(rules_path):
            if filename.endswith(".txt") and filename != "whitelist.txt":
                category = filename.replace(".txt", "")
                rules[category] = []
                with open(os.path.join(rules_path, filename), 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.strip() or line.strip().startswith('#'): continue
                        patterns = [p.strip().lower() for p in line.split('|')]
                        if patterns[0]:
                            rules[category].append({'canonical_name': patterns[0], 'patterns': set(patterns)})
    except Exception as e:
        print(f"[ERROR] Could not load dynamic rules: {e}")
    return rules


def load_whitelist(rules_path="rules"):
    wl = []
    p = os.path.join(rules_path, "whitelist.txt")
    if os.path.exists(p):
        with open(p, 'r', encoding='utf-8') as f:
            wl = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
    return wl


class HybridDetectionEngine:
    def __init__(self, rules_path="rules", model_path="models"):
        self.rules = load_rules(rules_path)
        self.whitelist = load_whitelist(rules_path)
        self.fuzzy_threshold = 90
        self.score_weights = {
            'lolbin': 0.05, 'content': 0.4, 'frequency': 0.2, 'source': 0.1,
            'network': 0.1, 'behavioural': 0.1, 'history': 0.05
        }
        self.models, self.metrics, self.vectorizer = {}, {}, None
        self.ml_enabled = False
        try:
            vectorizer_path = os.path.join(model_path, "vectorizer_v3.joblib")
            if not os.path.exists(vectorizer_path):
                raise FileNotFoundError(f"Command vectorizer not found at {vectorizer_path}")
            self.vectorizer = joblib.load(vectorizer_path)
            for file in os.listdir(model_path):
                if file.startswith("model_") and "url" not in file:
                    name = file.replace("model_", "").replace(".joblib", "")
                    self.models[name] = joblib.load(os.path.join(model_path, file))
                    mfile = os.path.join(model_path, f"metrics_{name}.joblib")
                    if os.path.exists(mfile):
                        self.metrics[name] = joblib.load(mfile)
            if self.vectorizer is not None and self.models:
                self.ml_enabled = True
                print(f"[✓] Command Detection Engine loaded successfully.")
            else:
                raise Exception("Command ML models or vectorizer failed to load.")
        except Exception as e:
            print(f"[ERROR] Command ML init failed: {e}")

    def sanitize_command(self, command):
        command = command.lower()
        subs = {'@': 'a', '0': 'o', '1': 'l', '3': 'e', '5': 's', '^': ''}
        for k, v in subs.items(): command = command.replace(k, v)
        return re.sub(r'\s+', ' ', command).strip()

    def analyze(self, command):
        findings = {}
        cmd_sanitized = self.sanitize_command(command)
        if any(p in cmd_sanitized for p in self.whitelist):
            findings['whitelisted'] = [{'evidence': cmd_sanitized, 'pattern': p} for p in self.whitelist if
                                       p in cmd_sanitized]
        try:
            tokens = shlex.split(cmd_sanitized)
        except ValueError:
            tokens = cmd_sanitized.split()
        if self.rules:
            for category, rules_list in self.rules.items():
                for rule in rules_list:
                    match_found = False
                    for token in tokens:
                        for pattern in rule['patterns']:
                            if len(pattern) >= 3 and (
                                    pattern in token or fuzz.ratio(token, pattern) >= self.fuzzy_threshold):
                                findings.setdefault(category, []).append(
                                    {'evidence': token, 'pattern': rule['canonical_name']})
                                match_found = True
                                break
                        if match_found: break
        if self.ml_enabled:
            try:
                vec = self.vectorizer.transform([command])
                ml_findings = []
                for name, model in self.models.items():
                    pred = model.predict(vec)[0]
                    proba = model.predict_proba(vec)[0]
                    confidence = proba[int(pred)] * 100
                    ml_findings.append({
                        'model': name, 'prediction': 'Malicious' if pred == 1 else 'Benign', 'confidence': confidence
                    })
                findings['machine_learning'] = ml_findings
            except Exception as e:
                print(f"[ERROR] Command ML prediction failed: {e}")
        log_event("command", command, findings)
        return findings




class URLDetectionEngine:
    """
    Loads trained RF and XGBoost models and their evaluation metrics,
    featurizes URLs, and provides analysis results.

    Metrics are loaded from CSV files in `metrics_folder`:
      - `{prefix}_report.csv`: classification report
      - `{prefix}_confusion.csv`: confusion matrix
    where prefix is 'rf' for RandomForest and 'xgb' for XGBoost.

    Public attributes:
      - models: dict of loaded model objects
      - metrics: dict of {model_name: {classification_report: dict, confusion_matrix: list}}
      - feature_names: list of feature column names
      - label_map: numeric→string label mapping
      - label_mapping_rev: string→numeric for UI

    Methods:
      - featurize(url): returns a dict of feature_name→value
      - transform(urls): returns a DataFrame of features
      - analyze(url): returns list of {model, prediction, confidence}
    """
    def __init__(self,
                 rf_model_path='rf_model.joblib',
                 xgb_model_path='xgb_model.joblib',
                 metrics_folder='.'):
        # Load models
        self.models = {
            'RandomForest': joblib.load(rf_model_path),
            'XGBoost':      joblib.load(xgb_model_path)
        }
        # Load metrics
        self.metrics = {}
        prefix_map = {'RandomForest': 'rf', 'XGBoost': 'xgb'}
        for model_name, prefix in prefix_map.items():
            m = {}
            report_path = os.path.join(metrics_folder, f'{prefix}_report.csv')
            conf_path   = os.path.join(metrics_folder, f'{prefix}_confusion.csv')
            if os.path.exists(report_path):
                rpt_df = pd.read_csv(report_path, index_col=0)
                m['classification_report'] = rpt_df.to_dict(orient='index')
            if os.path.exists(conf_path):
                cm_df = pd.read_csv(conf_path, index_col=0)
                m['confusion_matrix'] = cm_df.values.tolist()
            self.metrics[model_name] = m
        # Feature names (must match training)
        self.feature_names = [
            'use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
            'count_dir', 'count_embed_domian', 'short_url', 'count-https',
            'count-http', 'count%', 'count?', 'count-', 'count=',
            'url_length', 'hostname_length', 'sus_url', 'fd_length',
            'count-digits', 'count-letters'
        ]
        # Label mappings
        self.label_map = {0: 'benign', 1: 'defacement', 2: 'malware', 3: 'phishing'}
        self.label_mapping_rev = {v: k for k, v in self.label_map.items()}

    def featurize(self, url: str) -> dict:
        """Compute the 20 hand-crafted features for a single URL."""
        def contains_ip_address(u):
            return 1 if re.search(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}'
                                   r'([01]?\d\d?|2[0-4]\d|25[0-5])', u) else 0
        def abnormal_url(u):
            h = urlparse(u).hostname or ''
            return 1 if h in u else 0
        def count_char(u, ch): return u.count(ch)
        def no_of_dir(u):    return urlparse(u).path.count('/')
        def shortening_service(u):
            return 1 if re.search(r'bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co', u) else 0

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

    def transform(self, urls) -> pd.DataFrame:
        """Transform a list of URLs into a feature DataFrame."""
        rows = [self.featurize(u) for u in urls]
        return pd.DataFrame(rows, columns=self.feature_names)

    def analyze(self, url: str) -> list:
        """Return predictions for each model as a list of dicts."""
        feats = self.featurize(url)
        X = pd.DataFrame([feats], columns=self.feature_names)
        results = []
        for name, model in self.models.items():
            pred = model.predict(X)[0]
            proba = model.predict_proba(X)[0]
            confidence = float(np.max(proba) * 100)
            results.append({
                'model': name,
                'prediction': self.label_map[pred],
                'confidence': confidence
            })
        log_event("url", url, results)
        return results




# HybridDetectionEngine would similarly load your command models
# and implement .analyze(command_string) using their vectorizer & metrics.
