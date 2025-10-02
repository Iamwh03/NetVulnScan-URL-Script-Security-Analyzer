import pandas as pd
import matplotlib
import re
from googlesearch import search
from urllib.parse import urlparse
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn import svm, metrics
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import joblib

matplotlib.use('TkAgg')

# 1. Load data
df = pd.read_csv(r"C:\Users\chanw\Desktop\malicious_phish.csv", nrows=20000)
df.dropna(subset=['url','type'], inplace=True)

# 2. Feature engineering helpers
def contains_ip_address(url):
    return 1 if re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])', url) else 0

def abnormal_url(url):
    h = urlparse(url).hostname or ''
    return 1 if h in url else 0

def count_char(url, ch): return url.count(ch)
def no_of_dir(url):    return urlparse(url).path.count('/')
def shortening_service(url):
    return 1 if re.search(r'bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co', url) else 0

# 3. Apply features
df['use_of_ip']    = df['url'].apply(contains_ip_address)
df['abnormal_url'] = df['url'].apply(abnormal_url)
df['count.']       = df['url'].apply(lambda u: count_char(u,'.'))
df['count-www']    = df['url'].apply(lambda u: count_char(u,'www'))
df['count@']       = df['url'].apply(lambda u: count_char(u,'@'))
df['count_dir']    = df['url'].apply(no_of_dir)
df['count_embed_domian'] = df['url'].apply(lambda u: urlparse(u).path.count('//'))
df['short_url']    = df['url'].apply(shortening_service)
df['count-https']  = df['url'].apply(lambda u: count_char(u,'https'))
df['count-http']   = df['url'].apply(lambda u: count_char(u,'http'))
df['count%']       = df['url'].apply(lambda u: count_char(u,'%'))
df['count?']       = df['url'].apply(lambda u: count_char(u,'?'))
df['count-']       = df['url'].apply(lambda u: count_char(u,'-'))
df['count=']       = df['url'].apply(lambda u: count_char(u,'='))
df['url_length']   = df['url'].apply(len)
df['hostname_length'] = df['url'].apply(lambda u: len(urlparse(u).netloc))
df['sus_url']      = df['url'].apply(lambda u: 1 if re.search(r'login|bank|free|update', u) else 0)
df['count-digits'] = df['url'].apply(lambda u: sum(c.isdigit() for c in u))
df['count-letters']= df['url'].apply(lambda u: sum(c.isalpha() for c in u))
df['fd_length']    = df['url'].apply(lambda u: len(urlparse(u).path.split('/')[1]) if '/' in urlparse(u).path else 0)

# 4. Encode labels
lb_make = LabelEncoder()
df["url_type"] = lb_make.fit_transform(df["type"])

# 5. Prepare X, y and split
FEATURES = [
    'use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
    'count_dir', 'count_embed_domian', 'short_url', 'count-https',
    'count-http', 'count%', 'count?', 'count-', 'count=',
    'url_length', 'hostname_length', 'sus_url', 'fd_length',
    'count-digits', 'count-letters'
]
X = df[FEATURES]
y = df['url_type']
X_train, X_test, y_train, y_test = train_test_split(
    X, y, stratify=y, test_size=0.2, random_state=5
)

# 6. Train SVM
svm_clf = svm.SVC(kernel='linear', probability=True)
svm_clf.fit(X_train, y_train)
joblib.dump(svm_clf, 'svm_model.joblib')

# 7. Train Random Forest
rf_clf = RandomForestClassifier(n_estimators=100, random_state=42)
rf_clf.fit(X_train, y_train)
joblib.dump(rf_clf, 'rf_model.joblib')

# 8. Train XGBoost
xgb_clf = xgb.XGBClassifier(learning_rate=0.1, max_depth=3, n_estimators=100,
                             use_label_encoder=False, eval_metric='mlogloss')
xgb_clf.fit(X_train, y_train)
joblib.dump(xgb_clf, 'xgb_model.joblib')

# 9. Evaluate and save metrics to CSV
models = {
    'svm': svm_clf,
    'rf':  rf_clf,
    'xgb': xgb_clf
}

for name, model in models.items():
    # Predictions
    y_pred = model.predict(X_test)
    # Classification report
    report_dict = metrics.classification_report(
        y_test, y_pred,
        target_names=lb_make.classes_,
        output_dict=True
    )
    report_df = pd.DataFrame(report_dict).transpose()
    report_df.to_csv(f'{name}_report.csv', index=True)
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    cm_df = pd.DataFrame(cm,
                         index=lb_make.classes_,
                         columns=lb_make.classes_)
    cm_df.to_csv(f'{name}_confusion.csv')
    # Print summary
    acc = accuracy_score(y_test, y_pred)
    print(f"{name.upper()} Accuracy: {acc:.4f}")

print("Reports and confusion matrices saved as *_report.csv and *_confusion.csv")
