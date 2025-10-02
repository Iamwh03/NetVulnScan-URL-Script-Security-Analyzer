# train_models.py
# Updated to load .ps1 files from the user-specified folder structure.

import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import confusion_matrix, classification_report

# Import the models
from sklearn.linear_model import LogisticRegression
from lightgbm import LGBMClassifier
from sklearn.neural_network import MLPClassifier


def load_data_from_folders(base_path):
    """Loads .ps1 files from 'benign' and 'malicious_pure' folders."""
    texts, labels = [], []
    benign_path = os.path.join(base_path, 'benign')
    malicious_path = os.path.join(base_path, 'malicious_pure')

    for path, label in [(benign_path, 0), (malicious_path, 1)]:
        if not os.path.exists(path):
            print(f"[WARNING] Path not found, skipping: {path}")
            continue
        for filename in os.listdir(path):
            # --- UPDATED TO CHECK FOR .ps1 FILES ---
            if filename.endswith('.ps1'):
                try:
                    with open(os.path.join(path, filename), 'r', encoding='utf-8', errors='ignore') as f:
                        texts.append(f.read())
                        labels.append(label)
                except Exception as e:
                    print(f"Could not read {filename}: {e}")
    return texts, labels


def save_confusion_matrix_plot(cm, model_name, path="models/metrics"):
    """Saves a plot of the confusion matrix to a file."""
    if not os.path.exists(path):
        os.makedirs(path)

    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges',
                xticklabels=['Benign', 'Malicious'],
                yticklabels=['Benign', 'Malicious'],
                annot_kws={"size": 14})
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    plt.title(f'Confusion Matrix for {model_name}', fontsize=14)
    plot_path = os.path.join(path, f"cm_{model_name}.png")
    plt.savefig(plot_path, bbox_inches='tight')
    plt.close()
    return plot_path


# --- Main Training ---
print("Training the final model panel...")
DATASET_PATH = r'C:\Users\chanw\Documents\GitHub\mpsd'  # Path confirmed by user
X, y = load_data_from_folders(DATASET_PATH)
if not X:
    print(
        "No data loaded. Please check your DATASET_PATH and ensure it contains 'benign' and 'malicious_pure' folders with .ps1 files.")
    exit()

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("Creating and fitting the vectorizer...")
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(4, 6), max_features=25000)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# Save the now-fitted vectorizer
VECTORIZER_FILE = "models/vectorizer_v3.joblib"
if not os.path.exists("models"): os.makedirs("models")
joblib.dump(vectorizer, VECTORIZER_FILE)
print(f"\n[✓] Fresh, fitted vectorizer saved to {VECTORIZER_FILE}")

# --- Define, Train, and Evaluate All Models ---
models_to_train = {
    "LogisticRegression": LogisticRegression(max_iter=1000, solver='liblinear'),
    "GradientBoosting_LGBM": LGBMClassifier(random_state=42),
    "NeuralNetwork_MLP": MLPClassifier(random_state=42, max_iter=300, hidden_layer_sizes=(100, 50), early_stopping=True)
}

# Clear out any old models and metrics before saving new ones
print("\nClearing old model and metric files...")
if os.path.exists("models"):
    for file in os.listdir("models"):
        if file.startswith("model_") or file.startswith("metrics_"):
            os.remove(os.path.join("models", file))
if os.path.exists("models/metrics"):
    for file in os.listdir("models/metrics"):
        os.remove(os.path.join("models/metrics", file))

for name, model in models_to_train.items():
    print(f"\n--- Training and Evaluating {name} ---")
    model.fit(X_train_vec, y_train)
    y_pred = model.predict(X_test_vec)

    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    plot_path = save_confusion_matrix_plot(cm, name)

    metrics = {
        'confusion_matrix': cm.tolist(),
        'classification_report': report,
        'plot_path': plot_path
    }

    joblib.dump(model, f"models/model_{name}.joblib")
    joblib.dump(metrics, f"models/metrics_{name}.joblib")
    print(f"[✓] {name} model and metrics saved.")

print("\n[✓] Final model training and metric generation complete.")