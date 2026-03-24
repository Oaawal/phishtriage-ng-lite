import os
import zipfile
import urllib.request
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

UCI_ZIP_URL = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"

def try_download_uci_dataset():
    os.makedirs("data", exist_ok=True)
    zip_path = os.path.join("data", "smsspamcollection.zip")
    extract_path = os.path.join("data", "smsspamcollection")

    if os.path.exists(os.path.join(extract_path, "SMSSpamCollection")):
        return os.path.join(extract_path, "SMSSpamCollection")

    try:
        print("Downloading dataset from UCI...")
        urllib.request.urlretrieve(UCI_ZIP_URL, zip_path)
        print("Extracting...")
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(extract_path)
        return os.path.join(extract_path, "SMSSpamCollection")
    except Exception as e:
        print("Could not download UCI dataset (maybe no internet).")
        print("Error:", e)
        return None

def fallback_dataset():
    # Tiny dataset for demo ONLY (replace/add your own examples later)
    samples = [
        ("ham", "Hi, are we still meeting by 4pm today?"),
        ("ham", "Your OTP is 123456. Do not share it with anyone."),
        ("ham", "Please call me when you are free."),
        ("spam", "Congratulations! You won a prize. Click http://bit.ly/claim-now"),
        ("spam", "Your account will be blocked today. Verify now at www.bank-secure-login.com"),
        ("spam", "Send your OTP to confirm your account immediately."),
        ("spam", "Investment opportunity: double your money in 24 hours. WhatsApp +2348012345678"),
        ("spam", "NIN update required. Click link to avoid arrest."),
    ]
    return pd.DataFrame(samples, columns=["label", "text"])

def load_data():
    path = try_download_uci_dataset()
    if path and os.path.exists(path):
        df = pd.read_csv(path, sep="\t", names=["label", "text"], encoding="utf-8")
    else:
        df = fallback_dataset()

    # Optional: add your own Nigeria samples if you create data/ng_samples.csv
    # CSV format: label,text  where label is ham or spam
    ng_path = os.path.join("data", "ng_samples.csv")
    if os.path.exists(ng_path):
        ng = pd.read_csv(ng_path)
        ng = ng[["label", "text"]].dropna()
        df = pd.concat([df, ng], ignore_index=True)

    df["y"] = (df["label"].str.lower() == "spam").astype(int)
    return df

def train_and_save(df):
    X = df["text"].astype(str)
    y = df["y"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if y.nunique() > 1 else None
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), max_features=30000)),
        ("clf", LogisticRegression(max_iter=1000))
    ])

    model.fit(X_train, y_train)

    acc = model.score(X_test, y_test) if y.nunique() > 1 else None
    if acc is not None:
        print(f"Test accuracy: {acc:.3f}")

    joblib.dump(model, "model.joblib")
    print("Saved model to model.joblib")

if __name__ == "__main__":
    df = load_data()
    train_and_save(df)