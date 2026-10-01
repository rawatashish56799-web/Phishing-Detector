import pandas as pd, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import make_pipeline

df = pd.read_csv("data/raw/Phishing_Email.csv")
df = df.dropna(subset=["Email Text", "Email Type"]).drop_duplicates(subset=["Email Text"])
print("Rows after cleaning:", len(df))

X = df["Email Text"].astype(str)
y = df["Email Type"].str.contains("phish", case=False).astype(int)  # 1 = phishing, 0 = safe

Xtr, Xte, ytr, yte = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

model = make_pipeline(
    TfidfVectorizer(stop_words="english", max_features=30000, ngram_range=(1, 2)),
    LogisticRegression(max_iter=1000),
)
model.fit(Xtr, ytr)

pred = model.predict(Xte)
print(classification_report(yte, pred, target_names=["safe", "phishing"]))
print("Confusion matrix:")
print(confusion_matrix(yte, pred))

joblib.dump(model, "models/baseline.pkl")
print("Model saved to models/baseline.pkl")
