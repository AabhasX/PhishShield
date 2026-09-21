import re
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score


def extract_features(url):
    url = url.strip().lower()

    has_https = int(url.startswith("https://"))
    has_ip = int(bool(re.search(
        r"https?://(\d{1,3}\.){3}\d{1,3}",
        url
    )))
    url_length = len(url)
    has_at = int("@" in url)
    hyphen_count = url.count("-")
    dot_count = url.count(".")
    slash_count = url.count("/")
    question_count = url.count("?")
    equal_count = url.count("=")

    suspicious_words = [
        "login", "signin", "verify", "account",
        "password", "bank", "secure", "payment",
        "confirm", "update", "recover", "unlock"
    ]

    keyword_count = sum(
        word in url for word in suspicious_words
    )

    return [
        has_https,
        has_ip,
        url_length,
        has_at,
        hyphen_count,
        dot_count,
        slash_count,
        question_count,
        equal_count,
        keyword_count
    ]


# Small starter dataset for the prototype.
# 1 = phishing, 0 = legitimate
data = [
    ["https://www.google.com", 0],
    ["https://www.microsoft.com", 0],
    ["https://www.apple.com", 0],
    ["https://www.amazon.com", 0],
    ["https://www.github.com", 0],
    ["https://www.wikipedia.org", 0],
    ["https://www.python.org", 0],
    ["https://www.microsoft.com/login", 0],
    ["https://www.google.com/account", 0],
    ["https://www.amazon.com/signin", 0],

    ["http://192.168.1.20/login", 1],
    ["http://paypal-login.example.com/verify", 1],
    ["http://secure-account-login.example.com", 1],
    ["http://verify-payment.example.com", 1],
    ["http://account-password-reset.example.com", 1],
    ["http://bank-security-check.example.com", 1],
    ["http://login.verify.account.example.com", 1],
    ["http://user:password@example.com/login", 1],
    ["http://secure-update-account.example.com", 1],
    ["http://paypal-confirm-login.example.com", 1],
    ["http://amazon-payment-verify.example.com", 1],
    ["http://microsoft-security-login.example.com", 1],
    ["http://192.0.2.1/login/verify", 1],
    ["http://example.com:8080/login", 1],
]


df = pd.DataFrame(
    data,
    columns=["url", "label"]
)

X = pd.DataFrame(
    df["url"].apply(extract_features).tolist(),
    columns=[
        "has_https",
        "has_ip",
        "url_length",
        "has_at",
        "hyphen_count",
        "dot_count",
        "slash_count",
        "question_count",
        "equal_count",
        "keyword_count"
    ]
)

y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print(f"Model accuracy: {accuracy * 100:.2f}%")

joblib.dump(
    model,
    "phishing_model.pkl"
)

print("Model saved as phishing_model.pkl")