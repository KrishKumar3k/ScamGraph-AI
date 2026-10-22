
import io
import urllib.request
import zipfile
from pathlib import Path

import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

DATA_URL = (
    "https://archive.ics.uci.edu/static/public/"
    "228/sms+spam+collection.zip"
)

MODEL_PATH = Path("scam_model.joblib")


def load_dataset():
    print("Downloading public SMS Spam Collection dataset...")

    request = urllib.request.Request(
        DATA_URL,
        headers={"User-Agent": "ScamGraphAI/1.0"},
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        archive_data = response.read()

    with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
        filename = next(
            name for name in archive.namelist()
            if name.endswith("SMSSpamCollection")
        )
        with archive.open(filename) as file:
            df = pd.read_csv(
                file,
                sep="\t",
                header=None,
                names=["label", "text"],
                encoding="utf-8",
            )

    df = df.dropna(subset=["label", "text"])
    df["label"] = df["label"].map({"ham": 0, "spam": 1})
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    return df


def main():
    df = load_dataset()

    print(f"\nDataset rows: {len(df)}")
    print("Labels:")
    print(df["label"].map({
        0: "Legitimate",
        1: "Spam",
    }).value_counts())

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"],
        df["label"],
        test_size=0.20,
        random_state=42,
        stratify=df["label"],
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                stop_words="english",
                ngram_range=(1, 2),
                max_features=20000,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ])

    print("\nTraining model...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nTest accuracy:", round(
        accuracy_score(y_test, predictions) * 100, 2
    ), "%")

    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Spam"],
        zero_division=0,
    ))

    print("Confusion matrix:")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))

    joblib.dump(model, MODEL_PATH)
    print(f"\nTrained model saved to: {MODEL_PATH.resolve()}")

    print("\nDemo predictions:")
    examples = [
        "URGENT! Your account is blocked. Verify your details now.",
        "Hey, are we meeting at college tomorrow?",
        "Congratulations! You won a prize. Click this link to claim.",
    ]

    for message in examples:
        prediction = int(model.predict([message])[0])
        probability = model.predict_proba([message])[0]
        spam_index = list(model.classes_).index(1)
        spam_probability = probability[spam_index] * 100

        label = "SPAM-LIKE" if prediction == 1 else "LIKELY LEGITIMATE"
        print(f"\nMessage: {message}")
        print(f"Prediction: {label}")
        print(f"Model spam score: {spam_probability:.1f}%")


if __name__ == "__main__":
    main()
