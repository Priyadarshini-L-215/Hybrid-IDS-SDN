import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pickle
import json

print("Loading dataset...")

# Load limited data (avoid memory crash)
df = pd.read_csv("data/dataset.csv")

# Take random sample instead of first rows
df = df.sample(n=200000, random_state=42)
print("Class distribution:")
print(df['Label'].value_counts())

print("Cleaning data...")

# Remove missing values
df = df.dropna()

# Shuffle data (important)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Convert label (BENIGN → 0, others → 1)
df['Label'] = df['Label'].apply(lambda x: 0 if str(x).lower() == "benign" else 1)

# Drop obvious leakage columns if present
leak_cols = [
    'Flow ID', 'Source IP', 'Destination IP',
    'Timestamp'
]
df = df.drop(columns=[col for col in leak_cols if col in df.columns], errors='ignore')

# Keep only numeric columns
df = df.select_dtypes(include=['number'])

# Remove duplicates
df = df.drop_duplicates()

# Separate features and target
X = df.drop('Label', axis=1)
y = df['Label']

print("Splitting data...")

# Split with stratification (VERY IMPORTANT)
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training model...")

# ✅ IMPROVED MODEL (handles imbalance)
model = RandomForestClassifier(
    n_estimators=20,      # reduce trees
    max_depth=5,          # shallow trees
    max_features='sqrt',  # limit features per split
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# Feature importance
importance = pd.DataFrame({
    "feature": X.columns,
    "importance": model.feature_importances_
})

# Sort by importance
importance = importance.sort_values(by="importance", ascending=False)

# Save to CSV
importance.to_csv("feature_importance.csv", index=False)

print("Feature importance saved ✅")

# ⬇️ ADD HERE
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

print("Evaluating...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy*100:.2f}%")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ✅ NEW (IMPORTANT METRIC)
roc = roc_auc_score(y_test, model.predict_proba(X_test)[:, 1])
print(f"\nROC-AUC Score: {roc:.4f}")

print("Saving model...")

# Save metrics
metrics = {
    "accuracy": float(accuracy),
    "roc_auc": float(roc)
}

with open("metrics.json", "w") as f:
    json.dump(metrics, f)

print("Metrics saved ✅")

# Save model
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

# Save feature names
with open("features.json", "w") as f:
    json.dump(list(X.columns), f)

print("Model + features saved successfully ✅")