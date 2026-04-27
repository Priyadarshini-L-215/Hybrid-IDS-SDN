"""
Hybrid IDS - Machine Learning Training Pipeline
================================================

Trains a Random Forest classifier on network traffic data (CICIDS format).
- Handles class imbalance (uses class_weight='balanced')
- Validates on stratified train/test split
- Saves model, features, and metrics

Output:
  - model.pkl: Pickled RandomForestClassifier
  - features.json: List of 57 feature names (in exact order)
  - feature_importance.csv: Feature importance rankings
  - metrics.json: Accuracy and ROC-AUC scores
"""

import logging
import sys
from pathlib import Path

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)
import pickle
import json

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Configuration
BASE_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = BASE_DIR / "models"

DATASET_PATH = BASE_DIR / "data" / "dataset.csv"
SAMPLE_SIZE = 200000  # Limit data to avoid memory issues
RANDOM_STATE = 42
TEST_SIZE = 0.2
MODEL_PATH = MODELS_DIR / "model.pkl"
FEATURES_PATH = MODELS_DIR / "features.json"
METRICS_PATH = MODELS_DIR / "metrics.json"
IMPORTANCE_PATH = MODELS_DIR / "feature_importance.csv"

def main():
    try:
        # ===== STEP 1: LOAD DATA =====
        logger.info("=" * 70)
        logger.info("STEP 1: Loading Dataset")
        logger.info("=" * 70)
        
        dataset_path = DATASET_PATH
        if not dataset_path.exists():
            logger.error(f"Dataset not found: {dataset_path}")
            logger.error("Expected format: CSV file with 'Label' column and network features")
            sys.exit(1)
        
        MODELS_DIR.mkdir(parents=True, exist_ok=True)

        logger.info(f"Loading {dataset_path}...")
        df = pd.read_csv(dataset_path)
        logger.info(f"[OK] Loaded {len(df):,} rows x {len(df.columns)} columns")
        
        # Sample data if too large
        if len(df) > SAMPLE_SIZE:
            logger.info(f"Sampling {SAMPLE_SIZE:,} rows (from {len(df):,})...")
            df = df.sample(n=SAMPLE_SIZE, random_state=RANDOM_STATE)
        
        logger.info(f"Class distribution:\n{df['Label'].value_counts()}")
        
        # ===== STEP 2: DATA CLEANING =====
        logger.info("\n" + "=" * 70)
        logger.info("STEP 2: Data Cleaning")
        logger.info("=" * 70)
        
        initial_rows = len(df)
        
        # Remove missing values
        df = df.dropna()
        logger.info(f"After dropna: {len(df):,} rows (removed {initial_rows - len(df):,})")
        
        # Drop leakage columns (info not available at inference time)
        leak_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
        dropped = [col for col in leak_cols if col in df.columns]
        if dropped:
            df = df.drop(columns=dropped, errors='ignore')
            logger.info(f"Dropped leakage columns: {dropped}")

        if 'Label' not in df.columns:
            logger.error("'Label' column not found in dataset")
            sys.exit(1)

        # Keep numeric feature columns, then reattach the target column explicitly.
        feature_frame = df.drop(columns=['Label'], errors='ignore').select_dtypes(include=['number'])
        df_numeric = feature_frame.copy()
        df_numeric['Label'] = df['Label'].values
        logger.info(f"Selected {len(feature_frame.columns)} numeric feature columns plus Label")
        
        # Remove duplicates
        before_dedup = len(df_numeric)
        df_numeric = df_numeric.drop_duplicates()
        logger.info(f"After dedup: {len(df_numeric):,} rows (removed {before_dedup - len(df_numeric):,})")
        
        # ===== STEP 3: PREPARE FEATURES & TARGET =====
        logger.info("\n" + "=" * 70)
        logger.info("STEP 3: Feature Engineering")
        logger.info("=" * 70)
        
        X = df_numeric.drop('Label', axis=1)
        y = df_numeric['Label']

        if not pd.api.types.is_numeric_dtype(y):
            logger.info("Normalizing string labels to binary classes (0=normal, 1=attack)")
            normal_labels = {"BENIGN", "NORMAL", "0"}
            y = y.astype(str).str.strip().str.upper().map(lambda value: 0 if value in normal_labels else 1)
        
        logger.info(f"Features: {len(X.columns)}")
        logger.info(f"Target: {sorted(y.unique())}")
        logger.info(f"Target distribution:\n  0 (Normal): {(y==0).sum():,}\n  1 (Attack): {(y==1).sum():,}")
        
        # ===== STEP 4: TRAIN/TEST SPLIT =====
        logger.info("\n" + "=" * 70)
        logger.info("STEP 4: Train/Test Split")
        logger.info("=" * 70)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y  # Ensure balanced class distribution
        )
        
        logger.info(f"Train set: {len(X_train):,} samples ({len(X_train)/len(X)*100:.1f}%)")
        logger.info(f"Test set:  {len(X_test):,} samples ({len(X_test)/len(X)*100:.1f}%)")
        
        # ===== STEP 5: MODEL TRAINING =====
        logger.info("\n" + "=" * 70)
        logger.info("STEP 5: Training Random Forest Model")
        logger.info("=" * 70)
        
        logger.info("Model configuration:")
        logger.info("  • n_estimators: 20 (trees)")
        logger.info("  • max_depth: 5 (shallow trees for generalization)")
        logger.info("  • max_features: 'sqrt' (reduces overfitting)")
        logger.info("  • class_weight: 'balanced' (handles imbalance)")
        
        model = RandomForestClassifier(
            n_estimators=20,
            max_depth=5,
            max_features='sqrt',
            class_weight='balanced',
            random_state=RANDOM_STATE,
            n_jobs=-1,  # Use all CPU cores
            verbose=1
        )
        
        logger.info("Training...")
        model.fit(X_train, y_train)
        logger.info("[OK] Model training complete")
        
        # ===== STEP 6: FEATURE IMPORTANCE =====
        logger.info("\n" + "=" * 70)
        logger.info("STEP 6: Feature Importance Analysis")
        logger.info("=" * 70)
        
        importance = pd.DataFrame({
            "feature": X.columns,
            "importance": model.feature_importances_
        }).sort_values(by="importance", ascending=False)
        
        logger.info(f"Top 10 features:")
        for idx, row in importance.head(10).iterrows():
            logger.info(f"  {row['feature']:<40} {row['importance']:.4f}")
        
        importance.to_csv(IMPORTANCE_PATH, index=False)
        logger.info(f"[OK] Saved: {IMPORTANCE_PATH}")
        
        # ===== STEP 7: MODEL EVALUATION =====
        logger.info("\n" + "=" * 70)
        logger.info("STEP 7: Model Evaluation")
        logger.info("=" * 70)
        
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, model.predict_proba(X_test)[:, 1])
        
        logger.info(f"Accuracy:  {accuracy*100:.2f}%")
        logger.info(f"ROC-AUC:   {roc_auc:.4f}")
        
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred))
        
        logger.info("\nConfusion Matrix (rows=actual, cols=predicted):")
        cm = confusion_matrix(y_test, y_pred)
        logger.info(f"  Normal→Normal: {cm[0,0]:6d}  |  Normal→Attack: {cm[0,1]:6d}")
        logger.info(f"  Attack→Normal: {cm[1,0]:6d}  |  Attack→Attack: {cm[1,1]:6d}")
        
        # ===== STEP 8: SAVE ARTIFACTS =====
        logger.info("\n" + "=" * 70)
        logger.info("STEP 8: Saving Model Artifacts")
        logger.info("=" * 70)
        
        # Save metrics
        metrics = {
            "accuracy": float(accuracy),
            "roc_auc": float(roc_auc),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "num_features": len(X.columns),
            "class_distribution": {
                "normal": int((y==0).sum()),
                "attack": int((y==1).sum())
            }
        }
        
        with open(METRICS_PATH, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"[OK] Saved: {METRICS_PATH}")
        
        # Save model
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(model, f)
        logger.info(f"[OK] Saved: {MODEL_PATH}")
        
        # Save feature names (exactly 57 for Hybrid IDS)
        feature_list = list(X.columns)
        logger.info(f"Features: {len(feature_list)}")
        if len(feature_list) != 57:
            logger.warning(f"Expected 57 features, got {len(feature_list)}")
        
        with open(FEATURES_PATH, "w", encoding="utf-8") as f:
            json.dump(feature_list, f, indent=2)
        logger.info(f"[OK] Saved: {FEATURES_PATH}")
        
        # ===== COMPLETE =====
        logger.info("\n" + "=" * 70)
        logger.info("[OK] TRAINING COMPLETE")
        logger.info("=" * 70)
        logger.info(f"Model Accuracy: {accuracy*100:.2f}%")
        logger.info(f"ROC-AUC Score:  {roc_auc:.4f}")
        logger.info(f"\nArtifacts saved to: {Path.cwd()}")
        logger.info("  • rf_model.pkl")
        logger.info("  • features.json")
        logger.info("  • metrics.json")
        logger.info("  • feature_importance.csv")
        logger.info("=" * 70)
        
        return 0
        
    except Exception as e:
        logger.error(f"Fatal error during training: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
)
