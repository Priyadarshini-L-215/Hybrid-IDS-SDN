import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
SOURCE_PATH = BASE_DIR / "data" / "cic-collection.parquet"
TARGET_PATH = BASE_DIR / "data" / "dataset.csv"

# Read parquet file
df = pd.read_parquet(SOURCE_PATH)

# Convert to CSV
df.to_csv(TARGET_PATH, index=False)

print("Conversion completed")
