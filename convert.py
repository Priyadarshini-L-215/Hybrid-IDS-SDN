import pandas as pd

# Read parquet file
df = pd.read_parquet("data/cic-collection.parquet")

# Convert to CSV
df.to_csv("data/dataset.csv", index=False)

print("Conversion completed ✅")