"""
capture_local_normal.py
========================
Reads confirmed-normal events from the Sentinel SQLite database, 
extracts 49 features using the real feature_extractor, and exports 
them to data/local_normal.csv for VAE retraining.
"""
import sys
import argparse
import sqlite3
import json
import csv
import zlib
from pathlib import Path

# Add src directory to path to import feature_extractor
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "src"))

from common.config import DB_PATH
from common.feature_extractor import extract_features_from_eve, load_feature_names

def parse_args():
    parser = argparse.ArgumentParser(description="Export confirmed-normal events to local_normal.csv")
    parser.add_argument("--min-confidence", type=float, default=0.0,
                        help="Minimum confidence % that it is normal")
    parser.add_argument("--limit", type=int, default=20000,
                        help="Max rows to export")
    parser.add_argument("--output", type=str, default=str(BASE_DIR / "data" / "local_normal.csv"),
                        help="Output CSV path")
    parser.add_argument("--append", action="store_true",
                        help="Append to existing file")
    return parser.parse_args()


def main():
    args = parse_args()
    db_path = DB_PATH

    if not Path(db_path).exists():
        print(f"[ERROR] Database not found: {db_path}")
        sys.exit(1)

    print(f"[INFO] Reading from: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Pull normal-classified events with their raw_event JSON
    query = """
        SELECT raw_event, confidence, anomaly_score
        FROM alerts
        WHERE prediction = 'normal'
          AND confidence >= ?
        ORDER BY timestamp DESC
        LIMIT ?
    """
    rows = conn.execute(query, (args.min_confidence, args.limit)).fetchall()
    conn.close()

    print(f"[INFO] Found {len(rows)} normal events in DB")

    feature_names = load_feature_names()
    output_path = Path(args.output)
    mode = "a" if args.append and output_path.exists() else "w"
    existing_count = 0
    if mode == "a":
        with open(output_path, "r") as f:
            existing_count = sum(1 for _ in f) - 1
        print(f"[INFO] Appending to existing file ({existing_count} rows)")

    written = 0
    skipped = 0

    with open(output_path, mode, newline="") as csvfile:
        writer = csv.writer(csvfile)
        if mode == "w":
            writer.writerow(feature_names + ["label"])

        for row in rows:
            raw_event_blob = row["raw_event"]
            if not raw_event_blob:
                skipped += 1
                continue

            try:
                # Decompress zlib BLOB
                decompressed = zlib.decompress(raw_event_blob).decode('utf-8')
                suricata_event = json.loads(decompressed)
                
                # Use the REAL feature extractor
                features = extract_features_from_eve(suricata_event, feature_names)
                
                if features is None:
                    skipped += 1
                    continue
                
                # Check if it's all zeros (avoid noise)
                if all(v == 0.0 for v in features):
                    skipped += 1
                    continue

                # Add label = 0 for normal
                row_data = features + [0]
                writer.writerow(row_data)
                written += 1
                
            except Exception as e:
                skipped += 1
                continue

    print(f"[INFO] Written: {written} rows | Skipped: {skipped}")
    print(f"[INFO] Total rows now in {output_path}: {existing_count + written}")
    print("\nCapture complete. You can now run the retraining script.")


if __name__ == "__main__":
    main()
