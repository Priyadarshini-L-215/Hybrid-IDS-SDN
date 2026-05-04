import os
import zipfile
from pathlib import Path

def download_dataset(dataset_name="mrwellog/unsw-nb15", target_dir="data"):
    """
    Downloads a dataset from Kaggle and extracts it.
    Requires kaggle credentials to be configured.
    """
    try:
        from kaggle.api.kaggle_api_extended import KaggleApi
    except ImportError:
        print("Error: kaggle package not installed. Run 'pip install kaggle'")
        return False

    api = KaggleApi()
    api.authenticate()

    target_path = Path(target_dir)
    target_path.mkdir(parents=True, exist_ok=True)

    print(f"Downloading dataset '{dataset_name}' to '{target_dir}'...")
    api.dataset_download_files(dataset_name, path=target_dir, unzip=True)
    print("Download and extraction complete.")
    return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Download dataset from Kaggle")
    parser.add_argument("--dataset", type=str, default="mrwellog/unsw-nb15", help="Kaggle dataset name")
    parser.add_argument("--dir", type=str, default="data", help="Target directory")
    
    args = parser.parse_args()
    
    # Check if ~/.kaggle/kaggle.json exists
    kaggle_json = Path.home() / ".kaggle" / "kaggle.json"
    if not kaggle_json.exists():
        print(f"Error: Kaggle credentials not found at {kaggle_json}")
        print("Please provide your Kaggle API key (username and key).")
    else:
        download_dataset(args.dataset, args.dir)
