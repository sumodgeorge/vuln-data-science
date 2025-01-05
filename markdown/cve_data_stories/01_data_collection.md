---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.16.6
  kernelspec:
    display_name: Python 3
    language: python
    name: python3
---

# CVE Data Stories - Data Collection

```python
import zipfile
from pathlib import Path

import requests
```

## Project Setup

Before proceeding with data collection, we need to ensure that the necessary directory for storing raw data is in place. This step is crucial to maintain an organized structure for our project, especially when working with multiple datasets over time.

The following Python code will check if the required `raw` directory under `cve_data_stories` exists, and if not, it will create it. This approach ensures that the environment is always correctly set up before any data processing begins, even if you're running this notebook on a new machine or a fresh clone of the repository.

```python
# Target directory for raw data
DATA_DIR = Path("../../data/cve_data_stories/raw")
DATA_DIR.mkdir(parents=True, exist_ok=True)
```

# Data Collection

To automate the downloading, unzipping, and saving of required datasets, execute the Python code in the **next cell**.

This script will:
- Download the NIST NVD (2002-2024) and CISA KEV datasets.
- Extract JSON files from ZIP archives.
- Save all files to the directory: `/data/cve_data_stories/raw/`.

Once the script has run successfully, proceed to the data preprocessing steps in the next notebook.

```python
# Target directory for raw data
DATA_DIR = Path("../../data/cve_data_stories/raw")
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Generate URLs for NVD CVE datasets (2002-2024)
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
DATASETS = {f"nvdcve-1.1-{year}.json.zip": f"{BASE_URL}nvdcve-1.1-{year}.json.zip" for year in range(2002, 2025)}


def download_file(url, dest):
    """Download a file from a URL to a destination."""
    print(f"Downloading: {url}")
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(dest, "wb") as file:
            for chunk in response.iter_content(chunk_size=1024):
                file.write(chunk)
        print(f"Saved to: {dest}")
    else:
        print(f"Failed to download {url} - Status code: {response.status_code}")


def unzip_file(zip_path, dest_dir):
    """Unzip a file to a destination directory."""
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(dest_dir)
        print(f"Unzipped {zip_path} to {dest_dir}")


# Main execution
for filename, url in DATASETS.items():
    dest_path = DATA_DIR / filename

    # Download the file
    download_file(url, dest_path)

    # If it's a ZIP file, extract its contents
    if filename.endswith(".zip"):
        unzip_file(dest_path, DATA_DIR)
        dest_path.unlink()  # Remove the ZIP file after extraction

```
