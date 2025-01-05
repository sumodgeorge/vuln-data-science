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

# CVE Data Stories: Vendor CVE Trends - Data Cleaning

```python
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
```

## Project Setup

Before proceeding with data processing, we need to ensure that the necessary directory for storing processed data is in place. This step is crucial to maintain an organized structure for our project, especially when working with multiple datasets over time.

The following Python code will check if the required `processed` directory under `data/cve_data_stories/vendor_cve_trends/` exists, and if not, it will create it. This approach ensures that the environment is always correctly set up before any data processing begins, even if you're running this notebook on a new machine or a fresh clone of the repository.

```python
# Target directory for processed data
DATA_DIR = Path("../../../data/cve_data_stories/vendor_cve_trends/processed")
DATA_DIR.mkdir(parents=True, exist_ok=True)
```

## Collecting Monthly CVE Counts by Vendor

This script processes JSON files containing CVE data (downloaded from NVD) and extracts monthly counts of CVEs for each vendor. The output is saved as a CSV file for further analysis.

### Steps in the Script

1. **Define Datasets**:
   - A dictionary is created where each key is a year (2002–2024) and each value is the corresponding JSON file name:
     ```python
     DATASETS = {year: f"nvdcve-1.1-{year}.json" for year in range(2002, 2025)}
     ```

2. **Define a Function to Extract Monthly Counts**:
   - The function `collect_monthly_counts` processes a single JSON file and:
     - Extracts the `publishedDate` of each CVE to determine the year and month.
     - Extracts vendor names from the `cpe23Uri` field in the `configurations` section.
     - Updates a running tally of CVE counts for each `(vendor, year, month)`.

3. **Handle Missing or Invalid Data**:
   - Skips CVEs without a valid `publishedDate`.
   - Handles missing files, JSON decoding errors, or other exceptions gracefully by logging a message.

4. **Iterate Over All Datasets**:
   - Each year’s JSON file is processed in a loop:
     - Loads the file.
     - Extracts monthly CVE counts by vendor.
   - Uses a `defaultdict` to store cumulative counts for all `(vendor, year, month)` combinations.

5. **Write Results to a CSV File**:
   - Saves the data to a CSV file (`vendor_monthly_counts.csv`) with the following structure:
     | Vendor    | Year | Month | Count |
     |-----------|------|-------|-------|
     | microsoft | 2023 | 1     | 12    |
     | adobe     | 2023 | 1     | 8     |
     | redhat    | 2023 | 1     | 5     |

### Key Features

- **Handles Duplicate Vendors**:
  - Each CVE might list a vendor multiple times, but the script uses a `set` to ensure each vendor is counted only once per CVE.

- **Efficient Storage**:
  - Uses a `defaultdict(int)` to avoid repetitive checks for existing keys, ensuring the data structure is memory-efficient.

- **Error Handling**:
  - Logs errors for missing files, invalid JSON, or unexpected issues, allowing the script to continue processing other datasets.

### Output
- **CSV File**:
  - The final output is a CSV file (`vendor_monthly_counts.csv`) containing:
    - Vendor name.
    - Year and month.
    - CVE count for that vendor in the given month.


```python
# Define datasets
DATASETS = {year: f"nvdcve-1.1-{year}.json" for year in range(2002, 2025)}


def collect_monthly_counts(json_file, month_counts):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        for item in data.get('CVE_Items', []):
            published_date = item.get('publishedDate', None)

            # Parse year and month from the published date
            if published_date:
                date = datetime.strptime(published_date, "%Y-%m-%dT%H:%MZ")
                pub_year = date.year
                pub_month = date.month
            else:
                continue  # Skip if no published date

            # Extract vendor info
            vendors = set()  # Avoid duplicate vendors per CVE
            for node in item.get('configurations', {}).get('nodes', []):
                for cpe in node.get('cpe_match', []):
                    cpe_uri = cpe.get('cpe23Uri', '')
                    if cpe_uri:
                        parts = cpe_uri.split(':')
                        if len(parts) > 4:  # Ensure valid CPE format
                            vendors.add(parts[3])  # Extract vendor

            # Update monthly counts
            for v in vendors:
                month_counts[(v, pub_year, pub_month)] += 1

    except FileNotFoundError:
        print(f"File not found: {json_file}")
    except json.JSONDecodeError:
        print(f"Error decoding JSON: {json_file}")
    except Exception as e:
        print(f"An error occurred: {e}")


# Define data folder
data_folder = Path("../../../data/cve_data_stories/raw")

# Initialize defaultdict to hold monthly counts
monthly_counts = defaultdict(int)

# Process each dataset
for year, file_name in DATASETS.items():
    input_file = data_folder / file_name
    print(f"Processing {input_file}")
    collect_monthly_counts(input_file, monthly_counts)

# Write monthly counts to a CSV
output_csv = DATA_DIR / "vendor_monthly_counts.csv"
with open(output_csv, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Vendor", "Year", "Month", "Count"])  # Header row
    for (vendor, year, month), count in sorted(monthly_counts.items()):
        writer.writerow([vendor, year, month, count])

print(f"Monthly counts written to {output_csv}")

```
