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

# CVE Data Stories: CWE Trends - Data Processing


```python
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd
```

# Paths Setup and Data Directories

We start by defining the paths for the raw CVE datasets and setting up the target directory for storing processed data. This includes creating a dictionary of dataset file names for each year and ensuring the target directory exists for saving outputs.

```python
# Paths
DATASETS = {year: f"nvdcve-1.1-{year}.json" for year in range(2002, 2025)}
data_folder = Path("../../../data/cve_data_stories/raw")

# Target directory for processed data
DATA_DIR = Path("../../../data/cve_data_stories/cwe_trends/processed")
DATA_DIR.mkdir(parents=True, exist_ok=True)

output_csv_yearly = DATA_DIR / "cwe_yearly_counts.csv"
output_csv_cumulative = DATA_DIR / "cwe_yearly_cumulative.csv"
```

# Collecting CWE Yearly Counts

This section processes the raw JSON datasets to extract CWE IDs and their associated publication years.

The key steps include:
1. Reading the JSON files.
2. Extracting CWE IDs and publication years from each CVE item.
3. Counting occurrences of each CWE ID by year.

The resulting yearly counts are stored in a dictionary for further processing.

```python
def collect_cwe_yearly_counts(json_file, year_counts):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        for item in data.get('CVE_Items', []):
            published_date = item.get('publishedDate', None)

            # Parse year from the published date
            if published_date:
                pub_year = datetime.strptime(published_date, "%Y-%m-%dT%H:%MZ").year
            else:
                continue  # Skip if no published date

            # Extract CWE IDs
            cwe_ids = item.get('cve', {}).get('problemtype', {}).get('problemtype_data', [])
            for cwe_entry in cwe_ids:
                for desc in cwe_entry.get('description', []):
                    cwe = desc.get('value', '')  # Get CWE ID (e.g., CWE-79)
                    if cwe:
                        year_counts[(cwe, pub_year)] += 1

    except FileNotFoundError:
        print(f"File not found: {json_file}")
    except json.JSONDecodeError:
        print(f"Error decoding JSON: {json_file}")
    except Exception as e:
        print(f"An error occurred: {e}")


# Initialize defaultdict to hold CWE yearly counts
cwe_yearly_counts = defaultdict(int)

# Process each dataset
for year, file_name in DATASETS.items():
    input_file = data_folder / file_name
    print(f"Processing {input_file}")
    collect_cwe_yearly_counts(input_file, cwe_yearly_counts)

# Write CWE yearly counts to a CSV
with open(output_csv_yearly, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["CWE_ID", "Year", "Count"])  # Header row
    for (cwe_id, year), count in sorted(cwe_yearly_counts.items()):
        writer.writerow([cwe_id, year, count])

print(f"Yearly CWE counts written to {output_csv_yearly}")
```




# Preparing Yearly and Cumulative Counts

The yearly counts are loaded and preprocessed to ensure continuity in the timeline for each CWE ID. Missing years are filled with zero counts, and cumulative counts are calculated for each CWE over time.

The final dataset includes:
1. CWE ID
2. Year
3. Yearly Count
4. Cumulative Count

The processed data is saved to a CSV file for further analysis and visualization.

```python
# Load the yearly counts CSV
df = pd.read_csv(output_csv_yearly)

# Generate all years for each CWE
cwes = df["CWE_ID"].unique()
years = list(range(df["Year"].min(), df["Year"].max() + 1))

# Create a complete index for CWEs and years
full_index = pd.MultiIndex.from_product([cwes, years], names=["CWE_ID", "Year"])
df_full = pd.DataFrame(index=full_index).reset_index()

# Merge with original data, filling missing counts with 0
df = pd.merge(df_full, df, on=["CWE_ID", "Year"], how="left").fillna({"Count": 0})

# Sort by CWE ID and year
df = df.sort_values(by=["CWE_ID", "Year"])

# Calculate cumulative counts
df["Cumulative_Count"] = df.groupby("CWE_ID")["Count"].cumsum().astype(int)

# Save the final dataset
df.to_csv(output_csv_cumulative, index=False)

print(f"Cumulative counts saved to {output_csv_cumulative}")

```
