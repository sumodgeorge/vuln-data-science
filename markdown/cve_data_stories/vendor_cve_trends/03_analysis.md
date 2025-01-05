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

# CVE Data Stories: Vendor CVE Trends - Analysis



## Calculate Cumulative CVE Counts by Vendor (Starting from 1999)

This script processes a CSV file containing monthly CVE counts for each vendor, filters the data to start at 1999, and calculates cumulative totals over time. The output is saved as a new CSV file for further analysis.

### Steps in the Script

1. **Load the Monthly Counts CSV**:
   - Reads a CSV file (`vendor_monthly_counts.csv`) containing CVE counts grouped by `Vendor`, `Year`, and `Month`.

2. **Create a Complete Date Range**:
   - Generates a range of dates from the earliest to the latest `Year` and `Month` in the dataset.
   - Ensures no months are missing for any vendor by creating a complete time series for all vendors.

3. **Filter Data to Start at 1999**:
   - After generating the complete date range, filters the data to include only years starting from 1999. This ensures the dataset focuses on meaningful trends and avoids sparse data from earlier years.

4. **Build a DataFrame for All Vendors and Dates**:
   - Combines the list of unique vendors with the filtered date range using a multi-index.
   - Creates a DataFrame that represents every `(vendor, year, month)` combination, even for months with no CVEs.

5. **Merge and Fill Missing Counts**:
   - Merges the original data with the complete DataFrame, filling missing `Count` values with `0`.

6. **Sort the Data**:
   - Sorts the data by `Vendor`, `Year`, and `Month` to ensure proper order for cumulative calculations.

7. **Calculate Cumulative Totals**:
   - For each vendor, calculates a running total of CVE counts using the `cumsum` method.
   - Ensures the cumulative totals are stored as integers.

8. **Drop Unnecessary Columns**:
   - Removes the `Date` column (if not needed) to reduce file size and simplify the output.

9. **Save Results to a New CSV**:
   - Saves the processed data, including cumulative totals, to a new file (`vendor_cumulative_counts.csv`).

### Key Features

- **Filters Sparse Early Data**:
  - Focuses on data from 1999 onwards for improved analysis and visualization.

- **Handles Missing Data**:
  - Ensures every month is accounted for, even if no CVEs were reported for a vendor in a given month.

- **Efficient Cumulative Calculation**:
  - Uses `groupby` and `cumsum` to calculate cumulative totals efficiently for each vendor.

- **Clean and Sorted Output**:
  - The final CSV is sorted and ready for use in visualizations or additional analysis.

### Output
- **CSV File**:
  - The final output is a CSV file (`vendor_cumulative_counts.csv`) containing:
    | Vendor    | Year | Month | Count | Cumulative_Count |
    |-----------|------|-------|-------|-------------------|
    | freebsd   | 1999 | 1     | 5     | 5                 |
    | freebsd   | 1999 | 2     | 0     | 5                 |
    | freebsd   | 1999 | 3     | 8     | 13                |
    | redhat    | 1999 | 1     | 0     | 0                 |
    | redhat    | 1999 | 2     | 15    | 15                |


```python
import pandas as pd

# Load the monthly counts CSV
input_csv = "../../../data/cve_data_stories/raw/vendor_monthly_counts.csv"
output_csv = "../../../data/cve_data_stories/vendor_cve_trends/processed/vendor_cumulative_counts.csv"

# Read data into a DataFrame
df = pd.read_csv(input_csv)

# Ensure all months are represented for each vendor
# Create a complete date range from the earliest year and month to the latest
date_range = pd.date_range(
    start=f"{df['Year'].min()}-{df['Month'].min()}-01",
    end=f"{df['Year'].max()}-{df['Month'].max()}-01",
    freq="MS"  # Month Start frequency
)

# Create a DataFrame for all vendors and the complete date range
vendors = df["Vendor"].unique()
full_index = pd.MultiIndex.from_product(
    [vendors, date_range],
    names=["Vendor", "Date"]
)
df_full = pd.DataFrame(index=full_index).reset_index()

# Extract Year and Month from the full date range
df_full["Year"] = df_full["Date"].dt.year
df_full["Month"] = df_full["Date"].dt.month

# Filter to include only years from 1999 onwards
df_full = df_full[df_full["Year"] >= 1999]

# Merge with the original data, filling missing counts with 0
df = pd.merge(df_full, df, on=["Vendor", "Year", "Month"], how="left").fillna({"Count": 0})

# Drop the Date column (no longer needed)
df = df.drop(columns=["Date"])

# Sort data by vendor, year, and month
df = df.sort_values(by=["Vendor", "Year", "Month"])

# Calculate cumulative totals
df["Cumulative_Count"] = df.groupby("Vendor")["Count"].cumsum().astype(int)

# Save to a new CSV
df.to_csv(output_csv, index=False)

print(f"Cumulative totals saved to {output_csv}")
```
