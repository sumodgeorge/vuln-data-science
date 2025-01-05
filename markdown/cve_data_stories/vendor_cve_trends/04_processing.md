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

<!-- #raw -->
# CVE Data Stories: Vendor CVE Trends - Processing
<!-- #endraw -->

## **Preprocessing Vendors for Bar Chart Race**

This script preprocesses the cumulative CVE data to filter out vendors that have never been in the **Top 20** based on cumulative CVE counts during any period (Year-Month). By focusing only on these significant vendors, the dataset becomes more efficient to process and ensures meaningful insights in the bar chart race.

---

### **Steps in the Script**

1. **Load Cumulative Data**
   - The script starts by reading the `vendor_cumulative_counts.csv` file, which contains the cumulative CVE counts for each vendor across Year-Month periods.
   - This serves as the raw data for filtering.

2. **Remove Empty Periods**
   - Any rows where the `Cumulative_Count` is `0` are excluded.
   - This step ensures that only meaningful periods are used for ranking and filtering.

3. **Rank Vendors for Each Period**
   - Vendors are ranked **within each Year-Month period** based on their cumulative CVE counts:
     - A rank of `1` indicates the highest cumulative CVE count in that period.
     - Ties are handled by assigning the lowest rank among the tied vendors.

4. **Identify Top Vendors**
   - The script identifies vendors that have achieved a rank of **20 or better** in at least one period.
   - These vendors represent the most significant contributors to CVE disclosures.

5. **Filter to Top 20 Vendors**
   - The dataset is filtered to include only rows corresponding to these **Top 20** vendors across all periods.

6. **Drop Unnecessary Columns**
   - The `Rank` column, used for intermediate calculations, is removed to streamline the final dataset.

7. **Save the Filtered Data**
   - The filtered dataset is saved as `vendor_top_20.csv` in the original format:
     ```
     Vendor,Year,Month,Count,Cumulative_Count
     ```


```python
import pandas as pd

# Load cumulative data
input_csv = "../../../data/cve_data_stories/vendor_cve_trends/processed/vendor_cumulative_counts.csv"
df = pd.read_csv(input_csv)

# Remove periods where all vendors have Cumulative_Count = 0
df = df[df["Cumulative_Count"] > 0]

# Rank vendors for each Year-Month period based on Cumulative_Count
df["Rank"] = df.groupby(["Year", "Month"])["Cumulative_Count"].rank(
    method="min", ascending=False
)

# Filter vendors that have been in the Top 20 at least once
top_vendors = df[df["Rank"] <= 20]["Vendor"].unique()

# Filter the original dataset to include only these top vendors
df_filtered = df[df["Vendor"].isin(top_vendors)]

# Drop the Rank column (optional, as it's no longer needed)
df_filtered = df_filtered.drop(columns=["Rank"])

# Save the filtered data
filtered_csv = "../../../data/cve_data_stories/vendor_cve_trends/processed/vendor_top_20.csv"
df_filtered.to_csv(filtered_csv, index=False)

print(f"Filtered dataset saved to {filtered_csv}.")

```
