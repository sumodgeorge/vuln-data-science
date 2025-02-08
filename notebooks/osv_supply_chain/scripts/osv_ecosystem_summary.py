import pandas as pd
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Load the processed OSV data
data_file = Path("./data/osv/processed/osv-data.csv")
if not data_file.exists():
    logging.error(f"Processed OSV data not found at {data_file}")
    exit(1)

df = pd.read_csv(str(data_file))

# Define year range (2015-2025)
YEAR_RANGE = list(range(2014, 2025))

# Aggregate key statistics by ecosystem and type
ecosystem_summary = (
    df.groupby(["ecosystem", "type"])
    .agg(
        total_affected=("num_affected", "sum"),
        most_affected_package=(
            "affected_packages",
            lambda x: x.value_counts().idxmax() if not x.isna().all() else "N/A",
        ),
        peak_attack_year=(
            "year",
            lambda x: x.value_counts().idxmax() if not x.isna().all() else "N/A",
        ),
    )
    .reset_index()
)

# Compute yearly trends per ecosystem and type
# (Group by both 'ecosystem' and 'type')
yearly_trends = df.groupby(["ecosystem", "type", "year"]).size().unstack(fill_value=0)

# Ensure every group has values for all years (fill missing years with 0)
for year in YEAR_RANGE:
    if year not in yearly_trends.columns:
        yearly_trends[year] = 0


# Function to return trend data as an array for plotting,
# using both ecosystem and type as the key.
def get_yearly_trend(row):
    ecosystem = row["ecosystem"]
    typ = row["type"]
    key = (ecosystem, typ)
    if key in yearly_trends.index:
        return [int(yearly_trends.loc[key, year]) for year in YEAR_RANGE]
    return [0] * len(YEAR_RANGE)


# Apply yearly trend array to each row of the summary
ecosystem_summary["trend_data"] = ecosystem_summary.apply(get_yearly_trend, axis=1)

# Remove duplicate package names (keep the first if multiple)
ecosystem_summary["most_affected_package"] = ecosystem_summary[
    "most_affected_package"
].apply(lambda x: x.split(", ")[0] if isinstance(x, str) else x)

# Save the ecosystem summary to CSV
output_file = Path("./data/osv/processed/osv_ecosystem_summary.csv")
output_file.parent.mkdir(parents=True, exist_ok=True)
ecosystem_summary.to_csv(str(output_file), index=False)
logging.info(f"Ecosystem summary saved to {output_file}")
