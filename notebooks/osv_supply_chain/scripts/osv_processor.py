import json
import pandas as pd
from pathlib import Path
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def classify_entry(entry_id: str) -> str:
    """
    Classify an entry as 'Vulnerability' or 'Malicious Code' based on the ID prefix.
    """
    return "Malicious Code" if entry_id.startswith("MAL-") else "Vulnerability"


def fetch_osv_data_to_dataframe() -> pd.DataFrame:
    """
    Fetch OSV data for all ecosystems, clean and structure it into a Pandas DataFrame.
    """
    raw_data_dir = Path("./data/osv/raw")
    if not raw_data_dir.exists():
        logging.error(f"Raw data directory does not exist: {raw_data_dir}")
        return pd.DataFrame()

    data_rows = []
    # Iterate over each ecosystem directory
    for ecosystem_dir in raw_data_dir.iterdir():
        if not ecosystem_dir.is_dir():
            continue
        ecosystem = ecosystem_dir.name

        # Process each JSON file in the directory
        for file_path in ecosystem_dir.glob("*.json"):
            try:
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(f"JSON decode error in {file_path}: {e}")
                continue

            db_severity = data.get("database_specific", {}).get("severity", "UNKNOWN")
            cwe_ids = data.get("database_specific", {}).get("cwe_ids", [])
            aliases = (
                ", ".join(data.get("aliases", []))
                if data.get("aliases", [])
                else "None"
            )
            affected = data.get("affected", [])
            num_affected = len(affected)
            affected_packages = ", ".join(
                [
                    pkg.get("package", {}).get("name", "")
                    for pkg in affected
                    if pkg.get("package", {}).get("name", "")
                ]
            )

            row = {
                "id": data.get("id", ""),
                "type": classify_entry(data.get("id", "")),
                "summary": data.get("summary", ""),
                "aliases": aliases,
                "ecosystem": ecosystem,
                "database_severity": db_severity,
                "cwe_ids": ", ".join(cwe_ids) if cwe_ids else "None",
                "num_affected": num_affected,
                "affected_packages": affected_packages,
                "modified": data.get("modified", ""),
                "published": data.get("published", ""),
                "withdrawn": data.get("withdrawn", ""),
            }
            data_rows.append(row)

    df = pd.DataFrame(data_rows)
    if df.empty:
        logging.error("No OSV data found.")
        return df

    # Fix date parsing issues
    for col in ["published", "modified", "withdrawn"]:
        df[col] = pd.to_datetime(df[col], format="ISO8601", errors="coerce")

    # Ensure timestamps are timezone-naive
    df["published"] = df["published"].dt.tz_convert(None)
    # Add a "Year" column for analysis
    df["year"] = df["published"].dt.year

    logging.info(f"Fetched {len(df)} OSV records from all ecosystems.")
    return df


def save_osv_dataframe(df: pd.DataFrame):
    """
    Save the cleaned OSV dataset to a CSV file.
    """
    output_file = Path("./data/osv/processed/osv-data.csv")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)
    logging.info(f"OSV data saved to {output_file}")


if __name__ == "__main__":
    osv_df = fetch_osv_data_to_dataframe()
    if not osv_df.empty:
        save_osv_dataframe(osv_df)
