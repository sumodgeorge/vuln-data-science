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

# Weekly CVE - Data Cleaning

```python
import json

import pandas as pd
```

## Script to Process NVD Data and Integrate CISA KEV Data

This script processes NVD JSON data for a specified year and enriches it with CISA Known Exploited Vulnerabilities (KEV) data.

### Features:
1. **Processes NVD Data**:
   - Extracts key fields such as CVE ID, description, CWE, CVSS scores, vendor, product, and publication dates.
   - Adds `CVE_Assigner` from the `CVE_data_meta.ASSIGNER` field.

2. **Enriches with CISA KEV Data**:
   - Merges with CISA KEV dataset to include information on exploited vulnerabilities.
   - Identifies if a CVE is part of CISA KEV.

3. **Generates Additional Fields**:
   - Adds derived fields such as `Published_Year`, `Published_Month`, and `Published_YearMonth` for trend analysis.

4. **Final Output**:
   - Saves the processed data to a CSV file, ready for analysis and visualization.

### Final Columns:
- **CVE_ID**: Unique identifier for the vulnerability.
- **Description**: English description of the CVE.
- **CWE**: Common Weakness Enumeration for the vulnerability.
- **CVSS_Base_Score**: CVSS v3 base score.
- **CVSS_Severity**: Severity rating (Critical, High, Medium, Low).
- **CVSS_Vector**: Attack vector for the CVE.
- **Exploitability_Score**: CVSS exploitability score.
- **Impact_Score**: CVSS impact score.
- **Vendor**: Vendor of the vulnerable product.
- **Product**: Vulnerable product name.
- **CVE_Assigner**: Organization or individual who assigned the CVE.
- **Published_Date**: Date the CVE was published.
- **Last_Modified_Date**: Date the CVE was last modified.
- **Published_Year**, **Published_Month**, **Published_YearMonth**: Derived fields for time-based analysis.
- **CISA_KEV**: Boolean indicating if the CVE is in the CISA KEV catalog.
- **KEV_DateAdded**: Date the CVE was added to CISA KEV.
- **KEV_Vendor**: Vendor information from CISA KEV.
- **KEV_Product**: Product information from CISA KEV.
- **KEV_ShortDescription**: Short description from CISA KEV.
- **KEV_KnownRansomware**: Ransomware association, if any.


```python
def process_nvd_data(year):
    # Define input & output paths
    file_path = f'../../data/2024_insights/raw/nvdcve-1.1-{year}.json'
    cisa_kev_path = '../../data/2024_insights/raw/known_exploited_vulnerabilities.csv'
    output_path_template = '../../data/2024_insights/processed/nvd_data_{}.csv'

    # Load the NVD JSON data for the given year
    with open(file_path, 'r') as file:
        nvd_data = json.load(file)

    records = []
    for item in nvd_data['CVE_Items']:
        cve = item['cve']
        cve_id = cve['CVE_data_meta']['ID']
        cve_assigner = cve.get('CVE_data_meta', {}).get('ASSIGNER', None)

        # Extract English description (if any)
        description = next(
            (desc['value'] for desc in cve['description']['description_data'] if desc['lang'] == 'en'),
            'No description available'
        )

        # Extract CWE
        cwe = next((
            desc['value']
            for problem in cve['problemtype']['problemtype_data']
            for desc in problem['description']
            if desc['lang'] == 'en'
        ), None)

        # Extract CVSS v3 details
        impact_data = item.get('impact', {})
        base_metric_v3 = impact_data.get('baseMetricV3', {})
        cvss_data = base_metric_v3.get('cvssV3', {})

        cvss_base_score = cvss_data.get('baseScore')
        cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
        cvss_vector = cvss_data.get('vectorString')
        exploitability_score = base_metric_v3.get('exploitabilityScore')
        impact_score = base_metric_v3.get('impactScore')

        # Parse published & modified dates
        published_date_str = item.get('publishedDate')
        last_modified_date_str = item.get('lastModifiedDate')
        published_date = pd.to_datetime(published_date_str, errors='coerce') or pd.NaT
        last_modified_date = pd.to_datetime(last_modified_date_str, errors='coerce') or pd.NaT

        # Create derived date fields
        published_year = published_date.year if pd.notnull(published_date) else None
        published_month = published_date.month if pd.notnull(published_date) else None
        published_ym = published_date.tz_localize(None).to_period('M') if pd.notnull(published_date) else None

        # Build records for each vendor-product pair
        cpe_found = False
        for node in item.get('configurations', {}).get('nodes', []):
            for cpe_match in node.get('cpe_match', []):
                if cpe_match.get('vulnerable'):
                    cpe_parts = cpe_match['cpe23Uri'].split(':')
                    vendor = cpe_parts[3].title() if len(cpe_parts) > 3 else "Unknown Vendor"
                    product = cpe_parts[4].title() if len(cpe_parts) > 4 else "Unknown Product"

                    records.append([
                        cve_id, description, cwe, cvss_base_score, cvss_severity,
                        cvss_vector, exploitability_score, impact_score, vendor,
                        product, cve_assigner, published_date_str, last_modified_date_str,
                        published_date, last_modified_date, published_year,
                        published_month, published_ym
                    ])
                    cpe_found = True

        if not cpe_found:
            records.append([
                cve_id, description, cwe, cvss_base_score, cvss_severity,
                cvss_vector, exploitability_score, impact_score, None,
                None, cve_assigner, published_date_str, last_modified_date_str,
                published_date, last_modified_date, published_year,
                published_month, published_ym
            ])

    # Convert to DataFrame
    columns = [
        'CVE_ID', 'Description', 'CWE', 'CVSS_Base_Score', 'CVSS_Severity',
        'CVSS_Vector', 'Exploitability_Score', 'Impact_Score', 'Vendor',
        'Product', 'CVE_Assigner', 'Published_Date_Str', 'Last_Modified_Date_Str',
        'Published_Date', 'Last_Modified_Date', 'Published_Year',
        'Published_Month', 'Published_YearMonth'
    ]
    df = pd.DataFrame(records, columns=columns)

    # Merge with the CISA KEV data
    kev_df = pd.read_csv(cisa_kev_path, parse_dates=['dateAdded'])
    kev_df.rename(
        columns={
            'cveID': 'CVE_ID',
            'dateAdded': 'KEV_DateAdded',
            'vendorProject': 'KEV_Vendor',
            'product': 'KEV_Product',
            'shortDescription': 'KEV_ShortDescription',
            'knownRansomwareCampaignUse': 'KEV_KnownRansomware'
        },
        inplace=True
    )
    kev_df['KEV_KnownRansomware'] = kev_df['KEV_KnownRansomware'].fillna("Unknown").str.capitalize()
    kev_df['KEV_Notes'] = kev_df['notes'].str.split(';').str[0].str.strip()

    df = df.merge(
        kev_df[['CVE_ID', 'KEV_DateAdded', 'KEV_Vendor', 'KEV_Product', 'KEV_ShortDescription', 'KEV_KnownRansomware']],
        on='CVE_ID',
        how='left'
    )
    df['CISA_KEV'] = df['KEV_DateAdded'].notna()

    # Define final column order
    final_columns = [
        'CVE_ID', 'Description', 'CWE', 'CVSS_Base_Score', 'CVSS_Severity',
        'CVSS_Vector', 'Exploitability_Score', 'Impact_Score', 'Vendor',
        'Product', 'CVE_Assigner', 'Published_Date', 'Last_Modified_Date',
        'Published_Year', 'Published_Month', 'Published_YearMonth',
        'CISA_KEV', 'KEV_DateAdded', 'KEV_Vendor', 'KEV_Product',
        'KEV_ShortDescription', 'KEV_KnownRansomware'
    ]
    df = df[final_columns]

    # Save processed data to CSV
    output_path = output_path_template.format(year)
    df.to_csv(output_path, index=False, encoding='utf-8')

    return df


# Process NVD data for 2023
df_2023 = process_nvd_data(2023)

# Process NVD data for 2024
df_2024 = process_nvd_data(2024)
df_2024.head()
```
