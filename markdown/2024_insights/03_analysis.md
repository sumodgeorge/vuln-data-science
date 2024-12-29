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

```python
import json

import pandas as pd
```

```python
df_2024 = pd.read_csv('../../data/2024_insights/processed/nvd_data_2024.csv')
df_2023 = pd.read_csv('../../data/2024_insights/processed/nvd_data_2023.csv')

df_2024.head()
```

# Overview Metrics

This section calculates high-level aggregate metrics to summarize vulnerability data:

1. **Total Vulnerabilities Published**: Total CVEs published in each year (2023 and 2024).
2. **Month with Most Vulnerabilities Published**: Identifies the month with the highest vulnerability count.
3. **Vulnerability Severity Distribution**: Calculates the distribution of Critical, High, Medium, and Low severity vulnerabilities.


```python
total_vulns_2023 = df_2023.shape[0]
total_vulns_2024 = df_2024.shape[0]
percentage_change = round(((total_vulns_2024 - total_vulns_2023) / total_vulns_2023) * 100, 3)

total_vulnerabilities = {
    "2023": total_vulns_2023,
    "2024": total_vulns_2024,
    "percentage_change": percentage_change
}

# 2023 Data
month_2023 = df_2023['Published_Month'].value_counts().idxmax()
count_2023 = df_2023['Published_Month'].value_counts().max()

# 2024 Data
month_2024 = df_2024['Published_Month'].value_counts().idxmax()
count_2024 = df_2024['Published_Month'].value_counts().max()

month_with_most_vulnerabilities = {
    "2023": {
        "month": int(month_2023),  # Convert np.int64 to int
        "vulnerability_count": int(count_2023)
    },
    "2024": {
        "month": int(month_2024),  # Convert np.int64 to int
        "vulnerability_count": int(count_2024)
    },
    "comparison": {
        "percentage_change": round(float((count_2024 - count_2023) / count_2023) * 100, 3),
        "difference_in_vulnerability_count": int(count_2024 - count_2023)
    }
}

severity_distribution = {
    "2023": df_2023['CVSS_Severity'].value_counts().to_dict(),
    "2024": df_2024['CVSS_Severity'].value_counts().to_dict()
}

overview_metrics = {
    "total_vulnerabilities": total_vulnerabilities,
    "month_with_most_vulnerabilities": month_with_most_vulnerabilities,
    "severity_distribution": severity_distribution
}

# Save the overview_metrics to a JSON file
with open("../../data/2024_insights/output/overview_metrics.json", "w") as f:
    json.dump(overview_metrics, f)

overview_metrics
```

# Time-Series Metrics

This section focuses on trends over time to analyze how vulnerabilities evolve month-to-month:

1. **Monthly Vulnerability Counts**: Monthly counts of vulnerabilities published in 2023 and 2024.
2. **Severity Trends**: Tracks changes in vulnerability severities (Critical, High, Medium, Low) over time.
3. **Spike in Vulnerability Counts**: Highlights months with significant increases in vulnerability publication.


```python
# Group by Published_Month and count vulnerabilities for each year
monthly_counts_2023 = df_2023.groupby('Published_Month').size().reindex(range(1, 13), fill_value=0)
monthly_counts_2024 = df_2024.groupby('Published_Month').size().reindex(range(1, 13), fill_value=0)

monthly_vulnerability_counts = {
    "2023": monthly_counts_2023.to_dict(),
    "2024": monthly_counts_2024.to_dict(),
}

# Ensure all severities are represented
all_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

# Group and count by Published_Month and CVSS_Severity for each year
severity_2023 = df_2023.groupby(['Published_Month', 'CVSS_Severity']).size().unstack(fill_value=0)
severity_2024 = df_2024.groupby(['Published_Month', 'CVSS_Severity']).size().unstack(fill_value=0)

# Ensure all months and severities are represented
severity_2023 = severity_2023.reindex(columns=all_severities, fill_value=0).reindex(range(1, 13), fill_value=0)
severity_2024 = severity_2024.reindex(columns=all_severities, fill_value=0).reindex(range(1, 13), fill_value=0)

severity_trends = {
    "2023": severity_2023.to_dict(orient='index'),
    "2024": severity_2024.to_dict(orient='index')
}

# Calculate percentage change month-over-month
spike_analysis_2023 = (monthly_counts_2023.pct_change().fillna(0) * 100).round(2)
spike_analysis_2024 = (monthly_counts_2024.pct_change().fillna(0) * 100).round(2)

# Identify significant spikes (e.g., >20% increase)
spikes_2023 = spike_analysis_2023[spike_analysis_2023 > 20]
spikes_2024 = spike_analysis_2024[spike_analysis_2024 > 20]

spike_analysis = {
    "2023": {
        int(month): {
            "percentage_increase": round(float(spike_analysis_2023[month]), 2),
            "vulnerability_count": int(monthly_counts_2023[month])
        }
        for month in spikes_2023.index
    },
    "2024": {
        int(month): {
            "percentage_increase": round(float(spike_analysis_2024[month]), 2),
            "vulnerability_count": int(monthly_counts_2024[month])
        }
        for month in spikes_2024.index
    }
}
time_series_metrics = {
    "monthly_vulnerability_counts": monthly_vulnerability_counts,
    "severity_trends": severity_trends,
    "spike_analysis": spike_analysis,
}

# Save the time_series_metrics to a JSON file
with open("../../data/2024_insights/output/time_series_metrics.json", "w") as f:
    json.dump(time_series_metrics, f)

time_series_metrics
```

# Vendor/Product Analysis

This section investigates vulnerabilities at the vendor and product levels:

1. **Top Vendors by Vulnerabilities**: Ranks vendors with the most vulnerabilities, focusing on Critical and High severities.
2. **Top Products by Vulnerabilities**: Visualizes vulnerabilities grouped by product, nested under their vendors.
3. **Vulnerability Trends by Vendor**: Tracks monthly trends for top vendors across 2023 and 2024.
4. **Critical Vulnerability Spike Analysis**: Explores Critical vulnerabilities by vendor and product for peak months.


```python
# Configuration for dynamic counts
TOP_VENDOR_COUNT = 10
TOP_PRODUCT_COUNT = 5

# Top Vendors for 2023 and 2024
top_vendors_2023 = (
    df_2023.groupby('Vendor')
    .size()
    .sort_values(ascending=False)
    .head(TOP_VENDOR_COUNT)
    .reset_index(name='count')
)

top_vendors_2024 = (
    df_2024.groupby('Vendor')
    .size()
    .sort_values(ascending=False)
    .head(TOP_VENDOR_COUNT)
    .reset_index(name='count')
)

# Top Products for Each Vendor (2023 and 2024)
top_products = {"2023": {}, "2024": {}}
for vendor in top_vendors_2024['Vendor']:
    top_products["2024"][vendor] = (
        df_2024[df_2024['Vendor'] == vendor]
        .groupby('Product')
        .size()
        .sort_values(ascending=False)
        .head(TOP_PRODUCT_COUNT)
        .reset_index(name='count')
        .to_dict(orient='records')
    )

for vendor in top_vendors_2023['Vendor']:
    top_products["2023"][vendor] = (
        df_2023[df_2023['Vendor'] == vendor]
        .groupby('Product')
        .size()
        .sort_values(ascending=False)
        .head(TOP_PRODUCT_COUNT)
        .reset_index(name='count')
        .to_dict(orient='records')
    )

# Vendor Trends (Monthly Counts for 2023 and 2024)
vendor_trends = {"2023": {}, "2024": {}}
for vendor in top_vendors_2024['Vendor']:
    vendor_trends["2024"][vendor] = (
        df_2024[df_2024['Vendor'] == vendor]
        .groupby('Published_Month')
        .size()
        .reindex(range(1, 13), fill_value=0)
        .tolist()
    )

for vendor in top_vendors_2023['Vendor']:
    vendor_trends["2023"][vendor] = (
        df_2023[df_2023['Vendor'] == vendor]
        .groupby('Published_Month')
        .size()
        .reindex(range(1, 13), fill_value=0)
        .tolist()
    )

# Critical Spikes (2023 and 2024)
critical_spikes = {"2023": {}, "2024": {}}
critical_vulns_2023 = df_2023[df_2023['CVSS_Severity'] == 'CRITICAL']
critical_vulns_2024 = df_2024[df_2024['CVSS_Severity'] == 'CRITICAL']

for vendor in top_vendors_2024['Vendor']:
    critical_spikes["2024"][vendor] = {}
    vendor_critical = critical_vulns_2024[critical_vulns_2024['Vendor'] == vendor]
    for product in top_products["2024"].get(vendor, []):
        product_name = product['Product']
        product_critical = vendor_critical[vendor_critical['Product'] == product_name]
        if not product_critical.empty:
            top_month = (
                product_critical.groupby('Published_Month').size().idxmax()
            )
            count = (
                product_critical.groupby('Published_Month').size().max()
            )
            critical_spikes["2024"][vendor][product_name] = {
                "month": pd.to_datetime(f"2024-{top_month}-01").strftime('%B'),
                "count": int(count)
            }

for vendor in top_vendors_2023['Vendor']:
    critical_spikes["2023"][vendor] = {}
    vendor_critical = critical_vulns_2023[critical_vulns_2023['Vendor'] == vendor]
    for product in top_products["2023"].get(vendor, []):
        product_name = product['Product']
        product_critical = vendor_critical[vendor_critical['Product'] == product_name]
        if not product_critical.empty:
            top_month = (
                product_critical.groupby('Published_Month').size().idxmax()
            )
            count = (
                product_critical.groupby('Published_Month').size().max()
            )
            critical_spikes["2023"][vendor][product_name] = {
                "month": pd.to_datetime(f"2023-{top_month}-01").strftime('%B'),
                "count": int(count)
            }

# Final Vendor/Product Analysis JSON
vendor_product = {
    "top_vendors": {
        "2023": top_vendors_2023.to_dict(orient='records'),
        "2024": top_vendors_2024.to_dict(orient='records'),
    },
    "top_products": top_products,
    "vendor_trends": vendor_trends,
    "critical_spikes": critical_spikes,
}

# Save the vendor_product metrics to a JSON file
with open("../../data/2024_insights/output/vendor_product.json", "w") as f:
    json.dump(vendor_product, f)

vendor_product
```

# CISA KEV Analysis

This section evaluates the relationship between NVD data and the CISA KEV catalog:

1. **Vulnerabilities Added to CISA KEV**: Counts vulnerabilities added to the KEV catalog, with YoY comparison.
2. **CISA KEV Overlap with NVD**: Shows percentage of NVD vulnerabilities that are also in the KEV catalog.
3. **Top Exploited Vendors in CISA KEV**: Ranks vendors with the most KEV vulnerabilities.
4. **Time to CISA KEV Inclusion**: Calculates time between NVD publication and KEV inclusion.



# Specific CVE Details

This section highlights vulnerabilities with high impact or severity:

1. **Most Severe Vulnerabilities**: Lists CVEs with the highest CVSS scores.
2. **Most Impactful Vulnerabilities**: Combines multiple factors (CVSS, KEV inclusion, exploitation evidence) to rank vulnerabilities.


```python
# Filter only CISA KEV records early
kev_records_2023 = df_2023[df_2023['CISA_KEV'] == True].copy()
kev_records_2024 = df_2024[df_2024['CISA_KEV'] == True].copy()

# Ensure datetime columns are in the correct format and remove timezone info
for df in [kev_records_2023, kev_records_2024]:
    df['KEV_DateAdded'] = pd.to_datetime(df['KEV_DateAdded'], errors='coerce').dt.tz_localize(None)
    df['Published_Date'] = pd.to_datetime(df['Published_Date'], errors='coerce').dt.tz_localize(None)

# Group CISA KEV Data by Month for 2023 and 2024
kev_additions = {
    year: records[records['KEV_DateAdded'].dt.year == int(year)]
    .groupby(records['KEV_DateAdded'].dt.month)
    .size()
    .reindex(range(1, 13), fill_value=0)
    .to_dict()
    for year, records in {"2023": kev_records_2023, "2024": kev_records_2024}.items()
}

# Calculate Month-over-Month Changes in KEV Additions
kev_monthly_changes = {
    year: {
        month: round(((kev_additions[year][month] - kev_additions[year][month - 1]) /
                      kev_additions[year][month - 1]) * 100, 2)
        if month > 1 and kev_additions[year][month - 1] > 0 else 0
        for month in range(1, 13)
    }
    for year in ["2023", "2024"]
}

# Calculate NVD-KEV Overlap Percentage
nvd_cve_counts = {
    year: df.groupby('Published_Month').size().reindex(range(1, 13), fill_value=0)
    for year, df in {"2023": df_2023, "2024": df_2024}.items()
}

kev_overlap = {
    year: {
        month: round(float((kev_additions[year].get(month, 0) / nvd_cve_counts[year][month]) * 100), 2)
        if nvd_cve_counts[year][month] > 0 else 0
        for month in range(1, 13)
    }
    for year in ["2023", "2024"]
}

# Top Vendors in KEV Catalog for 2023 and 2024
top_kev_vendors = {
    year: (
        records[records['KEV_DateAdded'].dt.year == int(year)]
        .groupby('KEV_Vendor')
        .size()
        .sort_values(ascending=False)
        .head(10)
        .reset_index(name='kev_count')
        .to_dict(orient='records')
    )
    for year, records in {"2023": kev_records_2023, "2024": kev_records_2024}.items()
}

# Vendor Ranking Changes (Prioritize 2024 top vendors and compare with 2023)
vendor_rank_changes = []
for vendor in {v['KEV_Vendor'] for v in top_kev_vendors['2024']}:
    rank_2023 = next((i + 1 for i, v in enumerate(top_kev_vendors['2023']) if v['KEV_Vendor'] == vendor), None)
    rank_2024 = next((i + 1 for i, v in enumerate(top_kev_vendors['2024']) if v['KEV_Vendor'] == vendor), None)
    vendor_rank_changes.append({
        "vendor": vendor,
        "2023_rank": rank_2023,
        "2024_rank": rank_2024
    })

# Sort the vendor_rank_changes by 2024 rank
vendor_rank_changes = sorted(vendor_rank_changes, key=lambda x: x["2024_rank"] if x["2024_rank"] else float('inf'))

# Time to KEV Inclusion Metrics for 2023 and 2024
time_to_kev_inclusion = {}
for year, records in {"2023": kev_records_2023, "2024": kev_records_2024}.items():
    inclusion_times = records[records['KEV_DateAdded'].dt.year == int(year)].copy()
    inclusion_times['Time_To_KEV'] = (
            inclusion_times['KEV_DateAdded'] - inclusion_times['Published_Date']
    ).dt.days
    inclusion_times = inclusion_times[inclusion_times['Time_To_KEV'] >= 0]
    time_to_kev_inclusion[year] = {
        "min_days": int(inclusion_times['Time_To_KEV'].min()) if not inclusion_times.empty else None,
        "max_days": int(inclusion_times['Time_To_KEV'].max()) if not inclusion_times.empty else None,
        "average_days": round(float(inclusion_times['Time_To_KEV'].mean()), 2) if not inclusion_times.empty else None
    }

# Final JSON Structure
cisa_kev = {
    "kev_additions": kev_additions,
    "kev_monthly_changes": kev_monthly_changes,
    "nvd_kev_overlap": {
        "data": kev_overlap,
        "note": "Percentage of NVD vulnerabilities in a month that were also added to KEV."
    },
    "top_kev_vendors": top_kev_vendors,
    "vendor_rank_changes": vendor_rank_changes,
    "time_to_kev_inclusion": time_to_kev_inclusion
}

# Save the cisa_kev metrics to a JSON file
with open("../../data/2024_insights/output/cisa_kev.json", "w") as f:
    json.dump(cisa_kev, f)

cisa_kev
```

# Specific CVE Details

This section highlights vulnerabilities with high impact or severity:

1. **Most Severe Vulnerabilities**: Lists CVEs with the highest CVSS scores.
2. **Most Impactful Vulnerabilities**: Combines multiple factors (CVSS, KEV inclusion, exploitation evidence) to rank vulnerabilities.

```python
# Filter for all CVEs with CVSS_Base_Score of 10.0
cvss_10_cves = df_2024[df_2024['CVSS_Base_Score'] == 10.0]

# Additional CVEs to include if fewer than 25
remaining_cves_needed = 25 - len(cvss_10_cves)
if remaining_cves_needed > 0:
    additional_cves = (
        df_2024[df_2024['CVSS_Base_Score'] < 10.0]
        .sort_values(by=['CVSS_Base_Score', 'CVE_ID'], ascending=[False, True])
        [['CVE_ID', 'Description', 'CVSS_Base_Score', 'Vendor', 'Product']]
        .drop_duplicates()
        .head(remaining_cves_needed)
    )
    most_severe = pd.concat([cvss_10_cves, additional_cves]).drop_duplicates()
else:
    most_severe = cvss_10_cves

# Ensure the final result is sorted and unique
most_severe = (
    most_severe.sort_values(by=['CVSS_Base_Score', 'CVE_ID'], ascending=[False, True])
    [['CVE_ID', 'Description', 'CVSS_Base_Score', 'Vendor', 'Product']]
    .drop_duplicates()
    .to_dict(orient='records')
)

# Add exploitation evidence if not already present
df_2024['Exploitation_Evidence'] = df_2024['CVE_ID'].isin(kev_records_2024['CVE_ID'])


# Define Impact Score calculation function
def calculate_impact_score(row):
    exploitation_weight = 10 if row['Exploitation_Evidence'] else 0
    impact_score = row['CVSS_Base_Score'] * 2 + exploitation_weight
    return round(impact_score, 2)


# Calculate Impact Scores
df_2024['Impact_Score'] = df_2024.apply(calculate_impact_score, axis=1)

# Filter for most impactful CVEs
most_impactful = (
    df_2024.sort_values(by=['Impact_Score', 'CVE_ID'], ascending=[False, True])
    [['CVE_ID', 'Impact_Score', 'Exploitation_Evidence', 'Vendor', 'Product']]
    .drop_duplicates()
    .head(10)  # Top 10 CVEs
    .to_dict(orient='records')
)

# Final JSON structure
specific_cve_details = {
    "most_severe": most_severe,
    "most_impactful": most_impactful,
    "notes": {
        "most_severe": "Includes all CVEs with CVSS_Base_Score of 10.0 and additional CVEs to make a total of 25, if fewer than 25 CVSS 10.0 CVEs exist.",
        "most_impactful": "Top 10 CVEs by impact score, prioritizing exploitation evidence."
    }
}

# Save the specific_cve_details metrics to a JSON file
with open("../../data/2024_insights/output/specific_cve_details.json", "w") as f:
    json.dump(specific_cve_details, f)

specific_cve_details
```

# CVE Assigner Analysis

This section identifies the organizations assigning the most CVEs:

1. **Top CVE Assigners**: Highlights top assigners by the number of CVEs and severity breakdown (Critical and High).


```python
# Group by CVE Assigner for 2023 and 2024 with severity breakdown and total counts


def get_top_assigners_with_totals(df, year):
    assigner_data = (
        df.groupby('CVE_Assigner')
        .agg(
            cve_count=('CVE_ID', 'count'),
            critical_count=('CVSS_Base_Score', lambda x: (x >= 9.0).sum()),
            high_count=('CVSS_Base_Score', lambda x: ((x >= 7.0) & (x < 9.0)).sum()),
            medium_count=('CVSS_Base_Score', lambda x: ((x >= 4.0) & (x < 7.0)).sum()),
            low_count=('CVSS_Base_Score', lambda x: (x < 4.0).sum())
        )
        .reset_index()
        .sort_values(by='cve_count', ascending=False)  # Sort by total CVE count
        .head(10)  # Top 10 assigners
    )
    assigner_data['year'] = year  # Add year for clarity in the final structure
    return assigner_data


# Generate data for both years
top_assigners_2023 = get_top_assigners_with_totals(df_2023, "2023")
top_assigners_2024 = get_top_assigners_with_totals(df_2024, "2024")

# Add overall totals including percentage changes
total_2023 = {
    "year": "2023",
    "cve_count": df_2023['CVE_ID'].count().item(),
    **top_assigners_2023[['critical_count', 'high_count', 'medium_count', 'low_count']].sum().to_dict()
}
total_2024 = {
    "year": "2024",
    "cve_count": df_2024['CVE_ID'].count().item(),
    **top_assigners_2024[['critical_count', 'high_count', 'medium_count', 'low_count']].sum().to_dict()
}

# Calculate percentage changes between years
percentage_changes = {
    key: round((total_2024[key] - total_2023[key]) / total_2023[key] * 100, 2)
    if total_2023[key] > 0 else None
    for key in ['cve_count', 'critical_count', 'high_count', 'medium_count', 'low_count']
}

# Transform to JSON-friendly structure
top_assigners = {
    "top_assigners": {
        "2023": top_assigners_2023.to_dict(orient='records'),
        "2024": top_assigners_2024.to_dict(orient='records'),
        "comparison_notes": (
            "Critical: CVSS >= 9.0, High: 7.0 <= CVSS < 9.0, "
            "Medium: 4.0 <= CVSS < 7.0, Low: CVSS < 4.0. "
            "Shows top assigners for each year with severity breakdowns, "
            "total counts, and year-over-year changes."
        ),
        "totals": {
            "2023": total_2023,
            "2024": total_2024,
            "percentage_changes": percentage_changes
        }
    }
}

# Save the top_assigners metrics to a JSON file
with open("../../data/2024_insights/output/top_assigners.json", "w") as f:
    json.dump(top_assigners, f)

top_assigners
```
