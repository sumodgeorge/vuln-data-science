---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.16.6
  kernelspec:
    display_name: Python 3 (ipykernel)
    language: python
    name: python3
---

```python vscode={"languageId": "python"}
import pandas as pd

df = pd.read_csv("../../data/osv/processed/osv_ecosystem_summary.csv")
df.head(1)
```

```python vscode={"languageId": "python"}
from great_tables import GT, md, html, nanoplot_options
import pandas as pd
import numpy as np
import ast


# Ensure `trend_data` is properly formatted as a comma-separated string
df["trend_data"] = df["trend_data"].apply(
    lambda x: ", ".join(map(str, np.array(ast.literal_eval(x))))
    if isinstance(x, str) and x.startswith("[")
    else ", ".join(map(str, x))
    if isinstance(x, (list, np.ndarray))
    else str(x)
)

df["icon"] = df["type"].replace({"Vulnerability": "bug", "Malicious Code": "skull"})

color_map = {"bug": "purple", "skull": "red"}

# Create a sorted table DataFrame with the desired columns
table_df = df[
    ["ecosystem", "icon", "total_affected", "peak_attack_year", "trend_data"]
].sort_values(["total_affected", "ecosystem"], ascending=[False, True])

# Generate the Great Table
gt_table = (
    GT(table_df)
    .tab_header(
        title=md("**OSV Security Trends**"),
        subtitle=md(
            "_Malicious Code & Vulnerability Insights Across Software Supply Chains_"
        ),
    )
    .tab_stub(rowname_col="ecosystem")
    .tab_stubhead(label="Ecosystem")
    .tab_source_note(source_note=md("*Year Trends from 2014-2024*"))
    .tab_source_note(
        source_note=md(
            "Data sourced from [OSV.dev](https://osv.dev) (Open Source Vulnerability) and analyzed for vulnerability & malicious code trends. Covers PyPI, npm, Maven, Go, RubyGems, NuGet, Packagist, Pub, CRAN, Hackage, Hex, and crates.io. Last updated: February 2025."
        )
    )
    .tab_source_note(
        source_note=md("**Legend:** Bug = Vulnerability | Skull = Malicious Code")
    )
    .tab_stubhead(label="Ecosystem")
    .cols_label(
        ecosystem="Ecosystem",
        icon="Type",
        total_affected="Total",
        peak_attack_year="Peak",
        trend_data="Year Trend",
    )
    .fmt_nanoplot(
        "trend_data",
        plot_type="bar",
        reference_line="mean",
        options=nanoplot_options(
            data_bar_stroke_color="black",
            data_bar_stroke_width=2,
            data_bar_fill_color="darkgray",
            reference_line_color="pink",
        ),
    )
    .fmt_number(columns="total_affected", sep_mark=",", decimals=0)
    .cols_align(align="left", columns=["ecosystem"])
    .cols_align(
        align="center",
        columns=["icon", "total_affected", "peak_attack_year", "trend_data"],
    )
    .fmt_icon(columns="icon", fill_color=color_map)
)


# Generate the raw HTML from the table
html_output = gt_table.as_raw_html()

# Save it to an HTML file
with open(
    "../../data/osv/processed/osv_security_trends.html", "w", encoding="utf-8"
) as f:
    f.write(html_output)

# Display the table
gt_table
```
