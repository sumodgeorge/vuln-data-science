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

# CVE Data Stories: Vendor CVE Trends - Visualizations



## Bar Chart Race: Top 10 CVE Vendors (1996–2024)

This script generates a dynamic bar chart race showcasing the top 10 vendors by cumulative CVE count over time (1996–2024). CVE data offers critical insights into vendor-specific trends in cybersecurity vulnerabilities, highlighting shifts in the security landscape across two decades.

---

### Steps in the Script

1. **Import Necessary Libraries**:
   - `pandas`: For efficient data manipulation and preprocessing.
   - `bar_chart_race`: To create the bar chart race animation.
   - `matplotlib`: For additional visual customizations, including fonts and color palettes.

2. **Load and Preprocess Data**:
   - Reads a CSV file (`vendor_top_20.csv`) containing cumulative CVE counts for vendors by year and month.
   - Normalizes vendor names for consistency.
   - Ensures inclusion of all vendors that appeared in the top 20 during the analyzed period.

3. **Pivot and Format Data**:
   - Prepares the dataset for visualization by transforming it into a pivot table:
     - **Rows**: Time (`Year`, `Month`).
     - **Columns**: Vendors.
     - **Values**: Cumulative CVE counts.
   - Combines `Year` and `Month` into a `Date` column (`YYYY-MM`) for a continuous time index.

4. **Assign Colors**:
   - **Brand Colors**: Maps vendors to their official brand colors for easy recognition.
   - **Fallback Colors**: Assigns visually distinct colors to vendors without defined brand colors.

5. **Generate the Bar Chart Race**:
   - Animates the top 10 vendors dynamically over time:
     - Bars update their positions and lengths based on cumulative CVE counts.
     - Parameters enhance readability and visual storytelling.
   - Saves the animation as an `.mp4` file for high-quality sharing.

---

### Key Parameters

- **Top Vendors (`n_bars`)**: Displays the top 10 vendors based on cumulative CVE counts.
- **Dynamic Ordering (`fixed_order=False`)**: Updates the bar order dynamically to reflect changes in rankings.
- **Y-Axis Consistency (`fixed_max=True`)**: Maintains a consistent y-axis scale to enable meaningful visual comparisons.
- **Smooth Transitions (`steps_per_period=10`)**: Creates fluid animations between monthly time steps.
- **Frame Duration (`period_length=400`)**: Each time step lasts 400 milliseconds for optimal pacing.

---

### Customization

- **Visual Enhancements**:
   - Clear labels with larger fonts (`bar_label_size=12`) improve readability.
   - High resolution (`dpi=300`) ensures professional-quality visuals suitable for presentations and reports.
- **Colors**:
   - Brand colors make it easy to identify key vendors.
   - Fallback colors ensure distinction for all other vendors.

---

### Output

- **Video File**:
   - The animation is saved as `top_10_vendors_cve_trends_2002_2024.mp4`, ready for sharing and embedding.

- **Insights**:
   - Tracks the dynamic evolution of CVE counts by vendor.
   - Highlights key shifts and emerging trends in vulnerability disclosures across two decades, providing actionable insights into the cybersecurity landscape.


```python jupyter={"is_executing": true}
import os
import warnings

import matplotlib.pyplot as plt
import pandas as pd
from bar_chart_race import bar_chart_race
from matplotlib.colors import to_hex

# Suppress font warnings
warnings.filterwarnings("ignore", category=UserWarning)

# Set font for charts
plt.rcParams["font.family"] = "Arial"

# Load cumulative data
input_csv = "../../../data/cve_data_stories/vendor_cve_trends/processed/vendor_top_20.csv"
df = pd.read_csv(input_csv, encoding="utf-8")

# Normalize vendor names
vendor_normalization = {
    "adobe": "Adobe",
    "apache": "Apache",
    "apple": "Apple",
    "bsdi": "BSDi",
    "caldera": "Caldera",
    "canonical": "Canonical",
    "cisco": "Cisco",
    "data_general": "Data General",
    "debian": "Debian",
    "digital": "Digital Corp",
    "eric_allman": "E. Allman",
    "fedoraproject": "Fedora",
    "fred_n._van_kempen": "F. van Kempen",
    "freebsd": "FreeBSD",
    "gentoo": "Gentoo",
    "gnu": "GNU",
    "google": "Google",
    "gracenote": "Gracenote",
    "hp": "HP",
    "ibm": "IBM",
    "inet": "INET",
    "isc": "ISC",
    "jenkins": "Jenkins",
    "joomla": "Joomla",
    "kde": "KDE",
    "kth": "KTH",
    "linux": "Linux",
    "mandrakesoft": "Mandrakesoft",
    "microsoft": "Microsoft",
    "mit": "MIT",
    "mozilla": "Mozilla",
    "ncr": "NCR",
    "ncsa": "NCSA",
    "nec": "NEC",
    "netapp": "NetApp",
    "netbsd": "NetBSD",
    "netscape": "Netscape",
    "next": "NeXT",
    "nighthawk": "Nighthawk",
    "novell": "Novell",
    "openbsd": "OpenBSD",
    "opensuse": "OpenSUSE",
    "oracle": "Oracle",
    "paul_vixie": "P. Vixie",
    "php": "PHP",
    "process_software": "Process Soft.",
    "redhat": "Red Hat",
    "renaud_deraison": "R. Deraison",
    "rxvt": "Rxvt",
    "sap": "SAP",
    "sco": "SCO",
    "sendmail": "Sendmail",
    "sgi": "SGI",
    "slackware": "Slackware",
    "sun": "Sun Micro.",
    "suse": "SUSE",
    "symantec": "Symantec",
    "tcsh": "Tcsh",
    "transarc": "Transarc",
    "ubuntu": "Ubuntu",
    "university_of_washington": "U. of Wash.",
    "washington_university": "Wash. Univ",
}

df["Vendor"] = df["Vendor"].map(vendor_normalization).fillna(df["Vendor"])

# Ensure Year and Month are integers
df["Year"] = df["Year"].astype(int)
df["Month"] = df["Month"].astype(int)

# Pivot data for bar chart race
df_pivot = df.pivot(index=["Year", "Month"], columns="Vendor", values="Cumulative_Count").fillna(0)
df_pivot.index = pd.to_datetime(df_pivot.index.map(lambda x: f"{x[0]:04d}-{x[1]:02d}"), format="%Y-%m")
df_pivot = df_pivot.sort_index()

# Define known brand colors
brand_colors = {
    "Adobe": "#FF0000",
    "Apache": "#D22128",
    "Apple": "#A3AAAE",
    "BSDi": "#003366",
    "Caldera": "#CC0000",
    "Canonical": "#772953",
    "Cisco": "#1BA0D7",
    "Data General": "#4E6E9F",
    "Debian": "#A81D33",
    "Digital Corp": "#B2B2B2",
    "Fedora": "#294172",
    "FreeBSD": "#AB2B28",
    "Gentoo": "#54487A",
    "GNU": "#A42E2B",
    "Google": "#4285F4",
    "HP": "#0096D6",
    "IBM": "#054ADA",
    "ISC": "#6B2C91",
    "Jenkins": "#D33832",
    "Joomla": "#F44321",
    "KDE": "#1D99F3",
    "Linux": "#000000",
    "Microsoft": "#F25022",
    "MIT": "#A31F34",
    "Mozilla": "#C13832",
    "NCR": "#008000",
    "NEC": "#003366",
    "NetApp": "#0077C8",
    "NetBSD": "#E47911",
    "Netscape": "#34A853",
    "NeXT": "#FFC700",
    "Novell": "#D5192C",
    "OpenBSD": "#FFD700",
    "OpenSUSE": "#73BA25",
    "Oracle": "#F80000",
    "PHP": "#8892BF",
    "Red Hat": "#EE0000",
    "SAP": "#008FD3",
    "SGI": "#336699",
    "Slackware": "#4E4E4E",
    "Sun Micro.": "#EE7334",
    "SUSE": "#83BA2F",
    "Symantec": "#FDB511",
    "Ubuntu": "#E95420",
    "U. of Wash.": "#4B2E83",
    "Wash. Univ": "#4B2E83",
}

# Generate fallback colors using a colormap
palette = plt.colormaps.get_cmap('tab20')
fallback_colors = [to_hex(palette(i)) for i in range(palette.N)]

# Assign colors to vendors
colors = [
    brand_colors.get(vendor, fallback_colors[i % len(fallback_colors)])
    for i, vendor in enumerate(df_pivot.columns)
]

# Output file path
output_file = "../../../data/cve_data_stories/vendor_cve_trends/processed/top_10_vendors_cve_trends_1996_2024.mp4"
os.makedirs(os.path.dirname(output_file), exist_ok=True)

# Generate bar chart race
bar_chart_race(
    df=df_pivot,  # The pivoted DataFrame containing cumulative CVE counts by vendor over time.
    filename=output_file,  # Path to save the output video (e.g., .mp4). Set to None to display inline in a notebook.
    orientation="h",  # Display bars horizontally to show vendor trends over time.
    sort="desc",  # Sort vendors by descending CVE count for each time period.
    n_bars=10,  # Number of top CVE vendors to display at any given time.
    fixed_order=False,  # Allow the order of vendors to change dynamically as CVE counts update over time.
    fixed_max=True,  # Keep the maximum CVE count consistent across all time periods for better comparison.
    steps_per_period=10,  # Number of animation frames to transition between each month.
    period_length=400,  # Duration (in milliseconds) for each month in the animation.
    interpolate_period=True,  # Smoothly interpolate CVE counts between months for fluid animation.
    label_bars=True,  # Display the CVE count as a label on each bar.
    bar_size=0.85,  # Thickness of each bar as a fraction of the available space for the month.
    period_label={"size": 16, "x": 0.85, "y": 0.25},  # Customize the date label for each month (size and position).
    period_fmt="%Y-%m",  # Format of the date label displayed for each time period (e.g., "2023-01").
    title="Top Vendors by CVE",  # Title of the bar chart animation.
    title_size=20,  # Font size for the chart title.
    bar_label_size=12,  # Font size for the CVE count labels displayed on each bar.
    tick_label_size=10,  # Font size for axis tick labels (representing CVE counts).
    cmap=colors,  # Colors for each vendor's bar, using brand colors or fallback colors if unspecified.
    dpi=300,  # Resolution of the output video (higher DPI produces better quality but larger files).
    bar_kwargs={"alpha": 0.85},  # Set the transparency of the bars (alpha value).
)

print(f"Bar chart race saved to {output_file}.")
```
