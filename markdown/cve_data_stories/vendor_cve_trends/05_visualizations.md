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


```python
import warnings

import matplotlib.pyplot as plt
import pandas as pd
from bar_chart_race import bar_chart_race
from matplotlib.colors import to_hex
```




## Bar Chart Race: Top CVE Vendors (1999–2024)

This script generates dynamic bar chart race visualizations that showcase the top vendors by cumulative CVE count over time, covering the years 1999–2024. The project provides insights into long-term trends in vendor-specific vulnerabilities, highlighting shifts in the cybersecurity landscape over two decades.

---

### Purpose

- **Analyze Vulnerability Trends**: Understand which vendors have consistently had the most reported vulnerabilities and how rankings have evolved over time.
- **Engage Through Visualization**: Present data in a visually compelling way that draws attention to key trends in cybersecurity.
- **Inspire Data-Driven Discussions**: Encourage conversations about how this data can inform risk management strategies.

---

### Workflow

1. **Setup and Data Loading**:
   - Imports libraries for data manipulation (`pandas`), visualization (`bar_chart_race`, `matplotlib`), and system utilities (`os`, `warnings`).
   - Suppresses irrelevant warnings to streamline outputs.
   - Reads a preprocessed CSV file (`vendor_top_20.csv`) containing cumulative CVE counts by vendor, year, and month.

2. **Vendor Name Normalization**:
   - Ensures vendor names are clean and consistent using a mapping dictionary.
   - Handles variations in vendor naming for accurate aggregation.

3. **Data Transformation**:
   - Converts the `Year` and `Month` columns into a `datetime` format for proper sorting and animation.
   - Pivots the dataset to create a table where:
     - **Rows**: Time intervals (monthly or yearly).
     - **Columns**: Vendors.
     - **Values**: Cumulative CVE counts.
   - Prepares both monthly and yearly datasets for separate animations.

4. **Color Assignment**:
   - Assigns official brand colors to vendors where available for consistent identification.
   - Generates fallback colors for vendors without official brand palettes, ensuring a visually distinct output.

5. **Bar Chart Race Generation**:
   - Creates animations for:
     - **Monthly Data**: Top 10 vendors shown dynamically across monthly time steps, saved as an `.mp4` file.
     - **Yearly Data**: Top 5 vendors aggregated by year, optimized as a `.gif` file for LinkedIn sharing.
   - Configures parameters for animation smoothness, readability, and file size optimization.

---

### Parameters for Customization

- **Top Vendors (`n_bars`)**:
   - Displays the top 10 vendors for monthly visualizations and top 5 for yearly GIFs.
- **Dynamic Rankings (`fixed_order=False`)**:
   - Bar positions adjust dynamically based on rankings in each time interval.
- **Y-Axis Consistency (`fixed_max=True`)**:
   - Maintains a fixed scale across time intervals for meaningful comparisons.
- **Transition Smoothness (`steps_per_period`)**:
   - Controls animation fluidity, with fewer steps used for smaller file sizes.
- **Animation Speed (`period_length`)**:
   - Adjusted for LinkedIn-friendly GIFs with faster transitions.

---

### Outputs

1. **Monthly Animation (`.mp4`)**:
   - High-quality video highlighting the top 10 vendors month by month.
   - Saved as `top_10_vendors_cve_trends_1999_2024.mp4`.

2. **Yearly Animation (`.gif`)**:
   - Lightweight GIF optimized for LinkedIn, showing top 5 vendors per year.
   - Saved as `top_5_vendors_cve_trends_1999_2024.gif`.


```python
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
```

### Generate Monthly MP4 Bar Chart Race
In this step, we generate a bar chart race video in MP4 format that visualizes cumulative CVE counts by vendor over time, aggregated monthly.

- The output video will display the **top 10 vendors** ranked by their cumulative CVE counts for each month from 1999 to 2024.
- The `period_length` and `steps_per_period` control the animation speed and smoothness.
- The resolution (`dpi=300`) ensures high-quality output.

The resulting MP4 file will be saved to the specified path.


```python jupyter={"is_executing": true}
# Output file path
output_file = "../../../data/cve_data_stories/vendor_cve_trends/processed/top_10_vendors_cve_trends_1999_2024.mp4"

# Generate bar chart race
bar_chart_race(
    df=df_pivot,  # Pivoted DataFrame with cumulative CVE counts by vendor over time
    filename=output_file,  # Path to save the output video (e.g., .mp4). Set to None to display inline
    orientation="h",  # Display bars horizontally to show vendor trends over time
    sort="desc",  # Sort vendors by descending CVE count for each time period
    n_bars=10,  # Display the top 10 vendors at any given time
    fixed_order=False,  # Allow dynamic changes in the order of vendors as CVE counts update
    fixed_max=True,  # Keep the maximum y-axis value consistent across all time periods
    steps_per_period=10,  # Number of animation frames to transition between each month
    period_length=400,  # Duration (in milliseconds) of each month in the animation
    interpolate_period=True,  # Smoothly interpolate CVE counts between months for fluid animation
    label_bars=True,  # Display the CVE count as a label on each bar
    bar_size=0.85,  # Thickness of each bar as a fraction of the available space
    period_label={"size": 16, "x": 0.85, "y": 0.25},  # Customize date label size and position for each month
    period_fmt="%Y-%m",  # Format of the date label displayed for each time period (e.g., "2023-01")
    title="Top Vendors by CVE",  # Title of the bar chart animation
    title_size=20,  # Font size for the chart title
    bar_label_size=12,  # Font size for the CVE count labels displayed on each bar
    tick_label_size=10,  # Font size for axis tick labels (representing CVE counts)
    cmap=colors,  # Colors for each vendor's bar, using brand or fallback colors
    dpi=300,  # Resolution of the output video (higher DPI produces better quality)
    bar_kwargs={"alpha": 0.85},  # Set the transparency of the bars (alpha value)
)

print(f"Bar chart race mp4 saved to {output_file}.")
```

### Prepare Data for Yearly GIF
To simplify the visualization for LinkedIn, the CVE data is aggregated by year instead of monthly intervals. This reduces the size and complexity of the bar chart race while maintaining key trends.

#### Steps:
1. **Convert Index to Datetime**:
   - The date index is converted to a datetime format for proper resampling.

2. **Resample by Year-End**:
   - Using the `resample('YE').last()` method, we extract the **last value of each year**. This ensures that the cumulative data accurately reflects the total CVE count for each vendor by the end of the year.

3. **Format the Index**:
   - The index is updated to show only the year as a string for clarity in the visualization.

4. **Handle Missing Data**:
   - Any missing values (`NaN`) are filled with `0` to prevent gaps in the animation.

5. **Avoid Rendering Issues**:
   - A small value (`1e-5`) is added to the data to avoid potential rendering artifacts during animation.

6. **Ensure Complete Year Range**:
   - The data is reindexed to include all years in the range, filling any missing years with `0`.

```python
# Convert index to datetime and resample
df_pivot.index = pd.to_datetime(df_pivot.index)
df_yearly = df_pivot.resample('YE').last()  # Use last value of each year for cumulative data

# Update index to show only the year
df_yearly.index = df_yearly.index.year.astype(str)  # Convert years to strings for proper formatting

# Fill NaN values
df_yearly = df_yearly.fillna(0)

# Add a small value to avoid rendering issues
df_yearly += 1e-5

# Ensure all years are present
all_years = [str(year) for year in range(int(df_yearly.index[0]), int(df_yearly.index[-1]) + 1)]
df_yearly = df_yearly.reindex(all_years, fill_value=0)
```

### Generate Yearly GIF Bar Chart Race
Using the aggregated yearly data, we create a **GIF optimized for LinkedIn**.

- The GIF shows the **top 5 vendors** ranked by cumulative CVE counts for each year from 1999 to 2024.
- To ensure the file size is within LinkedIn's 8MB limit:
  - Resolution is reduced (`dpi=150`).
  - Animation transitions are faster (`period_length=200` milliseconds).
  - Fewer steps per period (`steps_per_period=5`) reduce frame count.

The resulting GIF will be saved to the specified path.


```python
# Output file path
output_file = "../../../data/cve_data_stories/vendor_cve_trends/processed/top_5_vendors_cve_trends_1999_2024.gif"

# Generate bar chart race
bar_chart_race(
    df=df_yearly,  # Aggregated DataFrame with yearly cumulative CVE counts by vendor
    filename=output_file,  # Path to save the output GIF (optimized for LinkedIn)
    orientation="h",  # Display bars horizontally to show vendor trends over time
    sort="desc",  # Sort vendors by descending CVE count for each year
    n_bars=5,  # Display the top 5 vendors at any given time
    fixed_order=False,  # Allow dynamic changes in the order of vendors as CVE counts update
    fixed_max=True,  # Keep the maximum y-axis value consistent across all time periods
    steps_per_period=5,  # Number of animation frames to transition between each year
    period_length=200,  # Duration (in milliseconds) of each year in the animation
    interpolate_period=False,  # Disable interpolation to avoid rendering artifacts
    label_bars=True,  # Display the CVE count as a label on each bar
    bar_size=0.85,  # Thickness of each bar as a fraction of the available space
    period_label={"size": 16, "x": 0.85, "y": 0.25},  # Customize date label size and position for each year
    period_fmt="{x}",  # Display the year as it appears in the DataFrame index
    title="Top Vendors by CVE (Yearly)",  # Title of the bar chart animation
    title_size=18,  # Font size for the chart title
    bar_label_size=10,  # Font size for the CVE count labels displayed on each bar
    tick_label_size=8,  # Font size for axis tick labels (representing CVE counts)
    cmap=colors,  # Colors for each vendor's bar, using brand or fallback colors
    dpi=150,  # Resolution of the output GIF (optimized for smaller file size)
    bar_kwargs={"alpha": 0.85},  # Set the transparency of the bars (alpha value)
)

print(f"Bar chart race gif saved to {output_file}.")
```
