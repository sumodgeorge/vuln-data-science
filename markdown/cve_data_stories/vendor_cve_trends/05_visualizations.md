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



## Bar Chart Race: Top 10 Vendors by CVE Count (2002–2024)

This script generates a dynamic bar chart race showcasing the top 10 vendors by CVE count over time (2002–2024). The visualization highlights trends and shifts in vulnerability disclosures across two decades in an engaging video format.

---

### Steps in the Script

1. **Import Necessary Libraries**:
   - `pandas`: For efficient data manipulation and preprocessing.
   - `bar_chart_race`: To create the bar chart race animation.
   - `matplotlib`: For additional customizations like font handling and color palettes.

2. **Load and Preprocess Data**:
   - Reads a CSV file (`vendor_top_20.csv`) containing cumulative CVE counts for each vendor by year and month.
   - Normalizes vendor names to ensure consistency.
   - Ensures all vendors that have ever been in the top 20 are included.

3. **Pivot and Format Data**:
   - Transforms the dataset into a suitable format for visualization:
     - **Rows**: Represent time (`Year`, `Month`).
     - **Columns**: Represent vendors.
     - **Values**: Represent cumulative CVE counts.
   - Combines `Year` and `Month` into a single `Date` column (`YYYY-MM`) to create a continuous time index.

4. **Assign Colors**:
   - **Brand Colors**: Known vendors are mapped to their official brand colors for easy recognition.
   - **Fallback Colors**: Vendors without defined colors are assigned visually distinct fallback colors from a predefined color palette (`tab20`).

5. **Generate the Bar Chart Race**:
   - Animates the top 10 vendors dynamically over time:
     - Bars update their values and order based on cumulative CVE counts.
     - Customizable parameters enhance readability and aesthetics.
   - Saves the animation as an `.mp4` file for high-quality sharing.

---

### Key Parameters

- **Number of Bars (`n_bars`)**: Displays the top 10 vendors at any given time.
- **Dynamic Ordering (`fixed_order=False`)**: Updates the bar order dynamically based on cumulative counts.
- **Y-Axis Consistency (`fixed_max=True`)**: Maintains a consistent y-axis scale across frames for clarity.
- **Smooth Transitions (`steps_per_period=20`)**: Ensures fluid animations between time steps.
- **Frame Duration (`period_length=600`)**: Each frame lasts 600 milliseconds.

---

### Customization

- **Font Compatibility**:
   - Special characters in vendor names are handled gracefully for a professional appearance.
- **Visual Enhancements**:
   - Larger bar labels (`bar_label_size=12`) improve readability.
   - High resolution (`dpi=300`) ensures visuals are suitable for presentations, reports, and social media sharing.
- **Brand Colors**:
   - Incorporates official colors for known vendors and visually distinct fallback colors for others.

---

### Output

- **Video File**:
   - The bar chart race is saved as `top_10_vendors_cve_trends_2002_2024.mp4`.

- **Insights**:
   - Highlights the dynamic evolution of CVE counts by vendor.
   - Visualizes trends in vulnerability disclosures over two decades, showcasing shifts in the security landscape.




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
    "digital": "Digital Equipment Corporation",
    "eric_allman": "Eric Allman",
    "fedoraproject": "Fedora Project",
    "fred_n._van_kempen": "Fred N. van Kempen",
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
    "paul_vixie": "Paul Vixie",
    "php": "PHP",
    "process_software": "Process Software",
    "redhat": "Red Hat",
    "renaud_deraison": "Renaud Deraison",
    "rxvt": "Rxvt",
    "sap": "SAP",
    "sco": "SCO",
    "sendmail": "Sendmail",
    "sgi": "SGI",
    "slackware": "Slackware",
    "sun": "Sun Microsystems",
    "suse": "SUSE",
    "symantec": "Symantec",
    "tcsh": "Tcsh",
    "transarc": "Transarc",
    "ubuntu": "Ubuntu",
    "university_of_washington": "University of Washington",
    "washington_university": "Washington University"
}

df["Vendor"] = df["Vendor"].map(vendor_normalization).fillna(df["Vendor"])

# Ensure Year and Month are integers
df["Year"] = df["Year"].astype(int)
df["Month"] = df["Month"].astype(int)

# Pivot data for bar chart race
df_pivot = df.pivot(index=["Year", "Month"], columns="Vendor", values="Cumulative_Count").fillna(0)
df_pivot.index = pd.to_datetime(df_pivot.index.map(lambda x: f"{x[0]:04d}-{x[1]:02d}"), format="%Y-%m")

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
    "Digital Equipment Corporation": "#B2B2B2",
    "Fedora Project": "#294172",
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
    "Linux": "#000000",  # Linux penguin black
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
    "Sun Microsystems": "#EE7334",
    "SUSE": "#83BA2F",
    "Symantec": "#FDB511",
    "Ubuntu": "#E95420",
    "University of Washington": "#4B2E83"
}

# Generate fallback colors using a colormap
palette = plt.colormaps.get_cmap('tab20')  # Updated to avoid deprecation warning
fallback_colors = [to_hex(palette(i)) for i in range(palette.N)]

# Assign colors to vendors
colors = []
used_colors = set()

for vendor in df_pivot.columns:
    if vendor in brand_colors:
        color = brand_colors[vendor]
    else:
        color = fallback_colors[len(used_colors) % len(fallback_colors)]
    colors.append(color)
    used_colors.add(color)

# Output file path
output_file = "../../../data/cve_data_stories/vendor_cve_trends/processed/top_10_vendors_cve_trends_1996_2024.mp4"
os.makedirs(os.path.dirname(output_file), exist_ok=True)

# Generate bar chart race
bar_chart_race(
    df=df_pivot,  # The pivoted DataFrame containing cumulative CVE counts over time
    filename=output_file,  # Path to save the output file (e.g., .mp4 or .gif)
    orientation="h",  # Horizontal bar chart orientation
    sort="desc",  # Sort bars in descending order by value
    n_bars=10,  # Display the top 10 vendors at any given time
    fixed_order=False,  # Dynamically adjust the order of bars based on value
    fixed_max=True,  # Keep the maximum value on the y-axis consistent across all frames
    steps_per_period=20,  # Number of steps (frames) per period for smoother transitions
    period_length=600,  # Duration of each period in milliseconds (controls animation speed)
    interpolate_period=True,  # Smoothly interpolate values between periods
    label_bars=True,  # Display values as labels inside the bars
    bar_size=0.85,  # Adjust bar thickness (0.85 means bars take up 85% of the space)
    period_label={"size": 16, "x": 0.85, "y": 0.25},  # Customize period label size and position
    period_fmt="%Y-%m",  # Format period as "Year-Month"
    title="Top Vendors by CVE",  # Title of the chart
    title_size=20,  # Font size for the title
    bar_label_size=12,  # Font size for labels on the bars
    tick_label_size=10,  # Font size for tick labels (on the x-axis)
    cmap=colors,  # List of colors for the bars (brand colors + fallback colors)
    dpi=300,  # Dots per inch for the output file (controls resolution)
    bar_kwargs={"alpha": 0.85},  # Additional customization for bars (e.g., transparency)
)

print(f"Bar chart race saved to {output_file}.")
```
