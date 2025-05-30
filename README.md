# vuln-data-science

![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)

Welcome to the vuln-data-science repository! This project focuses on applying data science techniques to vulnerability
management and analysis. Our goal is to explore, analyze, and share insights on vulnerabilities using data science
methodologies.

## Table of Contents

- [Introduction](#introduction)
- [Motivation](#motivation)
- [Features](#features)
- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Notebooks and Markdown](#notebooks-and-markdown)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Future Work](#future-work)
- [Acknowledgments](#acknowledgments)

## Introduction

In the modern cybersecurity landscape, vulnerability management is crucial. By leveraging data science, we can gain
deeper insights into vulnerabilities, predict trends, and enhance our overall security posture. This repository contains
data, Jupyter notebooks, and analysis scripts aimed at advancing our understanding of vulnerabilities across various
domains, including software and network vulnerabilities. We utilize data from trusted sources such as:

- [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide)
- [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/)

## Motivation

Effective vulnerability management is essential for maintaining a strong security posture. This project demonstrates how
data science can be used to identify patterns, predict vulnerabilities, and provide actionable insights to security
professionals.

## Features

- **Data Collection**: Automated scripts for collecting vulnerability data from various sources.
- **Data Cleaning**: Techniques to preprocess and clean the data for analysis.
- **Exploratory Data Analysis**: Visualizations and insights into vulnerability trends.
- **Predictive Analysis**: Models to predict future vulnerabilities and their potential impact.
- **Tools & Libraries**: Utilization of tools like Pandas, Matplotlib, Seaborn, and Scikit-learn for data processing and
  analysis.

## Getting Started

### Prerequisites

Before you begin, ensure you have the following software installed:

- Python 3.11 or higher

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/typeerror/vuln-data-science.git
   ```

2. Navigate to the project directory:

   ```bash
   cd vuln-data-science
   ```

3. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

4. Activate the virtual environment:

    - On Windows:
      ```bash
      venv\Scripts\activate
      ```
    - On macOS and Linux:
      ```bash
      source .venv/bin/activate
      ```

5. Install the required dependencies:

   ```bash
   pip install .
   ```

   Alternatively, if you use Hatch, you can set up the environment with:

   ```bash
   hatch env create
   hatch shell
   ```

## Usage

To start exploring the data and running the analyses, open the Jupyter notebooks in the `notebooks` directory. Each
notebook focuses on a different aspect of the data pipeline.

You can launch Jupyter Notebook with the following command:

```bash
jupyter notebook
```

Navigate to the `notebooks` directory and open any notebook to get started.

## Project Structure

```
vuln-data-science/
├── data/
├── notebooks/
├── scripts/
│   ├── nb_to_md.py
├── README.md
└── LICENSE
```

## Contributing

We welcome contributions! If you have ideas or find issues, please open a GitHub issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or suggestions, reach out via GitHub issues, email
at [projects@typeerror.com](mailto:projects@typeerror.com), or connect with Caleb
on [LinkedIn](https://linkedin.com/in/calebk).

## Future Work

We plan to expand the project with the following features:

- **Additional Data Sources**: Integration with more vulnerability databases and threat intelligence feeds.
- **Advanced Analytics**: Machine learning models for predicting vulnerability exploitation likelihood.
- **Visualization Dashboards**: Interactive dashboards for visualizing trends and insights.

### Data Usage and Attribution

This project uses data from various publicly available sources. Please ensure compliance with their respective usage
agreements and attribution requirements if you use or redistribute the data.

#### **NIST National Vulnerability Database (NVD)**

- Website: [NVD Developers - Terms of Use](https://nvd.nist.gov/developers/terms-of-use)
- **Attribution Requirement**:
    - Services utilizing the NVD API must display the following notice prominently:
      > "This product uses the NVD API but is not endorsed or certified by the NVD."
    - The NVD name may only be used to identify the source of API content and may not imply endorsement of any product
      or service.

#### **CISA Known Exploited Vulnerabilities (KEV)**

- Website: [CISA KEV License](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)
- **License**:
    - The KEV database is distributed under the **Creative Commons 0 1.0 License**.
    - You may use this data in any legal manner, but note:
        - Information provided at any 3rd-party links included in the KEV database is bound by the policies and licenses
          of those third-party websites.
        - Use of the information does not authorize you to use the **CISA Logo** or **DHS Seal**, nor should such use be
          interpreted as an endorsement by CISA or DHS.

#### **Exploit Prediction Scoring System (EPSS)**

- Website: [EPSS - FIRST.org](https://www.first.org/epss)
- **Usage Agreement**:
    - EPSS scores are freely available for public use.
    - **Attribution Requirement**:
      > "See EPSS at https://www.first.org/epss"  
      > or  
      > "Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, Idris Adjerid, (2021), Exploit Prediction
      Scoring System, Digital Threats Research and Practice, 2(3)."

---

### Acknowledgments

We would like to acknowledge the work of researchers and contributors who are advancing the field of vulnerability data
science. Their insights and tools have been instrumental in shaping this project. This project also draws inspiration
from the broader cybersecurity and data science communities, whose collective efforts improve security practices and
promote knowledge sharing.

- **[Jay Jacobs](https://www.linkedin.com/in/jayjacobs1/)**  
  Co-founder of the Cyentia Institute, focusing on security metrics and data-driven decision-making in vulnerability
  management and risk assessment.

- **[Jerry Gamblin](https://www.linkedin.com/in/jgamblin/)** / [GitHub](https://github.com/jgamblin)  
  Security researcher and advocate, contributing to vulnerability analysis, remediation strategies, and the development
  of security tools.

- **[Patrick Garrity](https://www.linkedin.com/in/patrickmgarrity/)**  
  Acclaimed security researcher with deep expertise in vulnerabilities, exploitation, and threat actor analysis, focused
  on transforming complex vulnerability data into clear, actionable visualizations.

- **[Wade Baker](https://www.linkedin.com/in/drwadebaker/)**  
  Co-founder of the Cyentia Institute and co-creator of the Verizon Data Breach Investigations Report (DBIR),
  specializing in security data analytics and risk management.

We also want to thank the broader cybersecurity and data science communities for their contributions. This project draws
inspiration from collective efforts to improve security practices and promote knowledge sharing.

