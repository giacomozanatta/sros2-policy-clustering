# SROS2 Policy Clustering

A tool to cluster SROS2 XML permission policies into security enclaves based on permission similarity and communication flows. This helps group ROS2 nodes for enhanced security and operational efficiency.

---

## Features

- Parses SROS2 XML policy files and extracts permissions  
- Computes permission similarity using Jaccard distance  
- Supports hierarchical clustering with adjustable threshold  
- Generates clustered policy XML files for enclave deployment  
- Reports inter-enclave communication flows and node exposure  
- Configurable via simple command-line interface

---

## Installation
This project requires **Python 3.11.13**.
```bash
git clone https://github.com/giacomozanatta/sros2-policy-clustering.git
cd sros2-policy-clustering
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

Run the clustering tool with:  
```bash
python3 main.py --policy_dir ./policies --output_dir ./output --threshold 0.8
```
For example:
```bash
python3 main.py --policy_dir ./permissions/Catch2023_hitchens --output_dir ./output --threshold 0.8
```
- `--policy_dir` : Directory containing your SROS2 XML policy files (default: `./policies`)  
- `--output_dir` : Directory where the reports and clustered policies will be saved (default: `./output`)  
- `--threshold`  : Clustering distance threshold between 0 and 1 (default: `0.8`)

---

## Output

- **clustering_report.txt**: Summary of clusters, node assignments, inter-enclave flows, and exposure points  
- **clustered_policy.xml**: New policy XML grouping nodes into clusters/enclaves

---

## Development

To install dependencies:  
```bash
pip3 install -r requirements.txt
```
