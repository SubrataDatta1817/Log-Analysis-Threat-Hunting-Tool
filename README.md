#  Log Analysis & Threat Hunting Tool

### Cybersecurity SOC Project | SURE ProEd Internship

---

##  Student Details

* **Name:** Subrata Datta
* **Email:** [subratadatta3584@gmail.com](mailto:subratadatta3584@gmail.com)
* **College:** University of Mumbai
* **Course:** B.Sc IT
* **Duration:** 6 Months

---

##  Project Introduction

This project is a cybersecurity-based SOC (Security Operations Center) tool designed to automate log analysis and detect suspicious activities.

It parses system logs from multiple sources, processes them using Python, and identifies threats such as brute-force attacks and abnormal login patterns.

---

##  Technologies Used

* Python
* Regex
* Pandas
* Streamlit
* Altair / PyDeck

---

##  Project Architecture

```
Logs → Parser → Data Processing → Detection Engine → Alerts → Dashboard
```

---

##  System Architecture

<p align="center">
  <img src="./images/architecture_diagram.png" width="800"/>
</p>

---

##  Key Features

* Multi-source log parsing (SSH, Auth, Web, Router)
* Automated threat detection
* Brute-force attack detection
* Suspicious login detection
* Interactive dashboard
* Alert generation system

---

##  Dashboard Overview

<p align="center">
  <img src="./images/dashboard_overview.png" width="850"/>
</p>

---

##  Alerts & Detection

<p align="center">
  <img src="./images/alerts_panel.png" width="850"/>
</p>

---

##  Analytics & Insights

<p align="center">
  <img src="./images/analytics_view.png" width="850"/>
</p>

---

## ⚡ How It Works

### 1 Parsing Layer

* Extracts IP address, timestamp, and event type using Regex

### 2 Data Processing

* Converts logs into structured Pandas DataFrame

### 3 Detection Engine

Detects:

* Brute force attacks
* Suspicious login time
* Invalid user attempts

### 4 Dashboard

Displays:

* Top attacking IPs
* Login trends
* Alerts

---

##  Sample Output

* **Total Events:** 39
* **Failed Logins:** 17
* **Top Attacker:** 198.51.100.20

---

##  Learnings

* Log analysis techniques
* SOC workflow understanding
* Python (Regex + Pandas)
* Dashboard creation using Streamlit
* Threat detection logic

---

##  Community Services

As part of SURE ProEd internship:

*  Planted two long-life trees
*  Participated in blood donation
*  Assisted senior citizens

---

##  Future Scope

* Machine Learning-based detection
* Real-time log streaming
* SIEM integration (Splunk / ELK)
* GeoIP tracking

---

##  Project Structure

```
log_hunting_tool/
├── images/
│   ├── dashboard_overview.png
│   ├── alerts_panel.png
│   ├── analytics_view.png
│   └── architecture_diagram.png
├── sample_logs/
├── src/
├── tests/
├── requirements.txt
└── README.md
```

---

##  How to Run

### 🔹 Install Dependencies

```
pip install -r requirements.txt
```

### 🔹 Run CLI

```
python src/run_analysis.py
```

### 🔹 Run Dashboard

```
streamlit run src/dashboard.py
```

---

##  Acknowledgment

Thanks to **SURE ProEd** for providing this opportunity to work on a real-world cybersecurity project.
