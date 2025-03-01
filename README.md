# LogAnalyzer-access.log-
A script to analyze access.log entries to search for suspicious patterns.

# Overview

Log Analyzer is a Python-based tool designed to scan web server logs for potential security threats, such as brute force attacks, SQL injections, XSS attempts, and other suspicious activities. The tool processes log files, identifies threats using regex-based pattern matching, and generates a comprehensive HTML report with visual insights.

# Features

- [x] Detects various types of security threats in web server log
- [x] Supports detection of BASIC SQL Injection, XSS Attempts, Directory Traversal, Remote Code Execution, User-Agent Anomalies, Path enumeration and SUspicious HTTP methods.
- [x] Generates an interactive HTML report with a summary and visualized data
- [x] Provides an optional JSON output for automated analysisa

# Requirements

Ensure you have Python installed along with the required dependencies:

```bash
pip install matplotlib
```

# Installation
1.Clone the repository:
```bash
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer
```

2.Install required Dependancies:
```bash
pip install -r requirements.txt
```

# Usage

1.Run the script and provide the path to the log file (absoulte path):
```bash
python accessLogAnalyzer.py
```
2.Enter the full path to the log file when prompted.
3.Provide the desired name for the output report (without extension).
4.The script analyzes the log and generates a detailed HTML report with graphs.

# Example
```bash
Enter the full path to the log file: /path/to/access.log
Enter the name of the output report (without extension): report
```
# Outputs:

report.html: Contains the summary and visualization of detected threats.
threat_chart.png: Graph representation of the analysis.

# Output Example

The HTML report includes:

A table listing detected threats and their occurrences.

A bar chart visualizing different types of attacks found in the log file.

# License

This project is licensed under the MIT License  - see the LICENSE file for details.

# Contributing

Contributions are welcome! If you find a bug or want to improve the detection accuracy, feel free to submit a pull request or open an issue.

# Contact

For any inquiries or contributions, reach out via GitHub Issues.

# @Author
Developed by Pierluca De Santis.
For feedback or contributions, feel free to open an issue on GitHub.
