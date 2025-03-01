import re
import os
import json
from collections import defaultdict
import matplotlib.pyplot as plt

# Define patterns for detecting various threats in logs
PATTERNS = {
    "Server Errors (500)": r'"\S+\s+\S+\s+HTTP/\d\.\d"\s+500\s+',
    "SQL Injection Attempts": r"(SELECT .* FROM|DROP TABLE|INSERT INTO|UNION SELECT|--|OR 1=1)",
    "XSS Attempts": r"(<script>|onerror=|javascript:|document\.cookie)",
    "Directory Traversal": r"(/\.\./|\\\.\.\\)",
    "Remote Code Execution": r"(eval\(|exec\(|system\(|shell_exec\(|popen\(|passthru\()",
    "User-Agent Anomalies": r"\b(curl|wget|python|nmap|sqlmap)\b",
    "Path Enumeration": r"(/etc/passwd|/etc/shadow|/var/www|C:\\Windows\\System32)",
    "Suspicious HTTP Methods": r"(TRACE|TRACK|CONNECT)",
}

# Function to analyze log files
def analyze_log(file_path, output_filename):
    """
    Analyze a log file for suspicious activities and generate an HTML report with charts.
    :param file_path: Path to the log file to analyze
    :param output_filename: Name of the output HTML report
    """
    if not os.path.isfile(file_path):
        print(f"[ERROR] Log file not found: {file_path}\nMake sure the file exists.")
        return
    
    detected_threats = defaultdict(int)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as log_file:
            for line in log_file:
                matched_threats = set()
                for threat, pattern in PATTERNS.items():
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            matched_threats.add(threat)  # Ensure no double count per log entry
                    except re.error as regex_error:
                        print(f"Regex error in pattern {threat}: {regex_error}")
                for threat in matched_threats:
                    detected_threats[threat] += 1
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return
    
    # Generate HTML Report
    generate_html_report(detected_threats, output_filename + ".html")


def generate_html_report(detected_threats, output_path):
    """
    Generate an HTML report with the analysis results, including graphs.
    :param detected_threats: Dictionary containing detected threats and their occurrences
    :param output_path: Path to save the HTML report
    """
    # Generate data for plotting
    categories = [key for key in detected_threats.keys() if detected_threats[key] > 0]
    counts = [detected_threats[key] for key in categories]
    
    # Generate a bar chart
    plt.figure(figsize=(10, 5))
    plt.barh(categories, counts, color='skyblue')
    plt.xlabel("Occurrences")
    plt.ylabel("Threat Category")
    plt.title("Threat Analysis from Log File")
    plt.savefig("threat_chart.png")
    plt.close()
    
    # Create HTML content
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Log Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            table { width: 100%%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Log Analysis Report</h1>
        <img src="threat_chart.png" alt="Threat Analysis Chart" width="600px">
        <h2>Detailed Threats Found</h2>
        <table>
            <tr>
                <th>Threat Category</th>
                <th>Occurrences</th>
            </tr>
    """
    
    for threat, count in detected_threats.items():
        if count > 0:
            html_content += f"<tr><td>{threat}</td><td>{count}</td></tr>"
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write(html_content)
    
    print(f"Report generated: {output_path}")

if __name__ == "__main__":
    file_path = input("Enter the full path to the log file: ").strip()
    output_filename = input("Enter the name of the output report (without extension): ").strip()
    
    analyze_log(file_path, output_filename)
