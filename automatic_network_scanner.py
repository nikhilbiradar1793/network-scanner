import subprocess
import os
import uuid

print("=================================")
print("  Simple Automated Network Scanner")
print("=================================")

target = input("Enter target IP: ")

print("Scanning target:", target)

# Generate random name
report_name = f"scan_{uuid.uuid4().hex}.html"

# Run nmap and create XML report
subprocess.run(["nmap", "-oX", "scan_report.xml", target])

print("XML report created.")

# Convert XML to HTML
subprocess.run(["xsltproc", "scan_report.xml", "-o", report_name])

print("HTML report generated:", report_name)

# Delete XML file
os.remove("scan_report.xml")

print("Temporary XML file removed.")
print("Scan completed successfully.")
