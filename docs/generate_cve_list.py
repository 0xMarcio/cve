#!/usr/bin/python3
import os
import json
import re

# Path to enumerate CVEs from
dir = "../"
CVE_list = []

# Fetch all the years
years = os.listdir(dir)
# Remove non-numeric years
years = [year for year in years if year.isdigit()]
# Sort descending (we want the latest at the top)
years.sort(reverse=True)

# Clean up the text blocks
def clean_text(description_text):
    description = re.sub(r'\n+', '\n', description_text)
    # Remove the '-' at the beginning of each line
    description_lines = description.split('\n')
    description_lines = [line.lstrip('- ') for line in description_lines]
    # Add <br/> for each line
    description = '\n'.join(description_lines)
    return description

# Generate JSON for each CVE
for year in years:
    yearDir = os.path.join(dir, year)
    for CVE_filename in os.listdir(yearDir):
        # Open CVE file
        with open(os.path.join(yearDir, CVE_filename), 'r') as CVE_file:
            # Read CVE file
            CVE_file_content = CVE_file.read()

            # Extract CVE description, references, and GitHub links
            CVE_description = CVE_file_content.split('### Description')[1].split('###')[0].strip()
            CVE_references = CVE_file_content.split('### Reference')[1].split('###')[0].strip()
            CVE_github = CVE_file_content.split('### Github')[1].split('###')[0].strip()

            CVE_Name = CVE_filename.split('.')[0]

            CVE_description = clean_text(CVE_description)
            CVE_github = clean_text(CVE_github)
            CVE_references = clean_text(CVE_references)

            CVE_poc = [ref for ref in CVE_references.split('\n') if "No PoCs" not in ref]
            CVE_poc += [poc for poc in CVE_github.split('\n') if "No PoCs" not in poc]

            thisCVE = {"cve": CVE_Name, "desc": CVE_description, "poc": CVE_poc}
            CVE_list.append(thisCVE)

# Convert CVE list to JSON without indentation
CVE_output = json.dumps(CVE_list)

# Save CVE list to JSON file
with open('CVE_list.json', 'w') as outfile:
    outfile.write(CVE_output)

print("CVE list saved to CVE_list.json")
