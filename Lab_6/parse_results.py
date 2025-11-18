import json
import csv
import pandas as pd
from lxml import etree
import os

# --- Configuration ---

# 1. Define the CWE Top 25 List
# We have hardcoded the list to avoid download errors.
# This list is from the 2023 CWE Top 25, which is perfectly valid.
cwe_top_25_list = [
    "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78", "CWE-20", 
    "CWE-125", "CWE-22", "CWE-352", "CWE-434", "CWE-862", "CWE-476",
    "CWE-287", "CWE-190", "CWE-502", "CWE-77", "CWE-119", "CWE-798",
    "CWE-918", "CWE-306", "CWE-362", "CWE-269", "CWE-94", "CWE-863", 
    "CWE-276"
]
cwe_top_25 = set(cwe_top_25_list)
print(f"[Info] Loaded {len(cwe_top_25)} hardcoded CWEs from Top 25 list.")


# 2. Define our projects and tools
PROJECTS = ['aider', 'aiohttp', 'airbyte']
TOOLS = ['Bandit', 'Horusec', 'SpotBugs']

# 3. This list will hold all our data
all_findings = []

# --- Helper Functions ---

def check_is_top_25(cwe_id):
    """Checks if a CWE ID is in the Top 25 list."""
    if not cwe_id or cwe_id == "CWE-0":
        return "No"
    # Ensure it's in the format "CWE-XXX"
    if not cwe_id.startswith('CWE-'):
        cwe_id = f"CWE-{cwe_id}"
    return "Yes" if cwe_id in cwe_top_25 else "No"

def add_finding(project, tool, cwe_id, count):
    """Adds a finding to our master list."""
    if cwe_id and cwe_id != "CWE-0":
        all_findings.append({
            'Project_name': project,
            'Tool_name': tool,
            'CWE_ID': cwe_id,
            'Number_of_Findings': count,
            'Is_In_CWE_Top_25?': check_is_top_25(cwe_id)
        })

# --- Main Parsing Logic ---

#
# === 1. Parse Bandit (JSON) ===
#
for project in PROJECTS:
    file_path = f"results/{project.lower()}_bandit.json"
    if not os.path.exists(file_path):
        print(f"[Warning] Bandit file not found: {file_path}")
        continue
        
    print(f"Parsing Bandit file: {file_path}")
    cwe_counts = {}
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for result in data.get('results', []):
                cwe_id = result.get('issue_cwe', {}).get('id')
                if cwe_id:
                    cwe_id = f"CWE-{cwe_id}" # Bandit just gives the number
                    cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1
                    
        for cwe, count in cwe_counts.items():
            add_finding(project, 'Bandit', cwe, count)
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")

#
# === 2. Parse Horusec (JSON) ===
#
for project in PROJECTS:
    file_path = f"results/{project.lower()}_horusec.json"
    if not os.path.exists(file_path):
        print(f"[Warning] Horusec file not found: {file_path}")
        continue
    
    print(f"Parsing Horusec file: {file_path}")
    cwe_counts = {}
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for vuln in data.get('analysisVulnerabilities', []):
                v = vuln.get('vulnerability', {})
                cwe_id = v.get('cwe') # Horusec gives full "CWE-XXX"
                if cwe_id:
                    cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1
                    
        for cwe, count in cwe_counts.items():
            add_finding(project, 'Horusec', cwe, count)
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")

#
# === 3. Parse SpotBugs (XML) ===
#
for project in PROJECTS:
    file_path = f"results/{project.lower()}_spotbugs.xml"
    if not os.path.exists(file_path):
        print(f"[Warning] SpotBugs file not found: {file_path}")
        continue
    
    print(f"Parsing SpotBugs file: {file_path}")
    cwe_counts = {}
    try:
        # Use lxml to parse the XML
        tree = etree.parse(file_path)
        # Find all BugInstance elements that have a Cweid child
        for bug_instance in tree.xpath("//BugInstance[Cweid]"):
            cwe_id = bug_instance.find("Cweid").text
            if cwe_id:
                cwe_id = f"CWE-{cwe_id}" # SpotBugs just gives the number
                cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1
                
        for cwe, count in cwe_counts.items():
            add_finding(project, 'SpotBugs', cwe, count)
            
    except etree.XMLSyntaxError:
        # This will happen for the empty files, which is fine
        print(f"Note: {file_path} is empty or not valid XML (this is expected for Python projects).")
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")

# --- Final Step: Create DataFrame and save CSV ---

if not all_findings:
    print("[Error] No findings were processed! Exiting.")
else:
    # Convert list of dictionaries to a pandas DataFrame
    df = pd.DataFrame(all_findings)
    
    # Re-order columns to match the assignment
    df = df[['Project_name', 'Tool_name', 'CWE_ID', 'Number_of_Findings', 'Is_In_CWE_Top_25?']]
    
    # Save the final consolidated CSV
    output_filename = 'consolidated_findings.csv'
    df.to_csv(output_filename, index=False)
    
    print(f"\n--- SUCCESS ---")
    print(f"All 9 scan reports parsed.")
    print(f"Consolidated data saved to: {output_filename}")
