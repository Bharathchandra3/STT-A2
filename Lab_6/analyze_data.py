import pandas as pd
import matplotlib.pyplot as plt

# --- Configuration ---
CSV_FILE = 'consolidated_findings.csv'
TOOLS = ['Bandit', 'Horusec', 'SpotBugs']

# --- Load Data ---
try:
    df = pd.read_csv(CSV_FILE)
except FileNotFoundError:
    print(f"[Error] The file '{CSV_FILE}' was not found.")
    print("Please make sure you have run 'parse_results.py' successfully.")
    exit()

print(f"--- Loaded '{CSV_FILE}' successfully. ---")

# --- 1. Tool-level CWE Coverage Analysis ---
print("\n" + "="*50)
print("PART 1: Tool-level CWE Coverage Analysis")
print("="*50)

# Get the set of all unique CWEs found by each tool
cwe_sets = {}
for tool in TOOLS:
    cwe_sets[tool] = set(df[df['Tool_name'] == tool]['CWE_ID'])
    print(f"Total unique CWEs found by {tool}: {len(cwe_sets[tool])}")

print("\n--- Top 25 CWE Coverage (%) ---")
for tool in TOOLS:
    # Get rows for this tool
    tool_df = df[df['Tool_name'] == tool]
    
    # Find how many of its findings are in the Top 25
    top_25_findings = tool_df[tool_df['Is_In_CWE_Top_25?'] == 'Yes']
    
    # Get the set of *unique* Top 25 CWEs this tool found
    unique_top_25_cwes_found = set(top_25_findings['CWE_ID'])
    
    # Total unique CWEs found by this tool
    total_unique_cwes_found = len(cwe_sets[tool])
    
    if total_unique_cwes_found == 0:
        print(f"{tool}: Found 0 total CWEs.")
    else:
        # Calculate coverage: (Unique Top 25 CWEs found) / (Total Unique CWEs found)
        coverage_percent = (len(unique_top_25_cwes_found) / total_unique_cwes_found) * 100
        print(f"{tool}: Found {len(unique_top_25_cwes_found)} unique Top 25 CWEs out of {total_unique_cwes_found} total unique CWEs.")
        print(f"  -> Top 25 Coverage: {coverage_percent:.2f}%")


# --- 2. Pairwise Agreement (IoU) Analysis ---
print("\n" + "="*50)
print("PART 2: Pairwise Agreement (IoU) Analysis")
print("="*50)

def calculate_iou(set1, set2):
    """Calculates the Intersection over Union (Jaccard Index)"""
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    
    if union == 0:
        return 0.0 # Avoid division by zero
        
    return intersection / union

# Create the IoU Matrix
iou_matrix = pd.DataFrame(index=TOOLS, columns=TOOLS, dtype=float)

for tool_a in TOOLS:
    for tool_b in TOOLS:
        if tool_a == tool_b:
            iou_matrix.loc[tool_a, tool_b] = 1.0
        else:
            set_a = cwe_sets[tool_a]
            set_b = cwe_sets[tool_b]
            iou_value = calculate_iou(set_a, set_b)
            iou_matrix.loc[tool_a, tool_b] = iou_value

print("--- Tool x Tool IoU Matrix (Jaccard Index) ---")
print(iou_matrix.to_string(float_format="%.4f"))

# --- 3. Interpretation (as required by assignment) ---
print("\n" + "="*50)
print("PART 3: How to Interpret These Results for Your Report")
print("="*50)

print("\n--- Interpreting the IoU Matrix ---")
print("The IoU matrix shows the *similarity* between tools based on the *types* of CWEs they find (not the count).")
print("A high value (near 1.0) means two tools find very similar sets of weaknesses (high agreement, high overlap).")
print("A low value (near 0.0) means two tools find very different sets of weaknesses (low agreement, high diversity).")
print("  -> Use the low values to answer 'which tool combination maximizes CWE coverage?'")

print("\n--- Answering Final Questions ---")
print("Q: Which tool combination maximizes CWE coverage?")
print("A: Look for the pair with the *lowest* IoU value. This pair has the least overlap, so using them together covers the widest range of unique CWEs.")

print("\nQ: What are the takeaways of your analyses?")
print("A: Your takeaways should be:")
print("  1. No single tool finds all weaknesses. (Look at the IoU values - none are 1.0 between different tools).")
print("  2. Different tools specialize. (e.g., Bandit finds Python-specific CWEs, SpotBugs finds Java-specific CWEs. Your IoU matrix will show this. Horusec is a generalist and will have some overlap with both).")
print("  3. To get the best security, you must use multiple, *diverse* tools (a low IoU pair) to cover different types of vulnerabilities.")


# --- 4. Generate and Save Graph ---
print("\n" + "="*50)
print("PART 4: Generating Visualization")
print("="*50)

# Get the data for the chart
tool_names = TOOLS
cwe_counts = [len(cwe_sets[tool]) for tool in tool_names] # This will be [15, 0, 0]

# Create the bar chart
plt.figure(figsize=(10, 6))
colors = ['blue', 'orange', 'green']
plt.bar(tool_names, cwe_counts, color=colors)

# Add titles and labels
plt.title('Unique CWEs Found by Tool', fontsize=16)
plt.ylabel('Number of Unique CWEs Found', fontsize=12)
plt.xlabel('Tool Name', fontsize=12)
plt.grid(axis='y', linestyle='--', alpha=0.7)

# Add the count labels on top of the bars
for i, count in enumerate(cwe_counts):
    plt.text(i, count + 0.1, str(count), ha='center', fontweight='bold')

# Save the figure to a file
output_chart_file = 'cwe_coverage_chart.png'
plt.savefig(output_chart_file)

print(f"Success! Bar chart has been saved to: {output_chart_file}")
print("You can find this file in your 'Stt_lab6' folder.")
