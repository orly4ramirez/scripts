import subprocess
import json
from collections import defaultdict
import configparser
import os
import re
import csv

# Output file
output_file = "oci_policies.csv"

# Data structure for all policy statements
policy_statements = []

def get_config_details():
    """Retrieve tenancy OCID and regions from OCI config file."""
    config_file = os.path.expanduser("~/.oci/config")
    if not os.path.exists(config_file):
        print(f"OCI config file not found at {config_file}. Please set up OCI CLI.")
        exit(1)
    
    config = configparser.ConfigParser()
    config.read(config_file)
    
    profile = 'DEFAULT'
    if profile not in config:
        print(f"No [DEFAULT] profile found in {config_file}.")
        exit(1)
    
    tenancy_ocid = config[profile].get('tenancy')
    if not tenancy_ocid:
        print(f"No tenancy OCID found in [DEFAULT] profile of {config_file}.")
        exit(1)
    
    # Get all regions from config file
    regions = set()
    for section in config.sections():
        if 'region' in config[section]:
            regions.add(config[section]['region'])
    
    # Add default region if present
    if 'region' in config[profile]:
        regions.add(config[profile]['region'])
    
    if not regions:
        print("No regions found in OCI config file. Please add at least one region.")
        exit(1)
    
    return tenancy_ocid, list(regions)

def run_oci_command(command):
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running '{command}': {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from '{command}': {e}")
        return None

def process_region(tenancy_ocid, region):
    """Process policies for a specific region."""
    print(f"\n=== Processing Region: {region} ===")
    
    # Get compartments (region-independent, but we'll use the --region flag for consistency)
    compartments_cmd = f"oci iam compartment list --compartment-id {tenancy_ocid} --all --include-root --region {region}"
    compartments = run_oci_command(compartments_cmd)
    
    if not compartments or "data" not in compartments:
        print(f"Failed to retrieve compartments for region {region}. Check your OCI CLI configuration and permissions.")
        return 0
    
    region_policy_count = 0
    
    # Process policies in each compartment
    for compartment in compartments["data"]:
        compartment_id = compartment["id"]
        compartment_name = compartment["name"]
        print(f"  Checking compartment: {compartment_name} ({compartment_id})")
        
        policies_cmd = f"oci iam policy list --compartment-id {compartment_id} --all --region {region}"
        policies = run_oci_command(policies_cmd)
        
        if not policies or "data" not in policies:
            print(f"  Skipping compartment {compartment_name} ({compartment_id}) - no policies or error.")
            continue
        
        for policy in policies["data"]:
            policy_name = policy.get("name", "Unnamed Policy")
            for statement in policy["statements"]:
                if not isinstance(statement, str):
                    continue
                
                region_policy_count += 1
                
                # Determine target
                target = "tenancy"  # Default
                if " in " in statement.lower():
                    target_part = statement.lower().split(" in ", 1)[1].strip()
                    if target_part.startswith("tenancy"):
                        target = "tenancy"
                    elif target_part.startswith("compartment"):
                        comp_name = target_part.split("compartment ", 1)[1].strip()
                        # Handle compartment name in quotes
                        match = re.search(r'compartment\s+["\'](.*?)["\']', target_part)
                        if match:
                            comp_name = match.group(1)
                        target = comp_name if comp_name else compartment_name
                
                # Extract group name if present
                group_name = ""
                if "group " in statement.lower():
                    try:
                        parts = statement.lower().split("group ", 1)
                        if len(parts) > 1:
                            group_part = parts[1].split(" to ", 1)[0].strip()
                            if group_part:
                                # Handle group name in quotes
                                match = re.search(r'group\s+["\'](.*?)["\']', statement.lower())
                                if match:
                                    group_name = match.group(1)
                                else:
                                    group_name = group_part.split()[0].strip(".,")
                    except Exception as e:
                        print(f"  Error processing group statement: {statement} - {e}")
                
                # Store all information in a single structure
                policy_statements.append({
                    'region': region,
                    'compartment': compartment_name,
                    'policy_name': policy_name,
                    'statement': statement,
                    'target': target,
                    'group': group_name
                })
    
    print(f"Found {region_policy_count} policy statements in region {region}")
    return region_policy_count

def write_to_csv():
    """Write all policy data to a single CSV output file."""
    if not policy_statements:
        print("No policy statements found to write to CSV.")
        return 0
    
    # Define CSV field names
    fieldnames = ['Region', 'Compartment', 'Policy Name', 'Statement', 'Target', 'Group']
    
    # Write all policy statements to the CSV file
    with open(output_file, mode='w', encoding='utf-8', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=[name.lower() for name in fieldnames])
        writer.writeheader()
        
        # Write each policy statement as a row
        for policy in policy_statements:
            writer.writerow(policy)
    
    print(f"Total policy statements written to {output_file}: {len(policy_statements)}")
    return len(policy_statements)

def main():
    """Main function to coordinate the extraction of OCI policies across all regions."""
    print("OCI Policy Extractor - Multi-Region CSV Version")
    print("==============================================")
    
    # Get tenancy OCID and regions from config
    tenancy_ocid, regions = get_config_details()
    print(f"Found {len(regions)} region(s) in config: {', '.join(regions)}")
    
    # Process each region
    total_policies = 0
    for region in regions:
        policies_count = process_region(tenancy_ocid, region)
        total_policies += policies_count
    
    print("\n=== Summary ===")
    print(f"Total regions processed: {len(regions)}")
    print(f"Total policy statements found: {total_policies}")
    
    # Write results to CSV file
    statements_written = write_to_csv()
    print(f"\nPolicy extraction complete. {statements_written} statements written to {output_file}")

if __name__ == "__main__":
    main()