import subprocess
import json
import argparse
import os
import configparser
import csv
from collections import defaultdict

def parse_args():
    parser = argparse.ArgumentParser(description='Extract and organize OCI policies')
    parser.add_argument('--tenancy-ocid', help='The OCID of your tenancy (optional, will read from config if not provided)')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile to use (default: DEFAULT)')
    parser.add_argument('--output', default='oci_policies_by_group.csv', help='Output CSV file name (default: oci_policies_by_group.csv)')
    return parser.parse_args()

def get_tenancy_from_config(profile='DEFAULT'):
    """Read tenancy OCID from OCI config file"""
    config_file = os.path.expanduser('~/.oci/config')
    
    if not os.path.exists(config_file):
        print(f"OCI config file not found at {config_file}")
        return None
    
    config = configparser.ConfigParser()
    config.read(config_file)
    
    if profile not in config:
        print(f"Profile '{profile}' not found in OCI config")
        return None
    
    if 'tenancy' in config[profile]:
        return config[profile]['tenancy']
    
    print(f"Tenancy OCID not found in profile '{profile}'")
    return None

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

def extract_target_compartment(statement):
    """Extract the target compartment from a policy statement"""
    target_comp = "tenancy"  # Default
    
    if " in " in statement.lower():
        target_part = statement.lower().split(" in ", 1)[1].strip()
        if target_part.startswith("tenancy"):
            target_comp = "tenancy"
        elif target_part.startswith("compartment"):
            # Extract the compartment name if specified
            parts = target_part.split("compartment ", 1)
            if len(parts) > 1:
                comp_name = parts[1].strip().split()[0].strip("'\"")  # Take first word and strip quotes
                if comp_name:
                    target_comp = comp_name
    
    return target_comp

def main():
    args = parse_args()
    
    # Get tenancy OCID from command line or config file
    tenancy_ocid = args.tenancy_ocid
    if not tenancy_ocid:
        tenancy_ocid = get_tenancy_from_config(args.profile)
        if not tenancy_ocid:
            print("Error: Tenancy OCID not provided and could not be read from OCI config.")
            print("Please provide it with --tenancy-ocid or ensure it's in your OCI config file.")
            exit(1)
    
    print(f"Using tenancy OCID: {tenancy_ocid}")
    
    # Output file
    output_file = args.output
    
    # Data structure
    group_policies = defaultdict(list)
    
    # Get compartments
    compartments_cmd = f"oci iam compartment list --compartment-id {tenancy_ocid} --all --include-root"
    compartments = run_oci_command(compartments_cmd)

    if not compartments or "data" not in compartments:
        print("Failed to retrieve compartments. Check your OCI CLI configuration and permissions.")
        exit(1)

    # Create a lookup for compartment names by ID
    compartment_names = {comp["id"]: comp["name"] for comp in compartments["data"]}

    # Process policies
    for compartment in compartments["data"]:
        compartment_id = compartment["id"]
        definition_compartment = compartment["name"]  # This is where the policy is defined
        print(f"Checking compartment: {definition_compartment} ({compartment_id})")
        
        policies_cmd = f"oci iam policy list --compartment-id {compartment_id} --all"
        policies = run_oci_command(policies_cmd)
        
        if not policies or "data" not in policies:
            print(f"Skipping compartment {definition_compartment} ({compartment_id}) - no policies or error.")
            continue
        
        for policy in policies["data"]:
            policy_name = policy.get("name", "Unnamed Policy")
            
            for statement in policy["statements"]:
                if not isinstance(statement, str):
                    continue
                
                # Extract target compartment from the statement
                target_compartment = extract_target_compartment(statement)
                
                # Look for groups in the statement
                groups_found = False
                if "group " in statement.lower():
                    try:
                        parts = statement.lower().split("group ", 1)
                        if len(parts) > 1:
                            group_part = parts[1].split(" to ", 1)[0].strip()
                            if group_part:
                                group_name = group_part.split()[0].strip(".,")
                                # Store policy info: group, policy_name, definition_compartment, target_compartment, statement
                                group_policies[group_name].append({
                                    'group': group_name,
                                    'policy_name': policy_name,
                                    'definition_compartment': definition_compartment,
                                    'target_compartment': target_compartment,
                                    'statement': statement
                                })
                                groups_found = True
                    except Exception as e:
                        print(f"Error processing group statement: {statement} - {e}")
                        continue
                
                # If no group was found, add to "NO_GROUP" category
                if not groups_found:
                    group_policies["NO_GROUP"].append({
                        'group': "NO_GROUP",
                        'policy_name': policy_name,
                        'definition_compartment': definition_compartment,
                        'target_compartment': target_compartment,
                        'statement': statement
                    })

    # Write to CSV file
    total_policies = sum(len(policies) for policies in group_policies.values())
    if total_policies > 0:
        with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Group', 'Policy Name', 'Definition Compartment', 'Target Compartment', 'Policy Statement']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for group_name, policies in sorted(group_policies.items()):
                for policy in policies:
                    writer.writerow({
                        'Group': policy['group'],
                        'Policy Name': policy['policy_name'],
                        'Definition Compartment': policy['definition_compartment'],
                        'Target Compartment': policy['target_compartment'],
                        'Policy Statement': policy['statement']
                    })
        
        print(f"Successfully wrote {total_policies} policy statements to {output_file}")
    else:
        print("No policy statements found")

if __name__ == "__main__":
    main()