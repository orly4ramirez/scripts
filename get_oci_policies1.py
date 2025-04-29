import subprocess
import json
from collections import defaultdict
import configparser
import os
import re
import csv

# Output files
policy_output_file = "oci_policies.csv"
group_users_output_file = "oci_group_users.csv"

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
        print(f"No [{profile}] profile found in {config_file}.")
        exit(1)
    
    tenancy_ocid = config[profile].get('tenancy')
    if not tenancy_ocid:
        print(f"No tenancy OCID found in [{profile}] profile of {config_file}.")
        exit(1)
    
    # Get all regions from config file, considering all profiles
    regions = set()
    for section in config.sections():
        if 'region' in config[section]:
            regions.add(config[section]['region'])
    
    # Add default region if present explicitly under [DEFAULT]
    if 'region' in config[profile]:
        regions.add(config[profile]['region'])
    
    if not regions:
        print("No regions found in OCI config file. Please add at least one region.")
        exit(1)
    
    return tenancy_ocid, list(regions)

def run_oci_command(command):
    """Executes an OCI CLI command and returns the parsed JSON output."""
    try:
        # Use the default profile unless overridden by command arguments like --region
        full_command = f"{command}" # Profile implicitly used by OCI CLI
        print(f"  Executing: {full_command[:100]}...") # Print shortened command for brevity
        result = subprocess.run(full_command, shell=True, text=True, capture_output=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON output from command: {command}")
        print(f"Error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred running command: {command}")
        print(f"Error: {e}")
        return None

def process_region(tenancy_ocid, region):
    """Process policies for a specific region."""
    print(f"\n=== Processing Region: {region} ===")
    
    # Get compartments (region-independent, but we'll use the --region flag for consistency)
    # Compartment listing might need tenancy scope, but policies are per-compartment
    compartments_cmd = f"oci iam compartment list --compartment-id {tenancy_ocid} --all --include-root --region {region}"
    compartments_data = run_oci_command(compartments_cmd)
    
    if not compartments_data or "data" not in compartments_data:
        print(f"Failed to retrieve compartments for region {region}. Check OCI CLI config and permissions.")
        return 0
    
    region_policy_count = 0
    compartments = compartments_data["data"]
    
    # Also include the root compartment (tenancy) itself for policies defined there
    compartments.append({
        "id": tenancy_ocid,
        "name": "Tenancy (Root)",
        "lifecycle-state": "ACTIVE" # Assume active for processing
    })
    
    # Process policies in each compartment
    for compartment in compartments:
        # Skip inactive compartments
        if compartment.get("lifecycle-state") != "ACTIVE":
            print(f"  Skipping inactive compartment: {compartment.get('name', 'Unnamed')} ({compartment['id']})")
            continue
        
        compartment_id = compartment["id"]
        compartment_name = compartment["name"]
        print(f"  Checking compartment: {compartment_name} ({compartment_id})")
        
        policies_cmd = f"oci iam policy list --compartment-id {compartment_id} --all --region {region}"
        policies = run_oci_command(policies_cmd)
        
        # Handle cases where policies might be None or lack 'data'
        if not policies or "data" not in policies:
            # It's normal for compartments to have no policies, so don't print error unless command failed (handled in run_oci_command)
            if policies is None:
                print(f"  Failed to retrieve policies for compartment {compartment_name} ({compartment_id}).")
            # else:
            #     print(f"  No policies found in compartment {compartment_name} ({compartment_id}).")
            continue
        
        for policy in policies["data"]:
            # Skip inactive policies
            if policy.get("lifecycle-state") != "ACTIVE":
                print(f"    Skipping inactive policy: {policy.get('name', 'Unnamed Policy')} ({policy['id']})")
                continue
            
            policy_name = policy.get("name", "Unnamed Policy")
            policy_ocid = policy.get("id") # Store policy OCID
            statements = policy.get("statements", [])
            
            if not statements:
                print(f"    Policy '{policy_name}' ({policy_ocid}) has no statements.")
                continue
            
            for statement_index, statement in enumerate(statements):
                if not isinstance(statement, str):
                    print(f"    Skipping non-string statement at index {statement_index} in policy '{policy_name}'")
                    continue
                
                region_policy_count += 1
                
                # Determine target (improved logic)
                target = "tenancy" # Default assumption
                target_type = "tenancy" # Default type
                target_name = "tenancy" # Default name
                
                if " in compartment id " in statement.lower():
                    target_type = "compartment_id"
                    target_name = statement.lower().split(" in compartment id ", 1)[1].split(" ")[0].strip()
                    target = target_name # Use OCID as target identifier
                elif " in compartment " in statement.lower():
                    target_type = "compartment_name"
                    # Regex to handle quoted or unquoted compartment names after "in compartment"
                    match = re.search(r'in compartment\s+("([^"]+)"|(\S+))', statement, re.IGNORECASE)
                    if match:
                        target_name = match.group(2) or match.group(3) # Quoted or unquoted name
                        target = target_name
                    else:
                        target = compartment_name # Fallback to policy's compartment if parsing fails
                elif " in tenancy" in statement.lower():
                    target_type = "tenancy"
                    target_name = "tenancy"
                    target = "tenancy"
                
                # Extract group name (improved logic)
                group_name = ""
                # Regex to find group name (quoted or unquoted) after "allow group"
                match = re.search(r'allow group\s+("([^"]+)"|(\S+))', statement, re.IGNORECASE)
                if match:
                    group_name = match.group(2) or match.group(3) # Group 2 for quoted, Group 3 for unquoted
                    group_name = group_name.strip(".,") # Clean trailing chars
                
                # Store all information
                policy_statements.append({
                    'region': region,
                    'compartment_name': compartment_name,
                    'compartment_ocid': compartment_id,
                    'policy_name': policy_name,
                    'policy_ocid': policy_ocid,
                    'statement_index': statement_index,
                    'statement': statement,
                    'target_type': target_type,
                    'target_name': target_name,
                    'group_name': group_name # Store extracted group name
                })
    
    print(f"Found {region_policy_count} policy statements in region {region}")
    return region_policy_count

def write_policies_to_csv():
    """Write all policy data to a single CSV output file."""
    if not policy_statements:
        print("No policy statements found to write to CSV.")
        return 0
    
    # Define CSV field names - Updated
    fieldnames = [
        'Region', 'Compartment Name', 'Compartment OCID', 'Policy Name', 'Policy OCID',
        'Statement Index', 'Statement', 'Target Type', 'Target Name', 'Group Name'
    ]
    
    # Write all policy statements to the CSV file
    try:
        with open(policy_output_file, mode='w', encoding='utf-8', newline='') as csvfile:
            # Use DictWriter with lowercase fieldnames for consistency
            writer = csv.DictWriter(csvfile, fieldnames=[name.lower().replace(' ', '_') for name in fieldnames])
            
            # Write header using original field names for readability
            header_dict = {name.lower().replace(' ', '_'): name for name in fieldnames}
            writer.writerow(header_dict)
            
            # Write each policy statement as a row using the internal keys
            for policy in policy_statements:
                # Ensure all keys exist, provide default if missing (though shouldn't happen with current logic)
                row_data = {key.lower().replace(' ', '_'): policy.get(key.lower().replace(' ', '_'), '') for key in fieldnames}
                writer.writerow(row_data)
            
        print(f"Total policy statements written to {policy_output_file}: {len(policy_statements)}")
        return len(policy_statements)
    except IOError as e:
        print(f"Error writing policies to CSV file {policy_output_file}: {e}")
        return 0
    except Exception as e:
        print(f"An unexpected error occurred during policy CSV writing: {e}")
        return 0

# --- New Functions for Group User Extraction ---

def get_all_groups(tenancy_ocid):
    """Retrieves all groups in the tenancy and returns a name-to-OCID mapping."""
    print("\n=== Fetching All Groups in Tenancy ===")
    groups_cmd = f"oci iam group list --all" # Tenancy scope is implicit
    groups_data = run_oci_command(groups_cmd)
    
    if not groups_data or "data" not in groups_data:
        print("Failed to retrieve groups. Check OCI CLI config and permissions.")
        return None
    
    group_map = {}
    for group in groups_data["data"]:
        # Skip inactive groups
        if group.get("lifecycle-state") == "ACTIVE":
            group_map[group["name"]] = group["id"]
        else:
            print(f"  Skipping inactive group: {group.get('name', 'Unnamed Group')} ({group.get('id')})")
    
    print(f"Found {len(group_map)} active groups in the tenancy.")
    return group_map

def get_users_in_group(group_ocid):
    """Retrieves users belonging to a specific group OCID."""
    # print(f"    Fetching users for group OCID: {group_ocid}") # Verbose logging
    users_cmd = f"oci iam group list-users --group-id {group_ocid} --all"
    users_data = run_oci_command(users_cmd)
    
    users_list = []
    if users_data and "data" in users_data:
        for user_membership in users_data["data"]:
            # Fetch user details to get name (list-users only gives user-id)
            user_id = user_membership.get("user-id")
            if not user_id:
                continue
            
            # Get user details - this might be slow if run for many users individually
            # Consider optimizing if performance is an issue (e.g., get all users once)
            user_details_cmd = f"oci iam user get --user-id {user_id}"
            user_info = run_oci_command(user_details_cmd)
            
            if user_info and "data" in user_info and user_info["data"].get("lifecycle-state") == "ACTIVE":
                user_name = user_info["data"].get("name", "Unknown User")
                user_ocid = user_info["data"].get("id") # Should be same as user_id
                users_list.append({
                    'user_name': user_name,
                    'user_ocid': user_ocid
                })
            # else: # Handle case where user is inactive or fetch fails
            #     print(f"      Skipping inactive user or failed fetch for user ID: {user_id}")
    
    # else: # Handle case where group might have no users or command fails
    #     if users_data is None:
    #         print(f"      Failed to retrieve users for group OCID: {group_ocid}")
        # else:
        #     print(f"      No users found for group OCID: {group_ocid}")
    
    return users_list

def write_group_users_to_csv(group_user_data):
    """Writes the collected group and user data to a CSV file."""
    if not group_user_data:
        print("\nNo group user data found to write to CSV.")
        return 0
    
    fieldnames = ['Group Name', 'Group OCID', 'User Name', 'User OCID']
    print(f"\n=== Writing Group Users to {group_users_output_file} ===")
    
    try:
        with open(group_users_output_file, mode='w', encoding='utf-8', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=[name.lower().replace(' ', '_') for name in fieldnames])
            
            # Write header using original field names
            header_dict = {name.lower().replace(' ', '_'): name for name in fieldnames}
            writer.writerow(header_dict)
            
            # Write data rows
            for row in group_user_data:
                writer.writerow(row) # Assumes row keys match fieldnames
        
        print(f"Total group user entries written to {group_users_output_file}: {len(group_user_data)}")
        return len(group_user_data)
    except IOError as e:
        print(f"Error writing group users to CSV file {group_users_output_file}: {e}")
        return 0
    except Exception as e:
        print(f"An unexpected error occurred during group user CSV writing: {e}")
        return 0

# --- End New Functions ---

def main():
    """Main function to coordinate the extraction of OCI policies and group users."""
    print("OCI Policy & Group User Extractor")
    print("=================================")
    
    # Get tenancy OCID and regions from config
    tenancy_ocid, regions = get_config_details()
    print(f"Found {len(regions)} region(s) in config: {', '.join(regions)}")
    print(f"Using Tenancy OCID: {tenancy_ocid}")
    
    # --- Policy Extraction ---
    print("\n--- Starting Policy Extraction ---")
    total_policies = 0
    for region in regions:
        policies_count = process_region(tenancy_ocid, region)
        total_policies += policies_count
    
    print("\n=== Policy Extraction Summary ===")
    print(f"Total regions processed: {len(regions)}")
    print(f"Total policy statements found: {total_policies}")
    
    # Write policy results to CSV file
    statements_written = write_policies_to_csv()
    print(f"Policy extraction complete. {statements_written} statements written to {policy_output_file}")
    
    # --- Group User Extraction ---
    print("\n--- Starting Group User Extraction ---")
    
    # 1. Get unique group names from policies
    unique_group_names = set(p['group_name'] for p in policy_statements if p.get('group_name'))
    if not unique_group_names:
        print("No group names found in policies to extract users from. Skipping group user extraction.")
        return # Exit if no groups found
    
    print(f"Found {len(unique_group_names)} unique group names in policies.")
    
    # 2. Get all groups in the tenancy (Name -> OCID map)
    all_groups_map = get_all_groups(tenancy_ocid)
    if not all_groups_map:
        print("Cannot proceed with user extraction without group list. Exiting.")
        return # Exit if group fetching failed
    
    # 3. Fetch users for each relevant group
    group_user_data = []
    processed_groups = 0
    for group_name in sorted(list(unique_group_names)): # Sort for consistent processing order
        group_ocid = all_groups_map.get(group_name)
        if not group_ocid:
            print(f"  Warning: Group '{group_name}' found in policies but not found (or inactive) in tenancy group list. Skipping.")
            continue
        
        print(f"  Processing group: '{group_name}' ({group_ocid})")
        processed_groups += 1
        users = get_users_in_group(group_ocid)
        if users:
            print(f"    Found {len(users)} active users in group '{group_name}'.")
            for user in users:
                group_user_data.append({
                    'group_name': group_name,
                    'group_ocid': group_ocid,
                    'user_name': user['user_name'],
                    'user_ocid': user['user_ocid']
                })
        # else: # Already handled logging within get_users_in_group
        #     print(f"    No active users found or failed to retrieve users for group '{group_name}'.")
    
    # 4. Write group user data to CSV
    users_written = write_group_users_to_csv(group_user_data)
    
    print("\n=== Group User Extraction Summary ===")
    print(f"Processed {processed_groups} groups out of {len(unique_group_names)} unique names found in policies.")
    print(f"Total group user entries written: {users_written}")
    
    print("\nExtraction complete.")

if __name__ == "__main__":
    main()