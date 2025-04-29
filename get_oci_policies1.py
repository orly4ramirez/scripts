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

# Cache for all groups to avoid multiple lookups
all_groups_cache = None

def get_config_details():
    """Retrieve tenancy OCID and regions from OCI config file."""
    config_file = os.path.expanduser("~/.oci/config")
    print(f"Reading OCI configuration from: {config_file}")
    if not os.path.exists(config_file):
        print(f"ERROR: OCI config file not found at {config_file}. Please set up OCI CLI.")
        exit(1)

    config = configparser.ConfigParser()
    try:
        config.read(config_file)
    except configparser.Error as e:
        print(f"ERROR: Failed to parse OCI config file {config_file}: {e}")
        exit(1)

    # Determine default profile for tenancy OCID lookup
    default_profile = 'DEFAULT'

    if default_profile not in config:
        print(f"ERROR: No [{default_profile}] profile found in {config_file} to determine tenancy OCID.")
        # Check if it exists with different casing (less likely but possible)
        if default_profile.lower() in (k.lower() for k in config.sections()):
             print(f"       Hint: A profile with different casing like '[{next(k for k in config.sections() if k.lower() == default_profile.lower())}]' exists.")
        exit(1)

    tenancy_ocid = config[default_profile].get('tenancy')
    if not tenancy_ocid:
        print(f"ERROR: No 'tenancy' key found in [{default_profile}] profile of {config_file}.")
        exit(1)
    print(f"Found Tenancy OCID using profile: [{default_profile}]") # Don't print the OCID itself

    # --- Debugging Region Detection --- START ---
    print(f"\nDebugging region detection in profile [{default_profile}]...")
    if default_profile in config:
        if 'region' in config[default_profile]:
             print(f"  Found 'region' key in [{default_profile}]: '{config[default_profile]['region']}'")
        elif ' Region' in config[default_profile]: # Check for common typo (space)
             print(f"  WARNING: Found key ' Region' (with leading space) instead of 'region' in [{default_profile}]. Using it: '{config[default_profile][' Region']}'")
             config[default_profile]['region'] = config[default_profile][' Region'] # Correct it for parsing
        elif 'Region' in config[default_profile]: # Check for common typo (capital R)
             print(f"  WARNING: Found key 'Region' (capital R) instead of 'region' in [{default_profile}]. Using it: '{config[default_profile]['Region']}'")
             config[default_profile]['region'] = config[default_profile]['Region'] # Correct it for parsing
        else:
             print(f"  Could not find 'region' key in [{default_profile}].")
    else:
        # This case was handled above, but added for completeness
        print(f"  Profile [{default_profile}] section itself was not found.")
    print("--- Debugging End ---\n")
    # --- Debugging Region Detection --- END ---

    # Get all unique regions from ALL profiles in the config file
    regions = set()
    print("Scanning config file for regions in all profiles...")
    for section in config.sections():
        # Skip the DEFAULT section handled separately if needed, or check if it has region
        # if section == default_profile:
        #     continue
        if 'region' in config[section]:
            region_name = config[section]['region']
            # Check for empty region string
            if region_name and region_name.strip():
                print(f"  Found region '{region_name.strip()}' in profile [{section}]")
                regions.add(region_name.strip())
            else:
                print(f"  WARNING: Found empty 'region' key in profile [{section}]. Skipping.")
        # else:
             # print(f"  Profile [{section}] does not contain a 'region' key.")

    # Explicitly add region from DEFAULT profile if found during debug
    if default_profile in config and 'region' in config[default_profile]:
        default_region = config[default_profile]['region'].strip()
        if default_region and default_region not in regions:
            print(f"  Adding region '{default_region}' from [{default_profile}] profile.")
            regions.add(default_region)

    if not regions:
        print("ERROR: No valid regions found in any profile within the OCI config file. Please add at least one region key with a value.")
        exit(1)

    print(f"Successfully identified {len(regions)} unique region(s) for processing.")
    return tenancy_ocid, list(regions)

def run_oci_command(command):
    """Executes an OCI CLI command and returns the parsed JSON output."""
    try:
        # Use the default profile unless overridden by command arguments like --region
        full_command = f"{command}" # OCI CLI uses DEFAULT profile unless specified otherwise
        print(f"  Executing OCI CLI (command truncated): {full_command[:120]}...") # Print shortened command
        result = subprocess.run(full_command, shell=True, text=True, capture_output=True, check=True)

        # Check for empty stdout before parsing
        if not result.stdout.strip():
             print(f"  WARNING: OCI CLI command returned empty output. Command: {full_command[:120]}...")
             return None # Treat empty output as non-error, but no data

        return json.loads(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"ERROR running OCI CLI command.")
        print(f"  Command: {command[:120]}...")
        print(f"  Return Code: {e.returncode}")
        # Log stderr for debugging
        print(f"  Stderr: {e.stderr.strip()}")
        return None
    except json.JSONDecodeError as e:
        print(f"ERROR parsing JSON output from OCI CLI command.")
        print(f"  Command: {command[:120]}...")
        print(f"  Error: {e}")
        # Log the problematic stdout content
        print(f"  Received Stdout (first 500 chars): {result.stdout[:500].strip()}...")
        return None
    except Exception as e:
        print(f"ERROR: An unexpected error occurred running command.")
        print(f"  Command: {command[:120]}...")
        print(f"  Error Type: {type(e).__name__}")
        print(f"  Error: {e}")
        return None

def process_region(tenancy_ocid, region):
    """Process policies for a specific region."""
    print(f"\n=== Processing Region: {region} ===")

    # Get compartments
    print("  Fetching compartments in region...")
    # Use tenancy OCID to list compartments within the region context
    compartments_cmd = f"oci iam compartment list --compartment-id {tenancy_ocid} --all --include-root --region {region}"
    compartments_data = run_oci_command(compartments_cmd)

    if not compartments_data or "data" not in compartments_data:
        print(f"  WARNING: Failed to retrieve compartments or no compartments found for region {region}. Skipping region.")
        return 0

    region_policy_count = 0
    compartments = compartments_data["data"]
    print(f"  Found {len(compartments)} compartment entries (including root).")

    # Add the root compartment details if not already included by --include-root (safeguard)
    if not any(c['id'] == tenancy_ocid for c in compartments):
        print("  Adding root compartment (tenancy) details manually.")
        compartments.append({
            "id": tenancy_ocid,
            "name": "Tenancy (Root)",
            "lifecycle-state": "ACTIVE" # Assume active for processing
        })

    # Process policies in each compartment
    for compartment in compartments:
        compartment_id = compartment["id"]
        compartment_name = compartment.get("name", "Unnamed Compartment")

        # Skip inactive compartments (unless it's the tenancy root)
        if compartment.get("lifecycle-state") != "ACTIVE" and compartment_id != tenancy_ocid:
            print(f"  Skipping inactive compartment: '{compartment_name}'")
            continue

        print(f"  Checking compartment: '{compartment_name}'")

        policies_cmd = f"oci iam policy list --compartment-id {compartment_id} --all --region {region}"
        policies = run_oci_command(policies_cmd)

        if not policies or "data" not in policies:
            if policies is None:
                # Error logged by run_oci_command
                print(f"  Skipping policy check for compartment '{compartment_name}' due to fetch error.")
            # else:
                # print(f"  No policies found in compartment '{compartment_name}'.") # Normal, no need to log
            continue

        policy_count_in_comp = 0
        for policy in policies["data"]:
            policy_name = policy.get("name", "Unnamed Policy")
            policy_ocid = policy.get("id")

            # Skip inactive policies
            if policy.get("lifecycle-state") != "ACTIVE":
                # print(f"    Skipping inactive policy: '{policy_name}'")
                continue

            statements = policy.get("statements", [])
            if not statements:
                 # print(f"    Policy '{policy_name}' has no statements.")
                 continue

            # print(f"    Processing policy: '{policy_name}'")
            for statement_index, statement in enumerate(statements):
                if not isinstance(statement, str):
                    print(f"    WARNING: Skipping non-string statement at index {statement_index} in policy '{policy_name}'")
                    continue

                policy_count_in_comp += 1
                region_policy_count += 1

                # Determine target
                target_type = "tenancy"
                target_name = "tenancy"
                if " in compartment id " in statement.lower():
                    target_type = "compartment_id"
                    # Extract compartment OCID carefully
                    parts = statement.lower().split(" in compartment id ", 1)
                    if len(parts) > 1:
                        target_name = parts[1].split(" ")[0].strip()
                    else:
                        target_name = "<parse_error>"
                elif " in compartment " in statement.lower():
                     target_type = "compartment_name"
                     match = re.search(r'in compartment\s+("([^"]+)"|(\S+))', statement, re.IGNORECASE)
                     if match:
                         target_name = match.group(2) or match.group(3)
                     else:
                         target_name = compartment_name # Fallback
                elif " in tenancy" in statement.lower():
                     target_type = "tenancy"
                     target_name = "tenancy"

                # Extract group name
                group_name = ""
                match = re.search(r'allow group\s+("([^"]+)"|(\S+))', statement, re.IGNORECASE)
                if match:
                    group_name = match.group(2) or match.group(3)
                    group_name = group_name.strip(".,")

                policy_statements.append({
                    'region': region,
                    'compartment_name': compartment_name,
                    # 'compartment_ocid': compartment_id, # Removed for console clarity
                    'policy_name': policy_name,
                    # 'policy_ocid': policy_ocid, # Removed for console clarity
                    'statement_index': statement_index,
                    'statement': statement,
                    'target_type': target_type,
                    'target_name': target_name,
                    'group_name': group_name
                })
        # if policy_count_in_comp > 0:
            # print(f"    Found {policy_count_in_comp} active policy statements in '{compartment_name}'.")

    print(f"Finished processing region {region}. Found {region_policy_count} policy statements.")
    return region_policy_count

def write_policies_to_csv():
    """Write all policy data to a single CSV output file."""
    if not policy_statements:
        print("No policy statements found to write to CSV.")
        return 0

    # Define CSV field names - simplified for example, adjust as needed
    fieldnames = [
        'Region', 'Compartment Name', 'Policy Name',
        'Statement Index', 'Statement', 'Target Type', 'Target Name', 'Group Name'
    ]
    print(f"\nWriting {len(policy_statements)} policy statements to {policy_output_file}...")

    try:
        with open(policy_output_file, mode='w', encoding='utf-8', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=[f.lower().replace(' ', '_') for f in fieldnames])

            header_dict = {f.lower().replace(' ', '_'): f for f in fieldnames}
            writer.writerow(header_dict)

            for policy in policy_statements:
                # Prepare row data, ensuring all keys match the writer's fieldnames
                row_data = {key: policy.get(key, '') for key in writer.fieldnames}
                writer.writerow(row_data)

        print(f"Successfully wrote {len(policy_statements)} statements to {policy_output_file}.")
        return len(policy_statements)
    except IOError as e:
        print(f"ERROR writing policies to CSV file {policy_output_file}: {e}")
        return 0
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during policy CSV writing: {e}")
        return 0

# --- Functions for Group User Extraction ---

def get_group_ocid_by_name(group_name):
    """Attempts to find the OCID of a group by its name (case-insensitive), with fallback."""
    global all_groups_cache # Use the global cache
    print(f"    Attempting to find OCID for group name: '{group_name}' (case-insensitive)")

    # 1. Try direct name filter first (more efficient)
    print(f"      Attempt 1: Using OCI CLI --name filter...")
    # Use quotes for names with spaces/special chars. Escape potential internal quotes?
    # Simple quoting should work for most names if the shell handles it.
    quoted_group_name = f'"{group_name}"' # Simple quoting
    group_cmd = f"oci iam group list --name {quoted_group_name} --all"
    groups_data_filtered = run_oci_command(group_cmd)

    found_ocid = None
    if groups_data_filtered and "data" in groups_data_filtered:
        for group in groups_data_filtered["data"]:
            # Double check name case-insensitively as filter might be sensitive
            if group.get("name", "").lower() == group_name.lower():
                found_ocid = group.get("id")
                print(f"      Found matching group OCID via --name filter: {found_ocid[:15]}...")
                return found_ocid # Success!
        # If data was returned but no exact case-insensitive match, the filter might be imperfect
        print(f"      Direct --name filter returned data, but no exact case-insensitive match for '{group_name}'. Proceeding to fallback.")
    elif groups_data_filtered is None:
        # Command failed (error logged by run_oci_command), proceed to fallback
         print(f"      Direct --name filter command failed. Proceeding to fallback.")
    # else: # Command succeeded but returned empty data list
    #     print(f"      Direct --name filter found no groups named '{group_name}'. Proceeding to fallback.")

    # 2. Fallback: List all groups (if not already cached) and filter locally
    print(f"      Attempt 2: Using fallback - listing all groups (if not cached)...")
    if all_groups_cache is None:
        print("        Fetching all groups for the first time (this might take a moment)...")
        all_groups_cmd = "oci iam group list --all"
        all_groups_data = run_oci_command(all_groups_cmd)
        if all_groups_data and "data" in all_groups_data:
            print(f"        Successfully fetched {len(all_groups_data['data'])} groups. Caching.")
            # Create a lowercase name to group data map for efficient lookup
            all_groups_cache = {g.get("name", "").lower(): g for g in all_groups_data["data"]}
        else:
            print("        ERROR: Failed to fetch the list of all groups for fallback lookup. Cannot find group OCID.")
            all_groups_cache = {} # Set empty cache to prevent retrying
            return None

    # Search in the cached data (case-insensitive)
    group_data = all_groups_cache.get(group_name.lower())
    if group_data:
        found_ocid = group_data.get("id")
        group_status = group_data.get("lifecycle-state", "UNKNOWN")
        print(f"      Found matching group OCID via fallback search: {found_ocid[:15]}... (Status: {group_status})")
        return found_ocid
    else:
        print(f"      WARNING: Could not find group '{group_name}' via fallback search either.")
        return None

def get_users_in_group(group_ocid, group_name_for_log):
    """Retrieves active users belonging to a specific group OCID."""
    print(f"    Fetching users for group '{group_name_for_log}'...")
    users_cmd = f"oci iam group list-users --group-id {group_ocid} --all"
    users_data = run_oci_command(users_cmd)

    users_list = []
    if users_data and "data" in users_data:
        print(f"      Found {len(users_data['data'])} user entries (memberships) in group. Fetching user details...")
        fetched_user_count = 0
        for user_membership in users_data["data"]:
            user_id = user_membership.get("user-id")
            if not user_id:
                print("      WARNING: Found a user membership entry with no user-id. Skipping.")
                continue

            # print(f"        Fetching details for user ID: {user_id[:15]}...{user_id[-5:]}") # Log truncated OCID
            user_details_cmd = f"oci iam user get --user-id {user_id}"
            user_info = run_oci_command(user_details_cmd)

            if user_info and "data" in user_info:
                user_detail_data = user_info["data"]
                if user_detail_data.get("lifecycle-state") == "ACTIVE":
                    user_name = user_detail_data.get("name", "Unknown User")
                    user_ocid = user_detail_data.get("id")
                    # print(f"          Found active user: '{user_name}'")
                    users_list.append({
                        'user_name': user_name,
                        'user_ocid': user_ocid # Store user OCID for CSV
                    })
                    fetched_user_count += 1
                # else:
                #     print(f"        Skipping inactive user: ID {user_id[:15]}...")
            else:
                # Error logged by run_oci_command or no data returned
                print(f"        WARNING: Failed to get details for user ID {user_id}. Skipping user.")
        print(f"      Successfully fetched details for {fetched_user_count} active users in group '{group_name_for_log}'.")
    elif users_data is None:
         print(f"      ERROR: Failed to list users for group '{group_name_for_log}'. Check permissions or group status.")
    else:
         print(f"      No user memberships found for group '{group_name_for_log}'.")

    return users_list

def write_group_users_to_csv(group_user_data):
    """Writes the collected group and user data to a CSV file."""
    if not group_user_data:
        print("\nNo group user data found to write to CSV.")
        return 0

    fieldnames = ['Group Name', 'Group OCID', 'User Name', 'User OCID']
    print(f"\n=== Writing Group Users ({len(group_user_data)} entries) to {group_users_output_file} ===")

    try:
        with open(group_users_output_file, mode='w', encoding='utf-8', newline='') as csvfile:
            # Use DictWriter fieldnames based on the keys in the first data row for robustness
            # writer_fieldnames = list(group_user_data[0].keys()) if group_user_data else [f.lower().replace(' ', '_') for f in fieldnames]
            writer_fieldnames = [f.lower().replace(' ', '_') for f in fieldnames] # Stick to defined fields
            writer = csv.DictWriter(csvfile, fieldnames=writer_fieldnames)

            header_dict = {f: f.replace('_', ' ').title() for f in writer_fieldnames} # Create readable headers
            writer.writerow(header_dict)

            written_count = 0
            for row in group_user_data:
                # Ensure row has all keys expected by writer, provide default empty string if missing
                row_to_write = {key: row.get(key, '') for key in writer_fieldnames}
                writer.writerow(row_to_write)
                written_count += 1

        print(f"Successfully wrote {written_count} group user entries to {group_users_output_file}.")
        return written_count
    except IOError as e:
        print(f"ERROR writing group users to CSV file {group_users_output_file}: {e}")
        return 0
    except Exception as e:
         print(f"ERROR: An unexpected error occurred during group user CSV writing: {e}")
         return 0

# --- End Group User Functions ---

def main():
    """Main function: Extracts OCI policies, then extracts users from groups found in policies."""
    print("OCI Policy & Group User Extractor")
    print("=================================")

    # Reset global cache at the start of each run
    global all_groups_cache
    all_groups_cache = None

    # Get tenancy OCID and regions from config
    tenancy_ocid, regions = get_config_details()
    print(f"Processing policies for regions: {', '.join(regions)}")

    # --- Policy Extraction ---
    print("\n--- Starting Policy Extraction --- (This may take a while...) ---")
    global policy_statements # Ensure we modify the global list
    policy_statements = [] # Reset policy statements at start
    total_policies = 0
    processed_regions_count = 0
    for region in regions:
        try:
            policies_count = process_region(tenancy_ocid, region)
            total_policies += policies_count
            processed_regions_count += 1
        except Exception as e:
            print(f"ERROR: Unhandled exception during processing of region {region}: {e}")
            print(f"       Attempting to continue with next region...")
            # Optionally add more detailed error logging here (e.g., traceback)

    print("\n=== Policy Extraction Summary ===")
    print(f"Regions processed: {processed_regions_count}/{len(regions)}")
    print(f"Total policy statements found: {total_policies}")

    # Write policy results to CSV file
    statements_written = write_policies_to_csv()
    if statements_written == 0 and total_policies > 0:
        print("WARNING: Policies were found but writing to CSV failed.")
    elif total_policies == 0:
         print("No policy statements were found in any processed region.")

    # --- Group User Extraction ---
    print("\n--- Starting Group User Extraction ---")

    # 1. Get unique group names from policies (case-insensitive)
    unique_group_names_case_sensitive = set(p['group_name'] for p in policy_statements if p.get('group_name'))
    # Store lowercase for lookup, keep original for reporting
    group_name_map_case_insensitive = {name.lower(): name for name in unique_group_names_case_sensitive}
    unique_group_names_lower = set(group_name_map_case_insensitive.keys())

    if not unique_group_names_lower:
        print("No group names found referenced in policy statements. Skipping group user extraction.")
        print("\nExtraction complete.")
        return

    print(f"Found {len(unique_group_names_lower)} unique group names (case-insensitive) in policies.")

    # 2. Attempt to fetch users for each unique group name
    group_user_data = []
    processed_groups_count = 0
    failed_groups_count = 0

    # Sort by lowercase name for consistent processing order
    for group_name_lower in sorted(list(unique_group_names_lower)):
        original_group_name = group_name_map_case_insensitive[group_name_lower]
        print(f"\n  Processing group referenced in policy: '{original_group_name}'")
        processed_groups_count += 1

        # Attempt to find the group OCID by name (case-insensitive)
        group_ocid = get_group_ocid_by_name(original_group_name)

        if group_ocid:
            # If OCID found, try to get users
            users = get_users_in_group(group_ocid, original_group_name) # Pass original name for logging
            if users:
                print(f"    Successfully retrieved {len(users)} active users for group '{original_group_name}'.")
                for user in users:
                    group_user_data.append({
                        'group_name': original_group_name, # Use original case name in CSV
                        'group_ocid': group_ocid,
                        'user_name': user['user_name'],
                        'user_ocid': user['user_ocid']
                    })
            # else: # Logging handled within get_users_in_group
            #     print(f"    No active users found or failed to retrieve users for group '{original_group_name}'.")
        else:
            # OCID not found
            print(f"    Could not find OCID for group '{original_group_name}'. Skipping user listing for this group.")
            failed_groups_count += 1
            # This could be because the group doesn't exist, is inactive, or naming issues/permissions.

    # 3. Write group user data to CSV
    users_written = write_group_users_to_csv(group_user_data)

    print("\n=== Group User Extraction Summary ===")
    print(f"Attempted processing for {processed_groups_count} unique group names found in policies.")
    print(f"Successfully found OCIDs and listed users for {processed_groups_count - failed_groups_count} groups.")
    print(f"Failed to find OCID or list users for {failed_groups_count} groups (check warnings above)." )
    print(f"Total group user entries written to {group_users_output_file}: {users_written}")

    print("\nExtraction complete.")

if __name__ == "__main__":
    main()