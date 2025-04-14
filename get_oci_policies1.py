import subprocess
import json
from collections import defaultdict
import configparser
import os

# Output file names
group_file = "policies_by_group.txt"
target_file = "policies_by_target.txt"
name_file = "policies_by_name.txt"

# Data structures
group_statements = defaultdict(list)
target_statements = defaultdict(list)
name_statements = defaultdict(list)

def get_tenancy_ocid():
    """Retrieve tenancy OCID from OCI config file."""
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
    
    return tenancy_ocid

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

# Get tenancy OCID
tenancy_ocid = get_tenancy_ocid()

# Get compartments
compartments_cmd = f"oci iam compartment list --compartment-id {tenancy_ocid} --all --include-root"
compartments = run_oci_command(compartments_cmd)

if not compartments or "data" not in compartments:
    print("Failed to retrieve compartments. Check your OCI CLI configuration and permissions.")
    exit(1)

# Process policies
for compartment in compartments["data"]:
    compartment_id = compartment["id"]
    compartment_name = compartment["name"]
    print(f"Checking compartment: {compartment_name} ({compartment_id})")
    
    policies_cmd = f"oci iam policy list --compartment-id {compartment_id} --all"
    policies = run_oci_command(policies_cmd)
    
    if not policies or "data" not in policies:
        print(f"Skipping compartment {compartment_name} ({compartment_id}) - no policies or error.")
        continue
    
    for policy in policies["data"]:
        policy_name = policy.get("name", "Unnamed Policy")
        for statement in policy["statements"]:
            if not isinstance(statement, str):
                continue
            
            # Determine target
            target = "tenancy"  # Default
            if " in " in statement.lower():
                target_part = statement.lower().split(" in ", 1)[1].strip()
                if target_part.startswith("tenancy"):
                    target = "tenancy"
                elif target_part.startswith("compartment"):
                    comp_name = target_part.split("compartment ", 1)[1].strip()
                    target = comp_name if comp_name else compartment_name
            
            # Store with compartment and target
            name_statements[policy_name].append((statement, compartment_name, target))
            target_statements[target].append((statement, compartment_name, target))
            
            if "group " in statement.lower():
                try:
                    parts = statement.lower().split("group ", 1)
                    if len(parts) > 1:
                        group_part = parts[1].split(" to ", 1)[0].strip()
                        if group_part:
                            group_name = group_part.split()[0].strip(".,")
                            group_statements[group_name].append((statement, compartment_name, target))
                except Exception as e:
                    print(f"Error processing group statement: {statement} - {e}")
                    continue

# Write to group file and count statements
total_group_statements = sum(len(stmts) for stmts in group_statements.values()) if group_statements else 0
if total_group_statements > 0:
    with open(group_file, mode="w", encoding="utf-8") as txtfile:
        max_group_len = max(len(group_name) for group_name in group_statements.keys())
        header = f"{'Group Name':<{max_group_len}}, Policy Statements, Compartment, Target"
        txtfile.write(header + "\n")
        
        padding = " " * (max_group_len + 2)
        first_group = True
        for group_name, statements in group_statements.items():
            if not first_group:
                txtfile.write("\n")
            first_group = False
            for i, (statement, compartment, target) in enumerate(statements):
                if i == 0:
                    line = f"{group_name:<{max_group_len}}, {statement}, {compartment}, {target}"
                else:
                    line = f"{padding}, {statement}, {compartment}, {target}"
                txtfile.write(line + "\n")
print(f"Total policy statements in {group_file}: {total_group_statements}")

# Write to target file and count statements
total_target_statements = sum(len(stmts) for stmts in target_statements.values()) if target_statements else 0
if total_target_statements > 0:
    with open(target_file, mode="w", encoding="utf-8") as txtfile:
        max_target_len = max(len(target) for target in target_statements.keys())
        header = f"{'Target':<{max_target_len}}, Policy Statements, Compartment, Target"
        txtfile.write(header + "\n")
        
        padding = " " * (max_target_len + 2)
        first_target = True
        for target, statements in target_statements.items():
            if not first_target:
                txtfile.write("\n")
            first_target = False
            for i, (statement, compartment, target_val) in enumerate(statements):
                if i == 0:
                    line = f"{target:<{max_target_len}}, {statement}, {compartment}, {target_val}"
                else:
                    line = f"{padding}, {statement}, {compartment}, {target_val}"
                txtfile.write(line + "\n")
print(f"Total policy statements in {target_file}: {total_target_statements}")

# Write to name file and count statements
total_name_statements = sum(len(stmts) for stmts in name_statements.values()) if name_statements else 0
if total_name_statements > 0:
    with open(name_file, mode="w", encoding="utf-8") as txtfile:
        max_name_len = max(len(name) for name in name_statements.keys())
        header = f"{'Policy Name':<{max_name_len}}, Policy Statements, Compartment, Target"
        txtfile.write(header + "\n")
        
        padding = " " * (max_name_len + 2)
        first_name = True
        for name, statements in name_statements.items():
            if not first_name:
                txtfile.write("\n")
            first_name = False
            for i, (statement, compartment, target) in enumerate(statements):
                if i == 0:
                    line = f"{name:<{max_name_len}}, {statement}, {compartment}, {target}"
                else:
                    line = f"{padding}, {statement}, {compartment}, {target}"
                txtfile.write(line + "\n")
print(f"Total policy statements in {name_file}: {total_name_statements}")