import subprocess
import json
import argparse
from collections import defaultdict

def parse_args():
    parser = argparse.ArgumentParser(description='Extract and organize OCI policies')
    parser.add_argument('--tenancy-ocid', required=True, help='The OCID of your tenancy')
    return parser.parse_args()

# Output file names
group_file = "policies_by_group.txt"
target_file = "policies_by_target.txt"
name_file = "policies_by_name.txt"

# Data structures
group_statements = defaultdict(list)
target_statements = defaultdict(list)
name_statements = defaultdict(list)

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
    tenancy_ocid = args.tenancy_ocid
    
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
                
                # Create a tuple with (statement, definition_compartment, target_compartment)
                policy_info = (statement, definition_compartment, target_compartment)
                
                # Group by policy name
                name_statements[policy_name].append(policy_info)
                
                # Group by target compartment
                target_statements[target_compartment].append(policy_info)
                
                # Group by group (if applicable)
                if "group " in statement.lower():
                    try:
                        parts = statement.lower().split("group ", 1)
                        if len(parts) > 1:
                            group_part = parts[1].split(" to ", 1)[0].strip()
                            if group_part:
                                group_name = group_part.split()[0].strip(".,")
                                group_statements[group_name].append(policy_info)
                    except Exception as e:
                        print(f"Error processing group statement: {statement} - {e}")
                        continue

    # Write to group file and count statements
    total_group_statements = sum(len(stmts) for stmts in group_statements.values()) if group_statements else 0
    if total_group_statements > 0:
        with open(group_file, mode="w", encoding="utf-8") as txtfile:
            max_group_len = max(len(group_name) for group_name in group_statements.keys())
            max_compartment_len = max(len(stmt[1]) for stmts in group_statements.values() for stmt in stmts)
            header = f"{'Group Name':<{max_group_len}}, {'Compartment':<{max_compartment_len}}, Policy Statements"
            txtfile.write(header + "\n")
            
            padding = " " * (max_group_len + 2)
            first_group = True
            for group_name, statements in group_statements.items():
                if not first_group:
                    txtfile.write("\n")
                first_group = False
                for i, (statement, compartment) in enumerate(statements):
                    if i == 0:
                        line = f"{group_name:<{max_group_len}}, {compartment:<{max_compartment_len}}, {statement}"
                    else:
                        line = f"{padding}, {compartment:<{max_compartment_len}}, {statement}"
                    txtfile.write(line + "\n")
    print(f"Total policy statements in {group_file}: {total_group_statements}")

    # Write to target file and count statements
    total_target_statements = sum(len(stmts) for stmts in target_statements.values()) if target_statements else 0
    if total_target_statements > 0:
        with open(target_file, mode="w", encoding="utf-8") as txtfile:
            max_target_len = max(len(target) for target in target_statements.keys())
            max_compartment_len = max(len(stmt[1]) for stmts in target_statements.values() for stmt in stmts)
            header = f"{'Target':<{max_target_len}}, {'Compartment':<{max_compartment_len}}, Policy Statements"
            txtfile.write(header + "\n")
            
            padding = " " * (max_target_len + 2)
            first_target = True
            for target, statements in target_statements.items():
                if not first_target:
                    txtfile.write("\n")
                first_target = False
                for i, (statement, compartment) in enumerate(statements):
                    if i == 0:
                        line = f"{target:<{max_target_len}}, {compartment:<{max_compartment_len}}, {statement}"
                    else:
                        line = f"{padding}, {compartment:<{max_compartment_len}}, {statement}"
                    txtfile.write(line + "\n")
    print(f"Total policy statements in {target_file}: {total_target_statements}")

    # Write to name file and count statements
    total_name_statements = sum(len(stmts) for stmts in name_statements.values()) if name_statements else 0
    if total_name_statements > 0:
        with open(name_file, mode="w", encoding="utf-8") as txtfile:
            max_name_len = max(len(name) for name in name_statements.keys())
            max_compartment_len = max(len(stmt[1]) for stmts in name_statements.values() for stmt in stmts)
            header = f"{'Policy Name':<{max_name_len}}, {'Compartment':<{max_compartment_len}}, Policy Statements"
            txtfile.write(header + "\n")
            
            padding = " " * (max_name_len + 2)
            first_name = True
            for name, statements in name_statements.items():
                if not first_name:
                    txtfile.write("\n")
                first_name = False
                for i, (statement, compartment) in enumerate(statements):
                    if i == 0:
                        line = f"{name:<{max_name_len}}, {compartment:<{max_compartment_len}}, {statement}"
                    else:
                        line = f"{padding}, {compartment:<{max_compartment_len}}, {statement}"
                    txtfile.write(line + "\n")
    print(f"Total policy statements in {name_file}: {total_name_statements}")

if __name__ == "__main__":
    main()