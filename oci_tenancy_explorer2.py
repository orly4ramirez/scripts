#!/usr/bin/env python3
"""
OCI Resource Inventory 

This script extracts all resources from a specified OCI compartment using the Resource Search API
and outputs detailed information to a CSV file.

Usage: python oci_resource_inventory.py --compartment-name "your-compartment-name" [--output-file "output.csv"]
"""

import oci
import csv
import sys
import os
import argparse
from datetime import datetime
import time

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Extract all resources from an OCI compartment using Resource Search API')
    parser.add_argument('--compartment-name', required=True, help='Name of the compartment to extract resources from')
    parser.add_argument('--output-file', default=None, help='Output CSV file path (default: compartment_name_resources_timestamp.csv)')
    parser.add_argument('--config-file', default='~/.oci/config', help='OCI config file path (default: ~/.oci/config)')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile (default: DEFAULT)')
    parser.add_argument('--recursive', action='store_true', help='Include child compartments (default: false)')
    return parser.parse_args()

def get_compartment_id_by_name(identity_client, tenancy_id, compartment_name):
    """Find compartment ID by name."""
    try:
        # Check if it's the root compartment (tenancy)
        tenancy = identity_client.get_compartment(tenancy_id).data
        if compartment_name.lower() == tenancy.name.lower():
            return tenancy_id
    except Exception as e:
        print(f"Error checking tenancy: {e}")
    
    # List all compartments in the tenancy
    compartments = []
    try:
        compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            compartment_id=tenancy_id,
            compartment_id_in_subtree=True
        ).data
    except Exception as e:
        print(f"Error listing compartments: {e}")
        sys.exit(1)
    
    # Find the compartment with matching name
    for compartment in compartments:
        if compartment.name.lower() == compartment_name.lower() and compartment.lifecycle_state == "ACTIVE":
            return compartment.id
    
    # If we get here, the compartment wasn't found
    raise Exception(f"Compartment '{compartment_name}' not found or not active.")

def get_all_compartments(identity_client, tenancy_id, parent_compartment_id):
    """Get all compartments in the tenancy or within a parent compartment."""
    compartments = []
    try:
        # Include the parent compartment
        parent = identity_client.get_compartment(parent_compartment_id).data
        compartments.append(parent)
        
        # Get all child compartments
        child_compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            compartment_id=parent_compartment_id,
            compartment_id_in_subtree=True,
            lifecycle_state="ACTIVE"
        ).data
        
        compartments.extend(child_compartments)
    except Exception as e:
        print(f"Error getting compartments: {e}")
    
    return compartments

def search_resources(search_client, compartment_id):
    """Search for all resources in a compartment."""
    query = f"query all resources where compartmentId = '{compartment_id}'"
    search_details = oci.resource_search.models.StructuredSearchDetails(
        type="Structured",
        query=query
    )
    
    try:
        response = oci.pagination.list_call_get_all_results(
            search_client.search_resources,
            search_details=search_details,
            limit=1000
        )
        return response.data.items
    except Exception as e:
        print(f"Error searching resources: {e}")
        return []

def extract_resource_group(defined_tags):
    """Extract resource group from defined tags."""
    if not defined_tags:
        return "N/A"
    
    try:
        if 'Oracle-ResourceGroup' in defined_tags:
            rg_tags = defined_tags['Oracle-ResourceGroup']
            if 'resourcegroup' in rg_tags:
                return rg_tags['resourcegroup']
            elif 'ResourceGroup' in rg_tags:
                return rg_tags['ResourceGroup']
        
        # Alternative format sometimes used
        if 'oracle-resourcegroup' in defined_tags:
            rg_tags = defined_tags['oracle-resourcegroup']
            for key, value in rg_tags.items():
                if 'resourcegroup' in key.lower():
                    return value
    except Exception:
        pass
    
    return "N/A"

def get_compartment_path(compartment_id, compartment_map):
    """Get the full path of a compartment."""
    if compartment_id not in compartment_map:
        return "Unknown"
    
    compartment = compartment_map[compartment_id]
    if hasattr(compartment, 'compartment_id') and compartment.compartment_id in compartment_map:
        parent_path = get_compartment_path(compartment.compartment_id, compartment_map)
        return f"{parent_path} / {compartment.name}"
    else:
        return compartment.name

def main():
    """Main function."""
    args = parse_arguments()
    start_time = time.time()
    
    # Set default output file if not specified
    if not args.output_file:
        args.output_file = f"{args.compartment_name}_resources_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    print(f"OCI Resource Inventory")
    print(f"====================")
    
    # Load OCI configuration
    config_file = os.path.expanduser(args.config_file)
    try:
        config = oci.config.from_file(config_file, args.profile)
    except Exception as e:
        print(f"Error loading OCI configuration: {e}")
        print("Make sure you have set up the OCI CLI configuration file at ~/.oci/config")
        sys.exit(1)
    
    # Initialize OCI clients
    identity_client = oci.identity.IdentityClient(config)
    search_client = oci.resource_search.ResourceSearchClient(config)
    
    # Get tenancy ID from config
    tenancy_id = config["tenancy"]
    
    # Get compartment ID
    try:
        compartment_id = get_compartment_id_by_name(identity_client, tenancy_id, args.compartment_name)
        print(f"Found compartment ID: {compartment_id}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Get all compartments to build a map for path resolution
    all_compartments = get_all_compartments(identity_client, tenancy_id, tenancy_id)
    compartment_map = {c.id: c for c in all_compartments}
    
    # Determine which compartments to search
    compartments_to_search = []
    if args.recursive:
        # Parent compartment and all children
        parent_compartment = identity_client.get_compartment(compartment_id).data
        compartments_to_search.append(parent_compartment)
        
        children = [c for c in all_compartments if hasattr(c, 'compartment_id') and c.compartment_id == compartment_id]
        compartments_to_search.extend(children)
        
        print(f"Searching {args.compartment_name} and {len(children)} child compartments")
    else:
        # Just the specified compartment
        compartments_to_search.append(identity_client.get_compartment(compartment_id).data)
        print(f"Searching compartment: {args.compartment_name}")
    
    # Collect all resources
    all_resources = []
    total_resources = 0
    
    for compartment in compartments_to_search:
        compartment_path = get_compartment_path(compartment.id, compartment_map)
        print(f"Searching compartment: {compartment_path}")
        
        resources = search_resources(search_client, compartment.id)
        resource_count = len(resources)
        total_resources += resource_count
        print(f"Found {resource_count} resources in {compartment_path}")
        
        all_resources.extend(resources)
    
    print(f"Total resources found: {total_resources}")
    
    # Define CSV headers
    headers = [
        "Compartment Name", 
        "Resource Name", 
        "Resource Group",
        "Compartment ID", 
        "Service", 
        "Resource Type", 
        "Resource ID",
        "Region", 
        "Availability Domain", 
        "Lifecycle State", 
        "Time Created",
        "Defined Tags", 
        "Freeform Tags"
    ]
    
    # Write to CSV
    with open(args.output_file, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        
        for resource in all_resources:
            # Get compartment path
            compartment_path = get_compartment_path(resource.compartment_id, compartment_map)
            
            # Get service from resource type
            service = resource.resource_type.split('.')[0] if '.' in resource.resource_type else ''
            
            # Get region from resource ID
            region = resource.identifier.split('.')[3] if len(resource.identifier.split('.')) > 3 else 'N/A'
            
            # Extract time created in readable format
            time_created = resource.time_created
            if time_created:
                if hasattr(time_created, 'strftime'):
                    time_created = time_created.strftime('%Y-%m-%d %H:%M:%S')
            
            # Extract resource group from defined tags
            resource_group = extract_resource_group(resource.defined_tags)
            
            row = {
                "Compartment Name": compartment_path,
                "Resource Name": resource.display_name,
                "Resource Group": resource_group,
                "Compartment ID": resource.compartment_id,
                "Service": service,
                "Resource Type": resource.resource_type,
                "Resource ID": resource.identifier,
                "Region": region,
                "Availability Domain": resource.availability_domain if resource.availability_domain else "N/A",
                "Lifecycle State": resource.lifecycle_state,
                "Time Created": time_created,
                "Defined Tags": str(resource.defined_tags) if resource.defined_tags else "",
                "Freeform Tags": str(resource.freeform_tags) if resource.freeform_tags else ""
            }
            writer.writerow(row)
    
    elapsed_time = time.time() - start_time
    print(f"Resources written to {args.output_file}")
    print(f"Total execution time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()