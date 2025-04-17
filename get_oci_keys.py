#!/usr/bin/env python3
"""
OCI Encryption Keys Report Generator
-----------------------------------
This script retrieves all encryption keys from OCI vaults,
along with their properties and associated resources.

Requirements:
- Python 3.6+
- OCI Python SDK (pip install oci)
- Configured OCI config file (~/.oci/config)
"""

import oci
import json
import argparse
import os
import sys
from datetime import datetime
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def get_all_compartments(identity_client, compartment_id):
    """Retrieve all compartments in the tenancy recursively"""
    print("Retrieving all compartments...")
    
    try:
        compartments = []
        list_compartments_response = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            compartment_id,
            compartment_id_in_subtree=True,
            lifecycle_state="ACTIVE"
        )
        
        # Add the root compartment
        if compartment_id not in [c.id for c in list_compartments_response.data]:
            try:
                root_compartment = identity_client.get_compartment(compartment_id).data
                compartments.append(root_compartment)
            except Exception as e:
                print(f"Error retrieving root compartment: {e}")
        
        compartments.extend(list_compartments_response.data)
        return compartments
    except Exception as e:
        print(f"Error retrieving compartments: {e}")
        return []

def find_compartment_by_name(identity_client, tenancy_id, compartment_name):
    """Find a compartment by its name and return its OCID"""
    print(f"Looking up compartment with name: {compartment_name}")
    
    # List all compartments in the tenancy
    compartments = []
    try:
        compartments_response = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            tenancy_id,
            compartment_id_in_subtree=True,
            lifecycle_state="ACTIVE"
        )
        compartments = compartments_response.data
        
        # Also check the root compartment
        try:
            root_compartment = identity_client.get_compartment(tenancy_id).data
            if root_compartment.name.lower() == compartment_name.lower():
                return root_compartment.id
            compartments.append(root_compartment)
        except Exception as e:
            print(f"Warning: Error retrieving root compartment: {e}")
    
    except Exception as e:
        print(f"Error looking up compartments: {e}")
        return None
    
    # Search for the compartment by name (case-insensitive)
    for compartment in compartments:
        if compartment.name.lower() == compartment_name.lower():
            print(f"Found compartment: {compartment.name} (ID: {compartment.id})")
            return compartment.id
    
    print(f"Error: No compartment found with name '{compartment_name}'")
    return None

def get_vaults_in_compartment(config, compartment_id, compartment_name="Unknown compartment"):
    """Retrieve all vaults in a compartment"""
    print(f"Retrieving vaults in {compartment_name}...")
    
    try:
        # Create a client for listing vaults
        vault_client = oci.key_management.KmsVaultClient(config)
        
        vaults_response = oci.pagination.list_call_get_all_results(
            vault_client.list_vaults,
            compartment_id
        )
        return vaults_response.data
    except Exception as e:
        print(f"Error retrieving vaults in {compartment_name}: {e}")
        return []

def get_keys_in_vault(config, compartment_id, vault_id, management_endpoint, vault_name="Unknown vault"):
    """Retrieve all keys in a vault"""
    print(f"Retrieving keys in vault: {vault_name}...")
    
    try:
        # Create a new client specific to this vault's management endpoint
        vault_client = oci.key_management.KmsManagementClient(
            config,
            service_endpoint=management_endpoint
        )
        
        keys_response = oci.pagination.list_call_get_all_results(
            vault_client.list_keys,
            compartment_id
        )
        return keys_response.data
    except Exception as e:
        print(f"Error retrieving keys in vault {vault_name}: {e}")
        return []

def get_key_details(config, key_id, management_endpoint, key_name="Unknown key"):
    """Retrieve details for a specific key"""
    print(f"Retrieving details for key: {key_name}...")
    
    try:
        # Create a new client specific to this vault's management endpoint
        vault_client = oci.key_management.KmsManagementClient(
            config,
            service_endpoint=management_endpoint
        )
        
        key_response = vault_client.get_key(key_id)
        return key_response.data
    except Exception as e:
        print(f"Error retrieving details for key {key_name}: {e}")
        return None

def get_key_versions(config, key_id, management_endpoint, key_name="Unknown key"):
    """Retrieve versions for a specific key"""
    print(f"Retrieving versions for key: {key_name}...")
    
    try:
        # Create a new client specific to this vault's management endpoint
        vault_client = oci.key_management.KmsManagementClient(
            config,
            service_endpoint=management_endpoint
        )
        
        versions_response = oci.pagination.list_call_get_all_results(
            vault_client.list_key_versions,
            key_id
        )
        return versions_response.data
    except Exception as e:
        print(f"Error retrieving versions for key {key_name}: {e}")
        return []

def find_resources_using_key(search_client, key_id, key_name="Unknown key"):
    """Find resources that use a specific key"""
    print(f"Finding resources for key: {key_name}...")
    
    try:
        search_text = f"""
            query all resources
            where (
                definedTags.contains('*.\"EncryptionKey\".*') ||
                freeformTags.contains('*EncryptionKey*') ||
                (resourceType = 'VolumeBackup' && isEncrypted = 'true') ||
                (resourceType = 'BootVolume' && isEncrypted = 'true') ||
                (resourceType = 'Volume' && isEncrypted = 'true') ||
                (resourceType = 'Bucket' && isEncrypted = 'true') ||
                (resourceType = 'Database' && isEncrypted = 'true') ||
                (resourceType = 'AutonomousDatabase' && isEncrypted = 'true') ||
                (resourceType = 'FileSystem' && isEncrypted = 'true')
            )
        """
        
        search_response = search_client.search_resources(
            oci.resource_search.models.StructuredSearchDetails(
                query=search_text
            )
        )
        
        # Filter results to find resources that reference this key
        resources = []
        for item in search_response.data.items:
            resource_json = json.dumps(oci.util.to_dict(item))
            if key_id in resource_json:
                resources.append(item)
        
        return resources
    except Exception as e:
        # Simplified error message
        print(f"Error finding resources for key {key_name}. Check permissions.")
        return []

def process_key(key_data, compartment_data, vault_data, config, search_client):
    """Process a single key and collect all its details"""
    try:
        key_id = key_data.id
        key_name = key_data.display_name
        management_endpoint = vault_data.management_endpoint
        
        # Get key details
        key_details = get_key_details(
            config,
            key_id,
            management_endpoint,
            key_name
        )
        
        if not key_details:
            print(f"No details available for key {key_name}. Skipping.")
            return None
        
        # Get key versions
        key_versions = get_key_versions(
            config,
            key_id,
            management_endpoint,
            key_name
        )
        
        # Find resources using this key
        resources_using_key = find_resources_using_key(
            search_client,
            key_id,
            key_name
        )
        
        print(f"Key {key_name}: Found {len(resources_using_key)} resources using this key")
        
        # Create key entry
        key_entry = {
            "compartment_id": compartment_data.id,
            "compartment_name": compartment_data.name,
            "vault_id": vault_data.id,
            "vault_name": vault_data.display_name,
            "vault_management_endpoint": vault_data.management_endpoint,
            "vault_crypto_endpoint": vault_data.crypto_endpoint,
            "key_details": oci.util.to_dict(key_details),
            "key_versions": [oci.util.to_dict(version) for version in key_versions],
            "resources_using_key": [oci.util.to_dict(resource) for resource in resources_using_key]
        }
        
        return key_entry
    except Exception as e:
        print(f"Error processing key {key_data.display_name if hasattr(key_data, 'display_name') else key_id}: {e}")
        return None

def safe_parse_datetime(date_string):
    """Safely parse datetime string with enhanced error handling"""
    if not date_string:
        return ""
    
    # Trim whitespace and check for empty string
    date_string = date_string.strip()
    if not date_string:
        return ""
    
    # List of possible formats to try
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",    # Standard ISO format with microseconds
        "%Y-%m-%dT%H:%M:%SZ",       # ISO format without microseconds
        "%Y-%m-%dT%H:%M:%S",        # ISO format without Z
        "%Y-%m-%d %H:%M:%S",        # Standard datetime format
        "%Y-%m-%d",                 # Date only
        "%Y/%m/%d",                 # Date with slashes
        "%d-%m-%Y",                 # European format
        "%m/%d/%Y",                 # US format
        "%b %d, %Y",                # Month abbreviated
        "%B %d, %Y"                 # Month full name
    ]
    
    # Try each format
    for fmt in formats:
        try:
            return datetime.strptime(date_string, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    
    # If all parsing attempts fail, return the original string
    # but truncate if it's too long
    if len(date_string) > 30:
        return date_string[:27] + "..."
    return date_string

def generate_html_report(results, output_file):
    """Generate HTML report from the collected results"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OCI Encryption Keys Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #336699; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            .section { margin-top: 30px; }
            .subsection { margin-left: 20px; margin-top: 20px; }
            .collapsible { cursor: pointer; background-color: #eee; padding: 10px; border: none; text-align: left; outline: none; width: 100%; }
            .active, .collapsible:hover { background-color: #ccc; }
            .content { padding: 0 18px; display: none; overflow: hidden; background-color: #f1f1f1; }
            .progress-bar { background-color: #f1f1f1; border-radius: 5px; padding: 3px; margin-top: 10px; }
            .progress-bar-inner { background-color: #4CAF50; border-radius: 5px; height: 20px; width: 0%; }
        </style>
    </head>
    <body>
        <h1>OCI Encryption Keys Report</h1>
        <p>Report generated on: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        
        <div class="section">
            <h2>Summary</h2>
            <p>Total keys: """ + str(len(results)) + """</p>
        </div>
        
        <div class="section">
            <h2>Encryption Keys</h2>
            <table id="keys-table">
                <tr>
                    <th>Compartment</th>
                    <th>Vault</th>
                    <th>Key Name</th>
                    <th>Algorithm</th>
                    <th>Protection Mode</th>
                    <th>Current Version</th>
                    <th>State</th>
                    <th>Created Date</th>
                    <th>Resources Count</th>
                    <th>Details</th>
                </tr>
    """
    
    for i, key_entry in enumerate(results):
        key_details = key_entry.get("key_details", {})
        resource_count = len(key_entry.get("resources_using_key", []))
        
        created_date = safe_parse_datetime(key_details.get("time_created", ""))
        
        html_content += f"""
                <tr>
                    <td>{key_entry.get("compartment_name", "Unknown")}</td>
                    <td>{key_entry.get("vault_name", "Unknown")}</td>
                    <td>{key_details.get("display_name", "Unknown")}</td>
                    <td>{key_details.get("algorithm", "Unknown")}</td>
                    <td>{key_details.get("protection_mode", "Unknown")}</td>
                    <td>{key_details.get("current_key_version", "Unknown")}</td>
                    <td>{key_details.get("lifecycle_state", "Unknown")}</td>
                    <td>{created_date}</td>
                    <td>{resource_count}</td>
                    <td><button class="collapsible" data-index="{i}">Details</button></td>
                </tr>
        """
    
    html_content += """
            </table>
        </div>
        
        <div id="key-details">
    """
    
    for i, key_entry in enumerate(results):
        key_details = key_entry.get("key_details", {})
        key_versions = key_entry.get("key_versions", [])
        resources = key_entry.get("resources_using_key", [])
        
        created_date = safe_parse_datetime(key_details.get("time_created", ""))
        
        # Key properties
        html_content += f"""
            <div id="key-detail-{i}" class="content">
                <h3>Key Properties</h3>
                <table>
                    <tr><th>Property</th><th>Value</th></tr>
                    <tr><td>Compartment</td><td>{key_entry.get("compartment_name", "Unknown")}</td></tr>
                    <tr><td>Vault</td><td>{key_entry.get("vault_name", "Unknown")}</td></tr>
                    <tr><td>Key Name</td><td>{key_details.get("display_name", "Unknown")}</td></tr>
                    <tr><td>Key ID</td><td>{key_details.get("id", "Unknown")}</td></tr>
                    <tr><td>Algorithm</td><td>{key_details.get("algorithm", "Unknown")}</td></tr>
                    <tr><td>Protection Mode</td><td>{key_details.get("protection_mode", "Unknown")}</td></tr>
                    <tr><td>Current Version</td><td>{key_details.get("current_key_version", "Unknown")}</td></tr>
                    <tr><td>State</td><td>{key_details.get("lifecycle_state", "Unknown")}</td></tr>
                    <tr><td>Created Date</td><td>{created_date}</td></tr>
                </table>
        """
        
        # Key versions
        html_content += """
                <h3>Key Versions</h3>
        """
        
        if key_versions:
            html_content += """
                <table>
                    <tr>
                        <th>Version</th>
                        <th>State</th>
                        <th>Created</th>
                    </tr>
            """
            
            for version in key_versions:
                version_created = safe_parse_datetime(version.get("time_created", ""))
                
                html_content += f"""
                    <tr>
                        <td>{version.get("key_version_number", "Unknown")}</td>
                        <td>{version.get("lifecycle_state", "Unknown")}</td>
                        <td>{version_created}</td>
                    </tr>
                """
            
            html_content += """
                </table>
            """
        else:
            html_content += """
                <p>No version information available</p>
            """
        
        # Resources using key
        html_content += """
                <h3>Resources Using This Key</h3>
        """
        
        if resources:
            html_content += """
                <table>
                    <tr>
                        <th>Resource Type</th>
                        <th>Name</th>
                    </tr>
            """
            
            for resource in resources:
                html_content += f"""
                    <tr>
                        <td>{resource.get("resource_type", "Unknown")}</td>
                        <td>{resource.get("display_name", "Unknown")}</td>
                    </tr>
                """
            
            html_content += """
                </table>
            """
        else:
            html_content += """
                <p>No resources found using this key</p>
            """
        
        html_content += """
            </div>
        """
    
    html_content += """
        </div>
        
        <script>
            // Add event listeners to collapsible buttons
            document.querySelectorAll('.collapsible').forEach(button => {
                button.addEventListener('click', function() {
                    this.classList.toggle('active');
                    const content = document.getElementById(`key-detail-${this.dataset.index}`);
                    if (content.style.display === 'block') {
                        content.style.display = 'none';
                    } else {
                        // Hide all other open sections
                        document.querySelectorAll('.content').forEach(section => {
                            section.style.display = 'none';
                        });
                        content.style.display = 'block';
                    }
                });
            });
        </script>
    </body>
    </html>
    """
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {output_file}")

def generate_csv_report(results, output_file):
    """Generate CSV report from the collected results"""
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow([
            "Compartment Name", 
            "Vault Name", 
            "Key Name", 
            "Key ID", 
            "Algorithm", 
            "Protection Mode", 
            "Current Key Version", 
            "State", 
            "Created Date", 
            "Resources Using Key"
        ])
        
        # Write data
        for key_entry in results:
            key_details = key_entry.get("key_details", {})
            resource_count = len(key_entry.get("resources_using_key", []))
            
            created_date = safe_parse_datetime(key_details.get("time_created", ""))
            
            writer.writerow([
                key_entry.get("compartment_name", "Unknown"),
                key_entry.get("vault_name", "Unknown"),
                key_details.get("display_name", "Unknown"),
                key_details.get("id", "Unknown"),
                key_details.get("algorithm", "Unknown"),
                key_details.get("protection_mode", "Unknown"),
                key_details.get("current_key_version", "Unknown"),
                key_details.get("lifecycle_state", "Unknown"),
                created_date,
                resource_count
            ])
    
    print(f"CSV report generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='OCI Encryption Keys Report Generator')
    parser.add_argument('--compartment-id', help='OCID of the compartment to search (default: root compartment)')
    parser.add_argument('--compartment-name', help='Name of the compartment to search (alternative to compartment-id)')
    parser.add_argument('--config-file', default='~/.oci/config', help='Path to OCI config file')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile to use')
    parser.add_argument('--output-dir', default='./oci_encryption_keys_report', help='Output directory for reports')
    parser.add_argument('--max-workers', type=int, default=5, help='Maximum number of worker threads')
    args = parser.parse_args()
    
    # Expand user directory
    config_file = os.path.expanduser(args.config_file)
    output_dir = os.path.expanduser(args.output_dir)
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Get current time for output files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_output = os.path.join(output_dir, f"encryption_keys_report_{timestamp}.json")
    csv_output = os.path.join(output_dir, f"encryption_keys_report_{timestamp}.csv")
    html_output = os.path.join(output_dir, f"encryption_keys_report_{timestamp}.html")
    
    print(f"Starting OCI Encryption Keys report...")
    print(f"Using config file: {config_file}")
    print(f"Using profile: {args.profile}")
    print(f"Output files will be saved to: {output_dir}")
    
    # Initialize OCI clients
    try:
        config = oci.config.from_file(config_file, args.profile)
        identity_client = oci.identity.IdentityClient(config)
        search_client = oci.resource_search.ResourceSearchClient(config)
        
        # Test the connection
        identity_client.list_regions()
    except Exception as e:
        print(f"Error initializing OCI clients: {e}")
        print("Please check your OCI configuration and permissions.")
        sys.exit(1)
    
    # Get tenancy ID from config
    tenancy_id = config.get('tenancy')
    print(f"Tenancy ID: {tenancy_id}")
    
    # Determine the compartment ID
    compartment_id = None
    compartment_name = None
    
    # If compartment name is provided, look up its ID
    if args.compartment_name:
        compartment_name = args.compartment_name
        print(f"Looking up compartment: {compartment_name}")
        compartment_id = find_compartment_by_name(identity_client, tenancy_id, compartment_name)
        if not compartment_id:
            print("Error: Could not find compartment by name. Please check the name or use compartment ID instead.")
            sys.exit(1)
        print(f"Found compartment: {compartment_name} (ID: {compartment_id})")
    else:
        # Use the provided compartment ID or default to tenancy
        compartment_id = args.compartment_id
        if not compartment_id:
            compartment_id = tenancy_id
            print(f"No compartment specified, using root compartment")
    
    # Get all compartments
    compartments = get_all_compartments(identity_client, compartment_id)
    print(f"Found {len(compartments)} compartments")
    
    # Progress tracking
    start_time = time.time()
    total_vaults = 0
    processed_vaults = 0
    total_keys = 0
    processed_keys = 0
    
    # First pass to count total vaults and keys for progress tracking
    print("\n[1/3] Counting vaults and keys for progress tracking...")
    for compartment in compartments:
        vaults = get_vaults_in_compartment(config, compartment.id, compartment.name)
        total_vaults += len(vaults)
        
        for vault in vaults:
            if not vault.management_endpoint:
                continue
                
            keys = get_keys_in_vault(
                config,
                compartment.id,
                vault.id,
                vault.management_endpoint,
                vault.display_name
            )
            total_keys += len(keys)
    
    print(f"Found {total_vaults} vaults containing {total_keys} keys in total")
    
    # Results array
    results = []
    keys_found = 0
    
    # Collect all keys from all compartments and vaults
    print("\n[2/3] Retrieving encryption keys and their properties...")
    for compartment in compartments:
        print(f"\nProcessing compartment: {compartment.name}")
        
        # Get vaults in compartment
        vaults = get_vaults_in_compartment(config, compartment.id, compartment.name)
        if not vaults:
            print(f"  No vaults found in {compartment.name}")
            continue
            
        print(f"  Found {len(vaults)} vaults in {compartment.name}")
        
        for vault in vaults:
            processed_vaults += 1
            vault_progress = (processed_vaults / total_vaults) * 100
            
            print(f"  Processing vault: {vault.display_name} ({processed_vaults}/{total_vaults}, {vault_progress:.1f}%)")
            
            # Skip vaults without management endpoint
            if not vault.management_endpoint:
                print(f"    No management endpoint available for vault {vault.display_name}. Skipping.")
                continue
            
            # Get keys in vault
            keys = get_keys_in_vault(
                config,
                compartment.id,
                vault.id,
                vault.management_endpoint,
                vault.display_name
            )
            
            if not keys:
                print(f"    No keys found in vault {vault.display_name}")
                continue
                
            print(f"    Found {len(keys)} keys in vault {vault.display_name}")
            
            # Process each key using thread pool for better performance
            with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
                futures = {
                    executor.submit(
                        process_key, 
                        key, 
                        compartment, 
                        vault,
                        config,
                        search_client
                    ): key.id for key in keys
                }
                
                for future in as_completed(futures):
                    key_id = futures[future]
                    try:
                        key_entry = future.result()
                        if key_entry:
                            results.append(key_entry)
                            keys_found += 1
                            processed_keys += 1
                            key_progress = (processed_keys / total_keys) * 100
                            
                            elapsed_time = time.time() - start_time
                            estimated_total_time = (elapsed_time / processed_keys) * total_keys if processed_keys > 0 else 0
                            estimated_remaining_time = estimated_total_time - elapsed_time if estimated_total_time > 0 else 0
                            
                            print(f"    Processed key {processed_keys}/{total_keys} ({key_progress:.1f}%) - ETA: {estimated_remaining_time:.0f}s remaining")
                            
                            # Save intermediate results
                            with open(json_output, 'w') as f:
                                json.dump(results, f, indent=2)
                    except Exception as e:
                        print(f"    Error processing key {key_id}: {e}")
    
    # Generate reports
    print(f"\n[3/3] Generating reports...")
    
    # Save final results
    print(f"  Writing JSON report to {json_output}")
    with open(json_output, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Generate CSV report
    print(f"  Generating CSV report")
    generate_csv_report(results, csv_output)
    
    # Generate HTML report
    print(f"  Generating HTML report")
    generate_html_report(results, html_output)
    
    # Summary
    total_time = time.time() - start_time
    print(f"\nSummary:")
    print(f"  Successfully processed {keys_found} encryption keys across {total_vaults} vaults")
    print(f"  Total execution time: {total_time:.1f} seconds")
    print(f"  Reports generated:")
    print(f"    - JSON: {json_output}")
    print(f"    - CSV: {csv_output}")
    print(f"    - HTML: {html_output}")
    print("Done!")

if __name__ == "__main__":
    start_time = time.time()
    main()
    elapsed_time = time.time() - start_time
    print(f"Total execution time: {elapsed_time:.2f} seconds")