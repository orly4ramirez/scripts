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

def get_vaults_in_compartment(kms_management_client, compartment_id):
    """Retrieve all vaults in a compartment"""
    print(f"Retrieving vaults in compartment {compartment_id}...")
    
    try:
        vaults_response = oci.pagination.list_call_get_all_results(
            kms_management_client.list_vaults,
            compartment_id
        )
        return vaults_response.data
    except Exception as e:
        print(f"Error retrieving vaults in compartment {compartment_id}: {e}")
        return []

def get_keys_in_vault(kms_management_client, compartment_id, vault_id, management_endpoint):
    """Retrieve all keys in a vault"""
    print(f"Retrieving keys in vault {vault_id}...")
    
    try:
        # Create a new client specific to this vault's management endpoint
        vault_client = oci.key_management.KmsManagementClient(
            kms_management_client.base_client.config,
            management_endpoint
        )
        
        keys_response = oci.pagination.list_call_get_all_results(
            vault_client.list_keys,
            compartment_id
        )
        return keys_response.data
    except Exception as e:
        print(f"Error retrieving keys in vault {vault_id}: {e}")
        return []

def get_key_details(kms_management_client, key_id, management_endpoint):
    """Retrieve details for a specific key"""
    print(f"Retrieving details for key {key_id}...")
    
    try:
        # Create a new client specific to this vault's management endpoint
        vault_client = oci.key_management.KmsManagementClient(
            kms_management_client.base_client.config,
            management_endpoint
        )
        
        key_response = vault_client.get_key(key_id)
        return key_response.data
    except Exception as e:
        print(f"Error retrieving details for key {key_id}: {e}")
        return None

def get_key_versions(kms_management_client, key_id, management_endpoint):
    """Retrieve versions for a specific key"""
    print(f"Retrieving versions for key {key_id}...")
    
    try:
        # Create a new client specific to this vault's management endpoint
        vault_client = oci.key_management.KmsManagementClient(
            kms_management_client.base_client.config,
            management_endpoint
        )
        
        versions_response = oci.pagination.list_call_get_all_results(
            vault_client.list_key_versions,
            key_id
        )
        return versions_response.data
    except Exception as e:
        print(f"Error retrieving versions for key {key_id}: {e}")
        return []

def find_resources_using_key(search_client, key_id):
    """Find resources that use a specific key"""
    print(f"Finding resources that use key {key_id}...")
    
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
        print(f"Error finding resources using key {key_id}: {e}")
        return []

def process_key(key_data, compartment_data, vault_data, clients_data):
    """Process a single key and collect all its details"""
    try:
        key_id = key_data.id
        management_endpoint = vault_data.management_endpoint
        
        # Get key details
        key_details = get_key_details(
            clients_data["kms_management_client"],
            key_id,
            management_endpoint
        )
        
        if not key_details:
            print(f"No details available for key {key_id}. Skipping.")
            return None
        
        # Get key versions
        key_versions = get_key_versions(
            clients_data["kms_management_client"],
            key_id,
            management_endpoint
        )
        
        # Find resources using this key
        resources_using_key = find_resources_using_key(
            clients_data["search_client"],
            key_id
        )
        
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
        print(f"Error processing key {key_data.id}: {e}")
        return None

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
                    <th>Key ID</th>
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
        
        created_date = key_details.get("time_created", "")
        if created_date:
            created_date = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
        
        html_content += f"""
                <tr>
                    <td>{key_entry.get("compartment_name", "Unknown")}</td>
                    <td>{key_entry.get("vault_name", "Unknown")}</td>
                    <td>{key_details.get("display_name", "Unknown")}</td>
                    <td>{key_details.get("id", "Unknown")}</td>
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
        
        # Key properties
        html_content += f"""
            <div id="key-detail-{i}" class="content">
                <h3>Key Properties</h3>
                <table>
                    <tr><th>Property</th><th>Value</th></tr>
                    <tr><td>Compartment</td><td>{key_entry.get("compartment_name", "Unknown")} ({key_entry.get("compartment_id", "Unknown")})</td></tr>
                    <tr><td>Vault</td><td>{key_entry.get("vault_name", "Unknown")} ({key_entry.get("vault_id", "Unknown")})</td></tr>
                    <tr><td>Key Name</td><td>{key_details.get("display_name", "Unknown")}</td></tr>
                    <tr><td>Key ID</td><td>{key_details.get("id", "Unknown")}</td></tr>
                    <tr><td>Algorithm</td><td>{key_details.get("algorithm", "Unknown")}</td></tr>
                    <tr><td>Protection Mode</td><td>{key_details.get("protection_mode", "Unknown")}</td></tr>
                    <tr><td>Current Version</td><td>{key_details.get("current_key_version", "Unknown")}</td></tr>
                    <tr><td>State</td><td>{key_details.get("lifecycle_state", "Unknown")}</td></tr>
                    <tr><td>Created Date</td><td>{created_date}</td></tr>
                    <tr><td>Crypto Endpoint</td><td>{key_entry.get("vault_crypto_endpoint", "Unknown")}</td></tr>
                    <tr><td>Management Endpoint</td><td>{key_entry.get("vault_management_endpoint", "Unknown")}</td></tr>
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
                        <th>ID</th>
                        <th>State</th>
                        <th>Created</th>
                    </tr>
            """
            
            for version in key_versions:
                version_created = version.get("time_created", "")
                if version_created:
                    version_created = datetime.strptime(version_created, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
                
                html_content += f"""
                    <tr>
                        <td>{version.get("key_version_number", "Unknown")}</td>
                        <td>{version.get("id", "Unknown")}</td>
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
                        <th>ID</th>
                    </tr>
            """
            
            for resource in resources:
                html_content += f"""
                    <tr>
                        <td>{resource.get("resource_type", "Unknown")}</td>
                        <td>{resource.get("display_name", "Unknown")}</td>
                        <td>{resource.get("identifier", "Unknown")}</td>
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
            
            created_date = key_details.get("time_created", "")
            if created_date:
                created_date = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
            
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
        kms_management_client = oci.key_management.KmsManagementClient(config)
        search_client = oci.resource_search.ResourceSearchClient(config)
        
        # Test the connection
        identity_client.list_regions()
    except Exception as e:
        print(f"Error initializing OCI clients: {e}")
        print("Please check your OCI configuration and permissions.")
        sys.exit(1)
    
    # Get tenancy ID from config
    tenancy_id = config.get('tenancy')
    
    # Determine the compartment ID
    compartment_id = None
    
    # If compartment name is provided, look up its ID
    if args.compartment_name:
        compartment_id = find_compartment_by_name(identity_client, tenancy_id, args.compartment_name)
        if not compartment_id:
            print("Error: Could not find compartment by name. Please check the name or use compartment ID instead.")
            sys.exit(1)
    else:
        # Use the provided compartment ID or default to tenancy
        compartment_id = args.compartment_id
        if not compartment_id:
            compartment_id = tenancy_id
            print(f"No compartment specified, using tenancy root compartment: {compartment_id}")
    
    # Get all compartments
    compartments = get_all_compartments(identity_client, compartment_id)
    print(f"Found {len(compartments)} compartments")
    
    # Results array
    results = []
    keys_found = 0
    
    # Collect all keys from all compartments and vaults
    for compartment in compartments:
        print(f"Processing compartment: {compartment.name} ({compartment.id})")
        
        # Get vaults in compartment
        vaults = get_vaults_in_compartment(kms_management_client, compartment.id)
        print(f"Found {len(vaults)} vaults in compartment {compartment.name}")
        
        for vault in vaults:
            print(f"Processing vault: {vault.display_name} ({vault.id})")
            
            # Skip vaults without management endpoint
            if not vault.management_endpoint:
                print(f"No management endpoint available for vault {vault.display_name}. Skipping.")
                continue
            
            # Get keys in vault
            keys = get_keys_in_vault(
                kms_management_client,
                compartment.id,
                vault.id,
                vault.management_endpoint
            )
            print(f"Found {len(keys)} keys in vault {vault.display_name}")
            
            # Process each key using thread pool for better performance
            clients_data = {
                "kms_management_client": kms_management_client,
                "search_client": search_client
            }
            
            with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
                futures = {
                    executor.submit(
                        process_key, 
                        key, 
                        compartment, 
                        vault,
                        clients_data
                    ): key.id for key in keys
                }
                
                for future in as_completed(futures):
                    key_id = futures[future]
                    try:
                        key_entry = future.result()
                        if key_entry:
                            results.append(key_entry)
                            keys_found += 1
                            print(f"Processed {keys_found} keys so far...")
                            
                            # Save intermediate results
                            with open(json_output, 'w') as f:
                                json.dump(results, f, indent=2)
                    except Exception as e:
                        print(f"Error processing key {key_id}: {e}")
    
    # Save final results
    print(f"Writing results to {json_output}")
    with open(json_output, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Generate CSV report
    generate_csv_report(results, csv_output)
    
    # Generate HTML report
    generate_html_report(results, html_output)
    
    print(f"Successfully processed {keys_found} encryption keys")
    print(f"JSON report: {json_output}")
    print(f"CSV report: {csv_output}")
    print(f"HTML report: {html_output}")
    print("Done!")

if __name__ == "__main__":
    start_time = time.time()
    main()
    elapsed_time = time.time() - start_time
    print(f"Total execution time: {elapsed_time:.2f} seconds")