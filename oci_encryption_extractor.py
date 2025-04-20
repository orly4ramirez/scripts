#!/usr/bin/env python3
"""
OCI Encryption Keys Multi-Region CSV Generator
----------------------------------------------
This script retrieves all encryption keys from OCI vaults across multiple regions
and outputs a single CSV file with key properties and resource usage.

Requirements:
- Python 3.6+
- OCI Python SDK (pip install oci)
- Configured OCI config file (~/.oci/config)
"""

import oci
import csv
import argparse
import os
import sys
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Default regions to scan
DEFAULT_REGIONS = ['us-ashburn-1', 'us-phoenix-1']

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

def get_all_compartments(identity_client, compartment_id):
    """Retrieve all compartments in the tenancy recursively"""
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
    try:
        # Create a client for listing vaults
        vault_client = oci.key_management.KmsVaultClient(config)
        
        vaults_response = oci.pagination.list_call_get_all_results(
            vault_client.list_vaults,
            compartment_id
        )
        return vaults_response.data
    except Exception as e:
        # Simplified error message
        print(f"Error retrieving vaults in {compartment_name}. Check permissions.")
        return []

def get_keys_in_vault(config, compartment_id, vault_id, management_endpoint, vault_name="Unknown vault"):
    """Retrieve all keys in a vault"""
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
        # Simplified error message
        print(f"Error retrieving keys in vault {vault_name}. Check endpoint configuration.")
        return []

def get_key_details(config, key_id, management_endpoint, key_name="Unknown key"):
    """Retrieve details for a specific key"""
    try:
        # Create a new client specific to this vault's management endpoint
        vault_client = oci.key_management.KmsManagementClient(
            config,
            service_endpoint=management_endpoint
        )
        
        key_response = vault_client.get_key(key_id)
        return key_response.data
    except Exception as e:
        # Simplified error message
        print(f"Error retrieving details for key {key_name}. Check key access.")
        return None

def get_key_versions(config, key_id, management_endpoint, key_name="Unknown key"):
    """Retrieve versions for a specific key"""
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
        # Simplified error message
        print(f"Error retrieving versions for key {key_name}. Check key access.")
        return []

def get_vault_secrets(config, compartment_id, vault_id, vault_name="Unknown vault"):
    """Retrieve all secrets in a vault"""
    try:
        # Create a client for secrets
        secrets_client = oci.secrets.SecretsClient(config)
        
        # List all secrets in the compartment that belong to this vault
        secrets_response = oci.pagination.list_call_get_all_results(
            secrets_client.list_secrets,
            compartment_id,
            vault_id=vault_id
        )
        return secrets_response.data
    except Exception as e:
        # Simplified error message
        print(f"Error retrieving secrets in vault {vault_name}: {str(e)}")
        return []

def get_secret_details(config, secret_id, secret_name="Unknown secret"):
    """Retrieve details for a specific secret"""
    try:
        # Create a client for secrets
        secrets_client = oci.secrets.SecretsClient(config)
        
        # Get secret details
        secret_response = secrets_client.get_secret(secret_id)
        return secret_response.data
    except Exception as e:
        # Simplified error message
        print(f"Error retrieving details for secret {secret_name}: {str(e)}")
        return None

def determine_key_type(key_details):
    """Determine the type of key from its details"""
    if not key_details:
        return "Unknown Key Type"
        
    # Look at the key algorithm, protection mode, and other properties to determine the type
    algorithm = key_details.get("algorithm", "").upper()
    protection_mode = key_details.get("protection_mode", "").upper()
    
    # Determine key type based on algorithm and protection mode
    if "AES" in algorithm:
        key_type = "AES Encryption Key"
    elif "RSA" in algorithm:
        key_type = "RSA Key Pair"
    elif "ECDSA" in algorithm:
        key_type = "ECDSA Key Pair"
    else:
        key_type = f"{algorithm} Key"
    
    # Add protection mode information
    if "HSM" in protection_mode:
        key_type += " (HSM-protected)"
    elif "SOFTWARE" in protection_mode:
        key_type += " (Software-protected)"
    
    return key_type

def find_resources_using_key(search_client, key_id, key_name="Unknown key"):
    """Find resources that use a specific key"""
    try:
        # Enhanced search query to find more resources using encryption
        search_text = f"""
            query all resources
            where (
                definedTags.contains('*.\"EncryptionKey\".*') ||
                freeformTags.contains('*EncryptionKey*') ||
                freeformTags.contains('*encryption*') ||
                definedTags.contains('*.\"KmsKeyId\".*') ||
                definedTags.contains('*.\"key_id\".*') ||
                definedTags.contains('*.\"master_key_id\".*') ||
                (resourceType = 'VolumeBackup' && isEncrypted = 'true') ||
                (resourceType = 'BootVolume' && isEncrypted = 'true') ||
                (resourceType = 'Volume' && isEncrypted = 'true') ||
                (resourceType = 'Bucket' && isEncrypted = 'true') ||
                (resourceType = 'Database' && isEncrypted = 'true') ||
                (resourceType = 'AutonomousDatabase' && isEncrypted = 'true') ||
                (resourceType = 'FileSystem' && isEncrypted = 'true') ||
                (resourceType = 'VaultSecret') ||
                (resourceType = 'Secret') ||
                (resourceType = 'MasterEncryptionKey') ||
                (resourceType = 'BackupDestination' && isEncrypted = 'true') ||
                (resourceType = 'DbSystem' && isEncrypted = 'true') ||
                (resourceType = 'VmCluster' && isEncrypted = 'true') ||
                (resourceType = 'Vault')
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
        
        if not resources:
            print(f"No resources using key '{key_name}'")
        
        return resources
    except Exception as e:
        print(f"Error accessing resources for key '{key_name}': {str(e)}")
        return []

def find_resources_using_secret(search_client, secret_id, secret_name="Unknown secret"):
    """Find resources that use a specific secret"""
    try:
        # Search query focused on finding resources that might reference this secret
        search_text = f"""
            query all resources
            where (
                definedTags.contains('*.\"SecretId\".*') ||
                freeformTags.contains('*secret*') ||
                freeformTags.contains('*Secret*') ||
                definedTags.contains('*.\"secret_id\".*') ||
                (resourceType = 'ApiGateway') ||
                (resourceType = 'Function') ||
                (resourceType = 'FunctionsApplication') ||
                (resourceType = 'Instance') ||
                (resourceType = 'AutonomousDatabase') ||
                (resourceType = 'Database') ||
                (resourceType = 'DbSystem') ||
                (resourceType = 'Cluster') ||
                (resourceType = 'VmCluster') ||
                (resourceType = 'StreamPool')
            )
        """
        
        search_response = search_client.search_resources(
            oci.resource_search.models.StructuredSearchDetails(
                query=search_text
            )
        )
        
        # Filter results to find resources that reference this secret
        resources = []
        for item in search_response.data.items:
            resource_json = json.dumps(oci.util.to_dict(item))
            if secret_id in resource_json:
                resources.append(item)
        
        if not resources:
            print(f"No resources using secret '{secret_name}'")
        
        return resources
    except Exception as e:
        print(f"Error accessing resources for secret '{secret_name}': {str(e)}")
        return []

def process_key(region, key_data, compartment_data, vault_data, config, search_client):
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
            "region": region,
            "compartment_id": compartment_data.id,
            "compartment_name": compartment_data.name,
            "vault_id": vault_data.id,
            "vault_name": vault_data.display_name,
            "vault_management_endpoint": vault_data.management_endpoint,
            "vault_crypto_endpoint": vault_data.crypto_endpoint,
            "key_details": oci.util.to_dict(key_details),
            "key_versions": [oci.util.to_dict(version) for version in key_versions],
            "resources_using_key": [oci.util.to_dict(resource) for resource in resources_using_key],
            "encryption_type": determine_key_type(oci.util.to_dict(key_details)),
            "entity_type": "Encryption Key"
        }
        
        return key_entry
    except Exception as e:
        print(f"Error processing key {key_data.display_name if hasattr(key_data, 'display_name') else key_id}: {e}")
        return None

def process_secret(region, secret_data, compartment_data, vault_data, config, search_client):
    """Process a single secret and collect all its details"""
    try:
        secret_id = secret_data.id
        secret_name = secret_data.display_name
        
        # Get secret details
        secret_details = get_secret_details(
            config,
            secret_id,
            secret_name
        )
        
        if not secret_details:
            print(f"No details available for secret {secret_name}. Skipping.")
            return None
        
        # Find resources using this secret
        resources_using_secret = find_resources_using_secret(
            search_client,
            secret_id,
            secret_name
        )
        
        print(f"Secret {secret_name}: Found {len(resources_using_secret)} resources using this secret")
        
        # Create secret entry
        secret_entry = {
            "region": region,
            "compartment_id": compartment_data.id,
            "compartment_name": compartment_data.name,
            "vault_id": vault_data.id,
            "vault_name": vault_data.display_name,
            "key_details": {
                "display_name": secret_details.display_name,
                "id": secret_details.id,
                "lifecycle_state": secret_details.lifecycle_state,
                "time_created": secret_details.time_created.isoformat() if hasattr(secret_details.time_created, 'isoformat') else str(secret_details.time_created),
                "current_key_version": None,
                "algorithm": None,
                "protection_mode": None
            },
            "key_versions": [],
            "resources_using_key": [oci.util.to_dict(resource) for resource in resources_using_secret],
            "encryption_type": "Vault Secret",
            "entity_type": "VaultSecret"
        }
        
        return secret_entry
    except Exception as e:
        print(f"Error processing secret {secret_data.display_name if hasattr(secret_data, 'display_name') else secret_id}: {e}")
        return None

def generate_csv_report(results, output_file):
    """Generate CSV report from the collected results"""
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header with resource information columns and new Type column
        writer.writerow([
            "Region",
            "Compartment Name", 
            "Vault Name", 
            "Key Name", 
            "Key ID", 
            "Algorithm", 
            "Protection Mode", 
            "Current Key Version", 
            "State", 
            "Key Created Date",
            "Entity Type",
            "Encryption Type",
            "Resource Type",
            "Resource Name",
            "Resource ID",
            "Resource State"
        ])
        
        # Write data with resource details
        for key_entry in results:
            key_details = key_entry.get("key_details", {})
            resources = key_entry.get("resources_using_key", [])
            encryption_type = key_entry.get("encryption_type", "Unknown")
            entity_type = key_entry.get("entity_type", "Unknown")
            
            created_date = safe_parse_datetime(key_details.get("time_created", ""))
            
            # Common key information
            key_info = [
                key_entry.get("region", "Unknown"),
                key_entry.get("compartment_name", "Unknown"),
                key_entry.get("vault_name", "Unknown"),
                key_details.get("display_name", "Unknown"),
                key_details.get("id", "Unknown"),
                key_details.get("algorithm", "N/A"),
                key_details.get("protection_mode", "N/A"),
                key_details.get("current_key_version", "N/A"),
                key_details.get("lifecycle_state", "Unknown"),
                created_date,
                entity_type,
                encryption_type
            ]
            
            # If no resources found, write one row with empty resource fields
            if not resources:
                writer.writerow(key_info + ["No resources", "", "", ""])
            else:
                # Write a row for each resource using this key
                for resource in resources:
                    resource_type = resource.get("resource_type", "Unknown")
                    resource_name = resource.get("display_name", "No name")
                    resource_id = resource.get("identifier", "Unknown")
                    resource_state = resource.get("lifecycle_state", "Unknown")
                    
                    writer.writerow(key_info + [resource_type, resource_name, resource_id, resource_state])
    
    print(f"CSV report generated: {output_file}")

def process_region(region, config, compartment_id, max_workers, quiet):
    """Process a single region and return results"""
    # Copy config and update the region
    region_config = config.copy()
    region_config["region"] = region
    
    # Setup logging based on quiet mode
    def log_message(msg):
        if not quiet:
            print(f"[{region}] {msg}")
    
    # Initialize OCI clients for this region
    try:
        identity_client = oci.identity.IdentityClient(region_config)
        search_client = oci.resource_search.ResourceSearchClient(region_config)
        
        # Test the connection
        identity_client.list_regions()
    except Exception as e:
        print(f"[{region}] Error initializing OCI clients: {e}")
        print(f"[{region}] Skipping region.")
        return []
    
    # Get all compartments
    compartments = get_all_compartments(identity_client, compartment_id)
    log_message(f"Found {len(compartments)} compartments")
    
    # Results array for this region
    results = []
    
    # Track vaults and keys for progress reporting
    total_vaults = 0
    processed_vaults = 0
    
    # First count vaults
    for compartment in compartments:
        vaults = get_vaults_in_compartment(region_config, compartment.id, compartment.name)
        total_vaults += len(vaults)
    
    log_message(f"Found {total_vaults} vaults")
    
    # Process each compartment
    for compartment in compartments:
        log_message(f"Processing compartment: {compartment.name}")
        
        # Get vaults in compartment
        vaults = get_vaults_in_compartment(region_config, compartment.id, compartment.name)
        if not vaults:
            log_message(f"  No vaults found in {compartment.name}")
            continue
            
        log_message(f"  Found {len(vaults)} vaults in {compartment.name}")
        
        for vault in vaults:
            processed_vaults += 1
            vault_progress = (processed_vaults / total_vaults) * 100 if total_vaults > 0 else 0
            
            log_message(f"  Processing vault: {vault.display_name} ({processed_vaults}/{total_vaults}, {vault_progress:.1f}%)")
            
            # Process encryption keys
            if vault.management_endpoint:
                # Get keys in vault
                keys = get_keys_in_vault(
                    region_config,
                    compartment.id,
                    vault.id,
                    vault.management_endpoint,
                    vault.display_name
                )
                
                if keys:
                    log_message(f"    Found {len(keys)} encryption keys in vault {vault.display_name}")
                    
                    # Process each key using thread pool for better performance
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = {
                            executor.submit(
                                process_key, 
                                region,
                                key, 
                                compartment, 
                                vault,
                                region_config,
                                search_client
                            ): key.id for key in keys
                        }
                        
                        for future in as_completed(futures):
                            key_id = futures[future]
                            try:
                                key_entry = future.result()
                                if key_entry:
                                    results.append(key_entry)
                            except Exception as e:
                                print(f"    Error processing key {key_id}: {e}")
                else:
                    log_message(f"    No encryption keys found in vault {vault.display_name}")
            else:
                log_message(f"    No management endpoint available for vault {vault.display_name}. Skipping key processing.")
            
            # Process secrets in this vault
            try:
                secrets = get_vault_secrets(
                    region_config,
                    compartment.id,
                    vault.id,
                    vault.display_name
                )
                
                if secrets:
                    log_message(f"    Found {len(secrets)} secrets in vault {vault.display_name}")
                    
                    # Process each secret using thread pool for better performance
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = {
                            executor.submit(
                                process_secret, 
                                region,
                                secret, 
                                compartment, 
                                vault,
                                region_config,
                                search_client
                            ): secret.id for secret in secrets
                        }
                        
                        for future in as_completed(futures):
                            secret_id = futures[future]
                            try:
                                secret_entry = future.result()
                                if secret_entry:
                                    results.append(secret_entry)
                            except Exception as e:
                                print(f"    Error processing secret {secret_id}: {e}")
                else:
                    log_message(f"    No secrets found in vault {vault.display_name}")
            except Exception as e:
                log_message(f"    Error processing secrets in vault {vault.display_name}: {e}")
    
    return results

def main():
    parser = argparse.ArgumentParser(description='OCI Encryption Keys Multi-Region CSV Generator')
    parser.add_argument('--compartment-id', help='OCID of the compartment to search (default: root compartment)')
    parser.add_argument('--compartment-name', help='Name of the compartment to search (alternative to compartment-id)')
    parser.add_argument('--config-file', default='~/.oci/config', help='Path to OCI config file')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile to use')
    parser.add_argument('--regions', help='Comma-separated list of regions to scan (default: us-ashburn-1,us-phoenix-1)')
    parser.add_argument('--output-file', help='Output CSV file path (default: auto-generated with date suffix)')
    parser.add_argument('--max-workers', type=int, default=5, help='Maximum number of worker threads')
    parser.add_argument('--quiet', action='store_true', help='Minimize output messages')
    args = parser.parse_args()
    
    # Setup logging based on quiet mode
    def log_message(msg):
        if not args.quiet:
            print(msg)
    
    # Generate default output filename with date suffix if not specified
    if not args.output_file:
        date_suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output_file = f"./oci_encryption_keys_report_{date_suffix}.csv"
    
    # Expand user directory
    config_file = os.path.expanduser(args.config_file)
    output_file = os.path.expanduser(args.output_file)
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    # Set regions to scan
    if args.regions:
        regions_to_scan = [r.strip() for r in args.regions.split(',')]
    else:
        regions_to_scan = DEFAULT_REGIONS
    
    log_message(f"Starting OCI Encryption Keys Multi-Region CSV generator...")
    log_message(f"Using config file: {config_file}")
    log_message(f"Using profile: {args.profile}")
    log_message(f"Scanning regions: {', '.join(regions_to_scan)}")
    log_message(f"Output file will be saved to: {output_file}")
    
    # Load OCI config
    try:
        config = oci.config.from_file(config_file, args.profile)
    except Exception as e:
        print(f"Error loading OCI configuration: {e}")
        print("Please check your OCI configuration and permissions.")
        sys.exit(1)
    
    # Get tenancy ID from config
    tenancy_id = config.get('tenancy')
    log_message(f"Tenancy ID: {tenancy_id}")
    
    # Determine the compartment ID
    compartment_id = None
    compartment_name = None
    
    # If compartment name is provided, look up its ID
    if args.compartment_name:
        compartment_name = args.compartment_name
        log_message(f"Looking up compartment: {compartment_name}")
        
        # Need to create a client with a valid region first
        temp_config = config.copy()
        temp_config["region"] = regions_to_scan[0]
        identity_client = oci.identity.IdentityClient(temp_config)
        
        compartment_id = find_compartment_by_name(identity_client, tenancy_id, compartment_name)
        if not compartment_id:
            print("Error: Could not find compartment by name. Please check the name or use compartment ID instead.")
            sys.exit(1)
        log_message(f"Found compartment: {compartment_name} (ID: {compartment_id})")
    else:
        # Use the provided compartment ID or default to tenancy
        compartment_id = args.compartment_id
        if not compartment_id:
            compartment_id = tenancy_id
            log_message(f"No compartment specified, using root compartment")
    
    # Process each region
    start_time = time.time()
    combined_results = []
    
    for region in regions_to_scan:
        log_message(f"\nProcessing region: {region}")
        region_start_time = time.time()
        
        region_results = process_region(
            region,
            config,
            compartment_id,
            args.max_workers,
            args.quiet
        )
        
        region_time = time.time() - region_start_time
        log_message(f"Completed region {region}: Found {len(region_results)} keys in {region_time:.1f} seconds")
        
        combined_results.extend(region_results)
    
    # Generate CSV report with all results
    log_message(f"\nGenerating CSV report with combined results...")
    generate_csv_report(combined_results, output_file)
    
    # Summary
    total_time = time.time() - start_time
    print(f"\nSummary:")
    print(f"  Successfully processed {len(combined_results)} encryption keys/secrets across {len(regions_to_scan)} regions")
    print(f"  Total execution time: {total_time:.1f} seconds")
    print(f"  CSV report: {output_file}")
    print("Done!")

if __name__ == "__main__":
    main()