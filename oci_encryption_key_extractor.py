#!/usr/bin/env python3
"""
OCI Encryption Key Extractor
----------------------------
Extracts detailed information about encryption keys and related resources in OCI.
This script focuses on KMS Vaults, Keys, Secrets, and encrypted resources.
"""

import oci
import sys
import argparse
import datetime
import json
import csv
import os
import time
from collections import defaultdict

# Replace with your actual tenancy ID
TENANCY_ID = "ocid1.tenancy.oc1..aaaaaaaxxxxxxxx"  # <-- REPLACE THIS WITH YOUR TENANCY OCID

def get_compartment_id_by_name(identity_client, compartment_name, parent_compartment_id=None, list_all=False):
    """Find a compartment ID by its name."""
    if parent_compartment_id is None:
        parent_compartment_id = TENANCY_ID
    
    print(f"Searching for compartment: '{compartment_name}'")
    
    try:
        # Get all compartments
        all_compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            parent_compartment_id,
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE"
        ).data
        
        # Add the tenancy as a possible compartment
        try:
            tenancy = identity_client.get_compartment(TENANCY_ID).data
            all_compartments.append(tenancy)
        except Exception as e:
            print(f"Could not get tenancy details: {e}")
                
    except Exception as e:
        print(f"Error listing compartments: {e}")
        return None
    
    # First, try to find an exact match (case-insensitive)
    exact_matches = [c for c in all_compartments if c.name.lower() == compartment_name.lower()]
    if exact_matches:
        match = exact_matches[0]
        print(f"Found exact match: {match.name} (ID: {match.id})")
        return match.id
    
    # If no exact match, look for partial matches
    partial_matches = [c for c in all_compartments if compartment_name.lower() in c.name.lower()]
    
    if not partial_matches:
        print(f"No compartment found with name '{compartment_name}'")
        return None
    
    if len(partial_matches) == 1:
        match = partial_matches[0]
        print(f"Found partial match: {match.name} (ID: {match.id})")
        return match.id
    
    # If multiple matches, let user choose
    print(f"Multiple compartments found matching '{compartment_name}':")
    for i, comp in enumerate(partial_matches):
        print(f"[{i+1}] {comp.name} (ID: {comp.id}, State: {comp.lifecycle_state})")
    
    choice = input("Enter the number of the compartment to use (or 'q' to quit): ")
    if choice.lower() == 'q':
        print("Exiting as requested.")
        sys.exit(0)
        
    try:
        index = int(choice) - 1
        if 0 <= index < len(partial_matches):
            return partial_matches[index].id
        else:
            print("Invalid choice. Please run the script again.")
            return None
    except ValueError:
        print("Invalid input. Please run the script again.")
        return None

def get_all_compartments(identity_client):
    """Get all compartments in the tenancy."""
    compartments = {}
    
    try:
        # Get the tenancy (root compartment)
        tenancy = identity_client.get_compartment(TENANCY_ID).data
        compartments[TENANCY_ID] = tenancy
        
        # Get all other compartments
        all_compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            TENANCY_ID,
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE",
            lifecycle_state="ACTIVE"
        ).data
        
        for compartment in all_compartments:
            compartments[compartment.id] = compartment
            
    except Exception as e:
        print(f"Error getting all compartments: {e}")
    
    return compartments

def extract_resource_details(resource, compartments=None):
    """Extract key details from a resource object."""
    details = {}
    
    # Common attributes to check
    common_attrs = [
        'id', 'display_name', 'name', 'lifecycle_state', 'time_created',
        'compartment_id', 'vault_id', 'key_id', 'current_key_version',
        'algorithm', 'length', 'protection_mode', 'curve_id',
        'crypto_endpoint', 'management_endpoint', 'restored_from_key_id',
        'is_primary_key', 'key_shape'
    ]
    
    # Extract common attributes
    for attr in common_attrs:
        if hasattr(resource, attr) and getattr(resource, attr) is not None:
            value = getattr(resource, attr)
            # Convert datetime objects to strings
            if isinstance(value, datetime.datetime):
                value = value.isoformat()
            details[attr] = value
    
    # Add compartment name if possible
    if compartments and hasattr(resource, 'compartment_id') and resource.compartment_id in compartments:
        details['compartment_name'] = compartments[resource.compartment_id].name
    
    # Extract freeform and defined tags if available
    if hasattr(resource, 'freeform_tags') and resource.freeform_tags:
        details['freeform_tags'] = resource.freeform_tags
        
    if hasattr(resource, 'defined_tags') and resource.defined_tags:
        # Flatten defined tags for easier reporting
        flattened_tags = {}
        for namespace, tags in resource.defined_tags.items():
            for key, value in tags.items():
                flattened_tags[f"{namespace}.{key}"] = value
        details['defined_tags'] = flattened_tags
    
    return details

def extract_vault_keys(config, vault, compartments):
    """
    Extract all keys and related details from a vault.
    
    Args:
        config: OCI configuration
        vault: Vault object
        compartments: Dictionary of compartment objects
        
    Returns:
        dict: Information about the vault and its keys
    """
    # Extract vault details
    vault_details = extract_resource_details(vault, compartments)
    vault_details['keys'] = []
    
    try:
        # Create a KMS Management client specifically for this vault
        management_endpoint = vault.management_endpoint
        kms_management_client = oci.key_management.KmsManagementClient(
            config, 
            service_endpoint=management_endpoint
        )
        
        # List all keys in the vault
        try:
            print(f"  Listing keys in vault {vault.display_name}...")
            keys = oci.pagination.list_call_get_all_results(
                kms_management_client.list_keys,
                compartment_id=vault.compartment_id
            ).data
            
            # Create a KMS crypto client for key usage operations
            try:
                crypto_endpoint = vault.crypto_endpoint
                kms_crypto_client = oci.key_management.KmsCryptoClient(
                    config,
                    service_endpoint=crypto_endpoint
                )
            except Exception as e:
                print(f"  Error creating crypto client for vault {vault.display_name}: {e}")
                kms_crypto_client = None
            
            # Process each key
            for i, key in enumerate(keys):
                print(f"    Processing key {i+1}/{len(keys)}: {key.display_name}")
                key_details = extract_resource_details(key, compartments)
                key_details['versions'] = []
                
                # Get key versions
                try:
                    versions = oci.pagination.list_call_get_all_results(
                        kms_management_client.list_key_versions,
                        key_id=key.id
                    ).data
                    
                    for version in versions:
                        version_details = extract_resource_details(version, compartments)
                        key_details['versions'].append(version_details)
                except Exception as e:
                    print(f"      Error getting versions for key {key.display_name}: {e}")
                
                # Get information about key usage - using the Vault client
                try:
                    vault_client = oci.vault.VaultsClient(config)
                    # Check if the key is used in any secrets
                    secrets = oci.pagination.list_call_get_all_results(
                        vault_client.list_secrets,
                        compartment_id=vault.compartment_id,
                        key_id=key.id
                    ).data
                    key_details['used_in_secrets'] = [extract_resource_details(secret, compartments) for secret in secrets]
                except Exception as e:
                    print(f"      Error getting secrets for key {key.display_name}: {e}")
                    key_details['used_in_secrets'] = []
                
                # Try to get resources encrypted with this key
                # This is complex and might require checking multiple services
                key_details['encrypted_resources'] = find_encrypted_resources(config, key, vault.compartment_id, compartments)
                
                vault_details['keys'].append(key_details)
        except Exception as e:
            print(f"  Error listing keys in vault {vault.display_name}: {e}")
    except Exception as e:
        print(f"  Error processing vault {vault.display_name}: {e}")
    
    return vault_details

def find_encrypted_resources(config, key, compartment_id, compartments):
    """
    Find resources encrypted with a specific key.
    This is a best-effort function as not all services expose this information directly.
    """
    encrypted_resources = []
    
    # Check Block Volumes
    try:
        block_storage_client = oci.core.BlockstorageClient(config)
        volumes = oci.pagination.list_call_get_all_results(
            block_storage_client.list_volumes,
            compartment_id=compartment_id
        ).data
        
        for volume in volumes:
            if hasattr(volume, 'kms_key_id') and volume.kms_key_id == key.id:
                resource = extract_resource_details(volume, compartments)
                resource['resource_type'] = 'block_volume'
                encrypted_resources.append(resource)
    except Exception as e:
        print(f"      Error checking block volumes: {e}")
    
    # Check Boot Volumes
    try:
        identity_client = oci.identity.IdentityClient(config)
        ads = oci.pagination.list_call_get_all_results(
            identity_client.list_availability_domains,
            compartment_id=compartment_id
        ).data
        
        for ad in ads:
            try:
                boot_volumes = oci.pagination.list_call_get_all_results(
                    block_storage_client.list_boot_volumes,
                    availability_domain=ad.name,
                    compartment_id=compartment_id
                ).data
                
                for volume in boot_volumes:
                    if hasattr(volume, 'kms_key_id') and volume.kms_key_id == key.id:
                        resource = extract_resource_details(volume, compartments)
                        resource['resource_type'] = 'boot_volume'
                        encrypted_resources.append(resource)
            except Exception as e:
                print(f"      Error checking boot volumes in AD {ad.name}: {e}")
    except Exception as e:
        print(f"      Error listing availability domains: {e}")
    
    # Check File Systems
    try:
        file_storage_client = oci.file_storage.FileStorageClient(config)
        for ad in ads:
            try:
                file_systems = oci.pagination.list_call_get_all_results(
                    file_storage_client.list_file_systems,
                    compartment_id=compartment_id,
                    availability_domain=ad.name
                ).data
                
                for fs in file_systems:
                    if hasattr(fs, 'kms_key_id') and fs.kms_key_id == key.id:
                        resource = extract_resource_details(fs, compartments)
                        resource['resource_type'] = 'file_system'
                        encrypted_resources.append(resource)
            except Exception as e:
                print(f"      Error checking file systems in AD {ad.name}: {e}")
    except Exception as e:
        print(f"      Error with file storage client: {e}")
    
    # Check Object Storage Buckets
    try:
        object_storage_client = oci.object_storage.ObjectStorageClient(config)
        namespace = object_storage_client.get_namespace().data
        
        buckets = oci.pagination.list_call_get_all_results(
            object_storage_client.list_buckets,
            namespace_name=namespace,
            compartment_id=compartment_id
        ).data
        
        for bucket in buckets:
            try:
                bucket_details = object_storage_client.get_bucket(
                    namespace_name=namespace,
                    bucket_name=bucket.name
                ).data
                
                if hasattr(bucket_details, 'kms_key_id') and bucket_details.kms_key_id == key.id:
                    resource = extract_resource_details(bucket_details, compartments)
                    resource['resource_type'] = 'bucket'
                    encrypted_resources.append(resource)
            except Exception as e:
                print(f"      Error checking bucket {bucket.name}: {e}")
    except Exception as e:
        print(f"      Error with object storage client: {e}")
    
    # Check Database Backups
    try:
        database_client = oci.database.DatabaseClient(config)
        
        # Check Autonomous Database backups
        try:
            adb_backups = oci.pagination.list_call_get_all_results(
                database_client.list_autonomous_database_backups,
                compartment_id=compartment_id
            ).data
            
            for backup in adb_backups:
                if hasattr(backup, 'kms_key_id') and backup.kms_key_id == key.id:
                    resource = extract_resource_details(backup, compartments)
                    resource['resource_type'] = 'autonomous_database_backup'
                    encrypted_resources.append(resource)
        except Exception as e:
            print(f"      Error checking autonomous database backups: {e}")
            
        # Check regular DB backups
        try:
            db_backups = oci.pagination.list_call_get_all_results(
                database_client.list_backups,
                compartment_id=compartment_id
            ).data
            
            for backup in db_backups:
                if hasattr(backup, 'kms_key_id') and backup.kms_key_id == key.id:
                    resource = extract_resource_details(backup, compartments)
                    resource['resource_type'] = 'database_backup'
                    encrypted_resources.append(resource)
        except Exception as e:
            print(f"      Error checking database backups: {e}")
    except Exception as e:
        print(f"      Error with database client: {e}")
    
    return encrypted_resources

def extract_encryption_keys(config, compartment_id, include_all_compartments=False):
    """
    Extract all encryption keys and related information from OCI.
    
    Args:
        config: OCI configuration
        compartment_id: The compartment to scan
        include_all_compartments: Whether to scan all compartments recursively
        
    Returns:
        dict: Information about all vaults, keys, and encrypted resources
    """
    # Initialize results structure
    results = {
        'scan_time': datetime.datetime.now().isoformat(),
        'compartment_id': compartment_id,
        'vaults': []
    }
    
    print("Getting all compartments...")
    identity_client = oci.identity.IdentityClient(config)
    compartments = get_all_compartments(identity_client)
    
    if compartment_id in compartments:
        results['compartment_name'] = compartments[compartment_id].name
    
    # Determine compartments to scan
    compartments_to_scan = []
    if include_all_compartments:
        print("Scanning all compartments recursively...")
        compartments_to_scan = list(compartments.keys())
    else:
        print(f"Scanning only the specified compartment: {results.get('compartment_name', compartment_id)}")
        compartments_to_scan = [compartment_id]
    
    print("Finding vaults...")
    kms_vault_client = oci.key_management.KmsVaultClient(config)
    
    # Track stats for summary
    total_vaults = 0
    total_keys = 0
    total_key_versions = 0
    total_secrets = 0
    total_encrypted_resources = 0
    
    # Process each compartment
    for comp_id in compartments_to_scan:
        try:
            # List vaults in this compartment
            vaults = oci.pagination.list_call_get_all_results(
                kms_vault_client.list_vaults,
                compartment_id=comp_id
            ).data
            
            if vaults:
                comp_name = compartments[comp_id].name if comp_id in compartments else "Unknown"
                print(f"Found {len(vaults)} vaults in compartment {comp_name}")
                
                # Process each vault
                for vault in vaults:
                    print(f"Processing vault: {vault.display_name}")
                    vault_details = extract_vault_keys(config, vault, compartments)
                    results['vaults'].append(vault_details)
                    
                    # Update stats
                    total_vaults += 1
                    total_keys += len(vault_details.get('keys', []))
                    
                    for key in vault_details.get('keys', []):
                        total_key_versions += len(key.get('versions', []))
                        total_secrets += len(key.get('used_in_secrets', []))
                        total_encrypted_resources += len(key.get('encrypted_resources', []))
            else:
                comp_name = compartments[comp_id].name if comp_id in compartments else "Unknown"
                print(f"No vaults found in compartment {comp_name}")
        except Exception as e:
            comp_name = compartments[comp_id].name if comp_id in compartments else comp_id
            print(f"Error scanning compartment {comp_name}: {e}")
    
    # Add summary to results
    results['summary'] = {
        'total_vaults': total_vaults,
        'total_keys': total_keys,
        'total_key_versions': total_key_versions,
        'total_secrets': total_secrets,
        'total_encrypted_resources': total_encrypted_resources
    }
    
    # Print summary to console
    print("\nEncryption Key Summary:")
    print("-" * 50)
    print(f"Total Vaults:             {total_vaults}")
    print(f"Total Keys:               {total_keys}")
    print(f"Total Key Versions:       {total_key_versions}")
    print(f"Total Secrets:            {total_secrets}")
    print(f"Total Encrypted Resources: {total_encrypted_resources}")
    print("-" * 50)
    
    return results

def save_to_json(results, output_file):
    """Save results to a JSON file."""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"Results saved to {output_file}")

def save_to_csv(results, output_dir):
    """Save results to CSV files."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create summary file
    summary_file = os.path.join(output_dir, "encryption_summary.csv")
    with open(summary_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Metric', 'Count'])
        for key, value in results['summary'].items():
            writer.writerow([key.replace('_', ' ').title(), value])
    
    # Create vaults file
    vaults_file = os.path.join(output_dir, "vaults.csv")
    with open(vaults_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Vault ID', 'Display Name', 'Compartment Name', 'State', 'Management Endpoint', 'Crypto Endpoint', 'Time Created', 'Key Count'])
        
        for vault in results['vaults']:
            writer.writerow([
                vault.get('id', ''),
                vault.get('display_name', ''),
                vault.get('compartment_name', ''),
                vault.get('lifecycle_state', ''),
                vault.get('management_endpoint', ''),
                vault.get('crypto_endpoint', ''),
                vault.get('time_created', ''),
                len(vault.get('keys', []))
            ])
    
    # Create keys file
    keys_file = os.path.join(output_dir, "keys.csv")
    with open(keys_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Key ID', 'Display Name', 'Vault Name', 'Vault ID', 'Algorithm', 
            'Length/Curve', 'State', 'Time Created', 'Current Version', 
            'Version Count', 'Secret Count', 'Encrypted Resource Count'
        ])
        
        for vault in results['vaults']:
            vault_name = vault.get('display_name', '')
            vault_id = vault.get('id', '')
            
            for key in vault.get('keys', []):
                protection_mode = ''
                if 'key_shape' in key and isinstance(key['key_shape'], dict):
                    protection_mode = key['key_shape'].get('protection_mode', '')
                
                # Determine key length or curve
                length_curve = ''
                if 'key_shape' in key and isinstance(key['key_shape'], dict):
                    if 'length' in key['key_shape']:
                        length_curve = key['key_shape']['length']
                    elif 'curve_id' in key['key_shape']:
                        length_curve = key['key_shape']['curve_id']
                
                # Get algorithm
                algorithm = ''
                if 'key_shape' in key and isinstance(key['key_shape'], dict):
                    algorithm = key['key_shape'].get('algorithm', '')
                
                writer.writerow([
                    key.get('id', ''),
                    key.get('display_name', ''),
                    vault_name,
                    vault_id,
                    algorithm,
                    length_curve,
                    key.get('lifecycle_state', ''),
                    key.get('time_created', ''),
                    key.get('current_key_version', ''),
                    len(key.get('versions', [])),
                    len(key.get('used_in_secrets', [])),
                    len(key.get('encrypted_resources', []))
                ])
    
    # Create encrypted resources file
    resources_file = os.path.join(output_dir, "encrypted_resources.csv")
    with open(resources_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Resource Type', 'Resource ID', 'Display Name', 'Compartment', 
            'State', 'Time Created', 'Key Name', 'Key ID', 'Vault Name'
        ])
        
        for vault in results['vaults']:
            vault_name = vault.get('display_name', '')
            
            for key in vault.get('keys', []):
                key_name = key.get('display_name', '')
                key_id = key.get('id', '')
                
                for resource in key.get('encrypted_resources', []):
                    writer.writerow([
                        resource.get('resource_type', ''),
                        resource.get('id', ''),
                        resource.get('display_name', resource.get('name', '')),
                        resource.get('compartment_name', ''),
                        resource.get('lifecycle_state', ''),
                        resource.get('time_created', ''),
                        key_name,
                        key_id,
                        vault_name
                    ])
    
    # Create key versions file
    versions_file = os.path.join(output_dir, "key_versions.csv")
    with open(versions_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Version ID', 'Key ID', 'Key Name', 'Vault Name',
            'Time Created', 'State', 'Is Current Version'
        ])
        
        for vault in results['vaults']:
            vault_name = vault.get('display_name', '')
            
            for key in vault.get('keys', []):
                key_name = key.get('display_name', '')
                key_id = key.get('id', '')
                current_version = key.get('current_key_version', '')
                
                for version in key.get('versions', []):
                    writer.writerow([
                        version.get('id', ''),
                        key_id,
                        key_name,
                        vault_name,
                        version.get('time_created', ''),
                        version.get('lifecycle_state', ''),
                        'Yes' if version.get('id', '') == current_version else 'No'
                    ])
    
    print(f"CSV files saved to {output_dir}")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Extract OCI encryption keys and related information')
    parser.add_argument('--compartment', '-c', required=True, help='Compartment name to scan')
    parser.add_argument('--config', default='~/.oci/config', help='OCI config file (default: ~/.oci/config)')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile (default: DEFAULT)')
    parser.add_argument('--output-format', choices=['json', 'csv'], default='json', 
                        help='Output format (default: json)')
    parser.add_argument('--output', help='Output file for JSON or directory for CSV')
    parser.add_argument('--all-compartments', action='store_true', 
                        help='Scan all compartments recursively')
    
    args = parser.parse_args()
    
    # Load OCI config
    try:
        config = oci.config.from_file(args.config, args.profile)
        oci.config.validate_config(config)
    except Exception as e:
        print(f"Error loading OCI config: {e}")
        sys.exit(1)
    
    # Create identity client
    identity_client = oci.identity.IdentityClient(config)
    
    # Get compartment ID from name
    compartment_id = get_compartment_id_by_name(identity_client, args.compartment)
    if not compartment_id:
        print("Could not find the specified compartment. Please check the name.")
        sys.exit(1)
    
    # Extract encryption keys
    start_time = time.time()
    print("Starting extraction of encryption keys...")
    results = extract_encryption_keys(config, compartment_id, args.all_compartments)
    end_time = time.time()
    print(f"Extraction completed in {end_time - start_time:.2f} seconds")
    
    # Determine default output file/directory if not specified
    if not args.output:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        if args.output_format == 'json':
            args.output = f"oci_encryption_keys_{timestamp}.json"
        else:
            args.output = f"oci_encryption_keys_{timestamp}"
    
    # Output results based on format
    if args.output_format == 'json':
        save_to_json(results, args.output)
    else:
        save_to_csv(results, args.output)

if __name__ == "__main__":
    main()