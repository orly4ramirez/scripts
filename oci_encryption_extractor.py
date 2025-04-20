#!/usr/bin/env python3
"""
OCI Encryption Keys Analyzer
----------------------------
Extracts comprehensive information about encryption keys in OCI,
including vaults, master keys, key versions, and their usage.
Can output to JSON or CSV format.
"""

import oci
import argparse
import json
import csv
import datetime
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor

def extract_key_details(config, compartment_id, include_key_versions=True, include_key_usage=True):
    """Extract detailed information about encryption keys in the specified compartment."""
    print(f"Analyzing encryption keys in compartment: {compartment_id}")
    
    # Initialize clients
    kms_vault_client = oci.key_management.KmsVaultClient(config)
    identity_client = oci.identity.IdentityClient(config)
    vault_client = oci.vault.VaultsClient(config)
    
    # Get compartment details for better reporting
    try:
        compartment = identity_client.get_compartment(compartment_id).data
        compartment_name = compartment.name
        print(f"Compartment name: {compartment_name}")
    except:
        compartment_name = "Unknown"
        print("Could not retrieve compartment name")
    
    # Get all vaults in the compartment
    try:
        vaults = oci.pagination.list_call_get_all_results(
            kms_vault_client.list_vaults,
            compartment_id
        ).data
        print(f"Found {len(vaults)} vaults")
    except Exception as e:
        print(f"Error retrieving vaults: {e}")
        return None
    
    # Initialize results structure
    results = {
        'compartment_id': compartment_id,
        'compartment_name': compartment_name,
        'scan_time': datetime.datetime.now().isoformat(),
        'vaults': []
    }
    
    # Get all secrets in the compartment
    all_secrets = []
    try:
        secrets = oci.pagination.list_call_get_all_results(
            vault_client.list_secrets,
            compartment_id
        ).data
        all_secrets = secrets
        print(f"Found {len(secrets)} secrets in compartment")
    except Exception as e:
        print(f"Error retrieving secrets: {e}")
    
    # For each vault, get detailed information
    for vault in vaults:
        print(f"Processing vault: {vault.display_name} (ID: {vault.id})")
        
        vault_details = {
            'id': vault.id,
            'name': vault.display_name,
            'lifecycle_state': vault.lifecycle_state,
            'crypto_endpoint': vault.crypto_endpoint,
            'management_endpoint': vault.management_endpoint,
            'time_created': vault.time_created.isoformat() if vault.time_created else None,
            'vault_type': vault.vault_type if hasattr(vault, 'vault_type') else "DEFAULT",
            'keys': []
        }
        
        # Only get keys if the vault is active
        if vault.lifecycle_state == "ACTIVE":
            try:
                # Create management client for this vault
                kms_management_client = oci.key_management.KmsManagementClient(
                    config, 
                    service_endpoint=vault.management_endpoint
                )
                
                # Get all keys in the vault
                keys = oci.pagination.list_call_get_all_results(
                    kms_management_client.list_keys,
                    compartment_id
                ).data
                print(f"  Found {len(keys)} keys in vault {vault.display_name}")
                
                # For each key, get detailed information
                for key in keys:
                    key_details = {
                        'id': key.id,
                        'name': key.display_name,
                        'algorithm': key.algorithm,
                        'length': key.length,
                        'protection_mode': key.protection_mode,
                        'type': 'MASTER_KEY',
                        'lifecycle_state': key.lifecycle_state,
                        'time_created': key.time_created.isoformat() if key.time_created else None,
                        'key_versions': [],
                        'key_usage': []
                    }
                    
                    # Get key versions if requested
                    if include_key_versions and key.lifecycle_state == "ENABLED":
                        try:
                            versions = oci.pagination.list_call_get_all_results(
                                kms_management_client.list_key_versions,
                                key.id
                            ).data
                            
                            for version in versions:
                                version_details = {
                                    'id': version.id,
                                    'time_created': version.time_created.isoformat() if version.time_created else None,
                                    'lifecycle_state': version.lifecycle_state,
                                    'type': 'KEY_VERSION'
                                }
                                key_details['key_versions'].append(version_details)
                                
                            print(f"    Found {len(versions)} versions for key {key.display_name}")
                        except Exception as e:
                            print(f"    Error retrieving versions for key {key.id}: {e}")
                    
                    # Get key usage if requested
                    if include_key_usage:
                        # Check for usage in secrets
                        for secret in all_secrets:
                            if hasattr(secret, 'key_id') and secret.key_id == key.id:
                                usage = {
                                    'resource_type': 'Secret',
                                    'resource_id': secret.id,
                                    'resource_name': secret.display_name if hasattr(secret, 'display_name') else 'Unnamed',
                                    'compartment_id': secret.compartment_id
                                }
                                key_details['key_usage'].append(usage)
                        
                        # Check for Block Volumes using this key
                        try:
                            block_storage_client = oci.core.BlockstorageClient(config)
                            volumes = oci.pagination.list_call_get_all_results(
                                block_storage_client.list_volumes,
                                compartment_id
                            ).data
                            
                            for volume in volumes:
                                if hasattr(volume, 'kms_key_id') and volume.kms_key_id == key.id:
                                    usage = {
                                        'resource_type': 'BlockVolume',
                                        'resource_id': volume.id,
                                        'resource_name': volume.display_name,
                                        'compartment_id': volume.compartment_id
                                    }
                                    key_details['key_usage'].append(usage)
                        except Exception as e:
                            print(f"    Error checking Block Volume usage for key {key.id}: {e}")
                        
                        # Check for Object Storage buckets using this key
                        try:
                            object_storage_client = oci.object_storage.ObjectStorageClient(config)
                            namespace = object_storage_client.get_namespace().data
                            buckets = oci.pagination.list_call_get_all_results(
                                object_storage_client.list_buckets,
                                namespace_name=namespace,
                                compartment_id=compartment_id
                            ).data
                            
                            for bucket in buckets:
                                bucket_details = object_storage_client.get_bucket(
                                    namespace_name=namespace,
                                    bucket_name=bucket.name
                                ).data
                                
                                if hasattr(bucket_details, 'kms_key_id') and bucket_details.kms_key_id == key.id:
                                    usage = {
                                        'resource_type': 'ObjectStorageBucket',
                                        'resource_id': f"{namespace}/{bucket.name}",
                                        'resource_name': bucket.name,
                                        'compartment_id': bucket.compartment_id
                                    }
                                    key_details['key_usage'].append(usage)
                        except Exception as e:
                            print(f"    Error checking Object Storage usage for key {key.id}: {e}")
                        
                        # Check for File Storage systems using this key
                        try:
                            file_storage_client = oci.file_storage.FileStorageClient(config)
                            file_systems = oci.pagination.list_call_get_all_results(
                                file_storage_client.list_file_systems,
                                compartment_id
                            ).data
                            
                            for fs in file_systems:
                                if hasattr(fs, 'kms_key_id') and fs.kms_key_id == key.id:
                                    usage = {
                                        'resource_type': 'FileSystem',
                                        'resource_id': fs.id,
                                        'resource_name': fs.display_name,
                                        'compartment_id': fs.compartment_id
                                    }
                                    key_details['key_usage'].append(usage)
                        except Exception as e:
                            print(f"    Error checking File Storage usage for key {key.id}: {e}")
                        
                        # Check for Autonomous Databases using this key
                        try:
                            database_client = oci.database.DatabaseClient(config)
                            autonomous_dbs = oci.pagination.list_call_get_all_results(
                                database_client.list_autonomous_databases,
                                compartment_id
                            ).data
                            
                            for adb in autonomous_dbs:
                                if hasattr(adb, 'kms_key_id') and adb.kms_key_id == key.id:
                                    usage = {
                                        'resource_type': 'AutonomousDatabase',
                                        'resource_id': adb.id,
                                        'resource_name': adb.display_name,
                                        'compartment_id': adb.compartment_id
                                    }
                                    key_details['key_usage'].append(usage)
                        except Exception as e:
                            print(f"    Error checking Autonomous Database usage for key {key.id}: {e}")
                        
                        print(f"    Found {len(key_details['key_usage'])} resources using key {key.display_name}")
                    
                    vault_details['keys'].append(key_details)
            except Exception as e:
                print(f"  Error retrieving keys for vault {vault.id}: {e}")
        
        results['vaults'].append(vault_details)
    
    # Get all Vault Secrets and include them in results even if they're not associated with a specific vault
    secrets_details = []
    for secret in all_secrets:
        try:
            # Get secret bundle to check if it's accessible and get additional details
            secret_bundle = vault_client.get_secret_bundle(
                secret.id,
                stage="CURRENT"
            ).data
            
            # Only add if we could get the bundle (confirms it's accessible)
            secret_details = {
                'id': secret.id,
                'name': secret.display_name,
                'type': 'VAULT_SECRET',
                'lifecycle_state': secret.lifecycle_state,
                'time_created': secret.time_created.isoformat() if hasattr(secret, 'time_created') and secret.time_created else None,
                'key_id': secret.key_id if hasattr(secret, 'key_id') else None,
                'vault_id': secret.vault_id if hasattr(secret, 'vault_id') else None,
                'secret_content_type': secret_bundle.secret_bundle_content.content_type if hasattr(secret_bundle, 'secret_bundle_content') else None
            }
            secrets_details.append(secret_details)
        except Exception as e:
            # If we can't access the secret, just capture basic info
            secret_details = {
                'id': secret.id,
                'name': secret.display_name if hasattr(secret, 'display_name') else 'Unknown',
                'type': 'VAULT_SECRET',
                'lifecycle_state': secret.lifecycle_state if hasattr(secret, 'lifecycle_state') else 'Unknown',
                'key_id': secret.key_id if hasattr(secret, 'key_id') else None,
                'vault_id': secret.vault_id if hasattr(secret, 'vault_id') else None,
                'error': str(e)
            }
            secrets_details.append(secret_details)
    
    # Add secrets to results
    results['secrets'] = secrets_details
    print(f"Added {len(secrets_details)} vault secrets to results")
    
    return results

def extract_encryption_keys_recursive(config, compartment_id, include_child_compartments=False):
    """Extract encryption keys from the specified compartment and optionally its children."""
    results = {}
    
    # Get keys in the specified compartment
    compartment_results = extract_key_details(config, compartment_id)
    if compartment_results:
        results[compartment_id] = compartment_results
    
    # If requested, get keys in child compartments
    if include_child_compartments:
        identity_client = oci.identity.IdentityClient(config)
        try:
            # Get child compartments
            child_compartments = oci.pagination.list_call_get_all_results(
                identity_client.list_compartments,
                compartment_id
            ).data
            
            if child_compartments:
                print(f"\nFound {len(child_compartments)} child compartments. Scanning recursively...")
                
                for child in child_compartments:
                    if child.lifecycle_state == "ACTIVE":
                        print(f"\nScanning child compartment: {child.name} (ID: {child.id})")
                        child_results = extract_key_details(config, child.id)
                        if child_results:
                            results[child.id] = child_results
        except Exception as e:
            print(f"Error retrieving child compartments: {e}")
    
    return results

def export_to_csv(results, output_file):
    """Export the encryption key results to CSV format."""
    if not results:
        print("No results to export")
        return
    
    # Flatten the results for CSV output
    flat_records = []
    
    for compartment_id, compartment_data in results.items():
        compartment_name = compartment_data.get('compartment_name', 'Unknown')
        
        # Process vaults and keys
        for vault in compartment_data.get('vaults', []):
            # Add vault record
            vault_record = {
                'Compartment Name': compartment_name,
                'Compartment ID': compartment_id,
                'Resource Type': 'Vault',
                'Encryption Type': vault.get('vault_type', 'DEFAULT'),
                'Resource Name': vault.get('name', 'Unknown'),
                'Resource ID': vault.get('id', 'Unknown'),
                'Key ID': 'N/A',
                'Lifecycle State': vault.get('lifecycle_state', 'Unknown'),
                'Time Created': vault.get('time_created', 'Unknown'),
                'Resource Using Key': 'N/A',
                'Using Resource ID': 'N/A',
                'Using Resource Name': 'N/A'
            }
            flat_records.append(vault_record)
            
            # Process keys in vault
            for key in vault.get('keys', []):
                # Add key record
                key_record = {
                    'Compartment Name': compartment_name,
                    'Compartment ID': compartment_id,
                    'Resource Type': 'Master Key',
                    'Encryption Type': key.get('algorithm', 'Unknown') + '-' + str(key.get('length', '')),
                    'Resource Name': key.get('name', 'Unknown'),
                    'Resource ID': key.get('id', 'Unknown'),
                    'Key ID': key.get('id', 'Unknown'),
                    'Lifecycle State': key.get('lifecycle_state', 'Unknown'),
                    'Time Created': key.get('time_created', 'Unknown'),
                    'Resource Using Key': 'N/A',
                    'Using Resource ID': 'N/A',
                    'Using Resource Name': 'N/A'
                }
                flat_records.append(key_record)
                
                # Add key version records
                for version in key.get('key_versions', []):
                    version_record = {
                        'Compartment Name': compartment_name,
                        'Compartment ID': compartment_id,
                        'Resource Type': 'Key Version',
                        'Encryption Type': key.get('algorithm', 'Unknown') + '-' + str(key.get('length', '')),
                        'Resource Name': key.get('name', 'Unknown') + ' (Version)',
                        'Resource ID': version.get('id', 'Unknown'),
                        'Key ID': key.get('id', 'Unknown'),
                        'Lifecycle State': version.get('lifecycle_state', 'Unknown'),
                        'Time Created': version.get('time_created', 'Unknown'),
                        'Resource Using Key': 'N/A',
                        'Using Resource ID': 'N/A',
                        'Using Resource Name': 'N/A'
                    }
                    flat_records.append(version_record)
                
                # Add resource usage records
                for usage in key.get('key_usage', []):
                    usage_record = {
                        'Compartment Name': compartment_name,
                        'Compartment ID': usage.get('compartment_id', compartment_id),
                        'Resource Type': 'Key Usage',
                        'Encryption Type': key.get('algorithm', 'Unknown') + '-' + str(key.get('length', '')),
                        'Resource Name': key.get('name', 'Unknown'),
                        'Resource ID': key.get('id', 'Unknown'),
                        'Key ID': key.get('id', 'Unknown'),
                        'Lifecycle State': key.get('lifecycle_state', 'Unknown'),
                        'Time Created': key.get('time_created', 'Unknown'),
                        'Resource Using Key': usage.get('resource_type', 'Unknown'),
                        'Using Resource ID': usage.get('resource_id', 'Unknown'),
                        'Using Resource Name': usage.get('resource_name', 'Unknown')
                    }
                    flat_records.append(usage_record)
        
        # Process secrets
        for secret in compartment_data.get('secrets', []):
            secret_record = {
                'Compartment Name': compartment_name,
                'Compartment ID': compartment_id,
                'Resource Type': 'VaultSecret',
                'Encryption Type': 'Secret',
                'Resource Name': secret.get('name', 'Unknown'),
                'Resource ID': secret.get('id', 'Unknown'),
                'Key ID': secret.get('key_id', 'N/A'),
                'Lifecycle State': secret.get('lifecycle_state', 'Unknown'),
                'Time Created': secret.get('time_created', 'Unknown'),
                'Resource Using Key': 'Secret',
                'Using Resource ID': secret.get('id', 'Unknown'),
                'Using Resource Name': secret.get('name', 'Unknown')
            }
            flat_records.append(secret_record)
    
    # Write to CSV
    if flat_records:
        try:
            # Get all possible fields
            all_fields = set()
            for record in flat_records:
                all_fields.update(record.keys())
            
            # Use consistent field order for CSV
            fieldnames = [
                'Compartment Name', 'Compartment ID', 'Resource Type', 'Encryption Type',
                'Resource Name', 'Resource ID', 'Key ID', 'Lifecycle State', 'Time Created',
                'Resource Using Key', 'Using Resource ID', 'Using Resource Name'
            ]
            
            # Add any additional fields
            for field in sorted(all_fields):
                if field not in fieldnames:
                    fieldnames.append(field)
            
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(flat_records)
            
            print(f"Exported {len(flat_records)} records to {output_file}")
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
    else:
        print("No records to export to CSV")

def main():
    parser = argparse.ArgumentParser(description='Extract OCI encryption key information')
    parser.add_argument('--compartment-id', help='Compartment OCID to scan (defaults to tenancy)')
    parser.add_argument('--config', default='~/.oci/config', help='OCI config file')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile')
    parser.add_argument('--output', default='oci_keys.json', help='Output file path for JSON')
    parser.add_argument('--csv-output', help='Output file path for CSV (default: no CSV output)')
    parser.add_argument('--include-children', action='store_true', help='Scan child compartments')
    parser.add_argument('--no-versions', action='store_true', help='Skip key version details')
    parser.add_argument('--no-usage', action='store_true', help='Skip key usage details')
    
    args = parser.parse_args()
    
    # Load OCI config
    try:
        config = oci.config.from_file(args.config, args.profile)
        oci.config.validate_config(config)
    except Exception as e:
        print(f"Error loading OCI config: {e}")
        sys.exit(1)
    
    # If no compartment ID specified, use the tenancy from config
    compartment_id = args.compartment_id
    if not compartment_id:
        try:
            # Get tenancy ID from config
            compartment_id = config['tenancy']
            print(f"No compartment ID specified, using tenancy: {compartment_id}")
        except KeyError:
            print("Error: No compartment ID specified and tenancy ID not found in config")
            sys.exit(1)
    
    start_time = time.time()
    
    # Extract encryption key information
    results = extract_encryption_keys_recursive(
        config,
        compartment_id,
        include_child_compartments=args.include_children,
    )
    
    # Save results to JSON file
    try:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nJSON results saved to {args.output}")
    except Exception as e:
        print(f"Error saving JSON results: {e}")
    
    # Export to CSV if requested
    if args.csv_output:
        export_to_csv(results, args.csv_output)
    
    end_time = time.time()
    print(f"Completed in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()