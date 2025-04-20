#!/usr/bin/env python3
"""
OCI Encryption Keys Analyzer
----------------------------
Extracts comprehensive information about encryption keys in OCI,
including vaults, master keys, key versions, and their usage.
"""

import oci
import argparse
import json
import datetime
import sys
import time
from concurrent.futures import ThreadPoolExecutor

def extract_key_details(config, compartment_id, include_key_versions=True, include_key_usage=True):
    """Extract detailed information about encryption keys in the specified compartment."""
    print(f"Analyzing encryption keys in compartment: {compartment_id}")
    
    # Initialize clients
    kms_vault_client = oci.key_management.KmsVaultClient(config)
    identity_client = oci.identity.IdentityClient(config)
    
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
            'vault_type': vault.vault_type if hasattr(vault, 'vault_type') else None,
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
                                    'lifecycle_state': version.lifecycle_state
                                }
                                key_details['key_versions'].append(version_details)
                                
                            print(f"    Found {len(versions)} versions for key {key.display_name}")
                        except Exception as e:
                            print(f"    Error retrieving versions for key {key.id}: {e}")
                    
                    # Get key usage if requested
                    if include_key_usage:
                        # We'll need to identify resources that use this key
                        # This requires checking various resource types
                        
                        # Create a Vault Client to check for usage in secrets
                        try:
                            vault_client = oci.vault.VaultsClient(config)
                            secrets = oci.pagination.list_call_get_all_results(
                                vault_client.list_secrets,
                                compartment_id
                            ).data
                            
                            # Find secrets using this key
                            for secret in secrets:
                                if secret.key_id == key.id:
                                    usage = {
                                        'resource_type': 'Secret',
                                        'resource_id': secret.id,
                                        'resource_name': secret.display_name if hasattr(secret, 'display_name') else 'Unnamed',
                                        'compartment_id': secret.compartment_id
                                    }
                                    key_details['key_usage'].append(usage)
                        except Exception as e:
                            print(f"    Error checking secret usage for key {key.id}: {e}")
                        
                        # Additional usage checks could be added here for:
                        # - Block volumes
                        # - Object Storage buckets
                        # - Autonomous Databases
                        # - File Storage
                        # - Etc.
                        
                        print(f"    Found {len(key_details['key_usage'])} resources using key {key.display_name}")
                    
                    vault_details['keys'].append(key_details)
            except Exception as e:
                print(f"  Error retrieving keys for vault {vault.id}: {e}")
        
        results['vaults'].append(vault_details)
    
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

def main():
    parser = argparse.ArgumentParser(description='Extract OCI encryption key information')
    parser.add_argument('--compartment-id', help='Compartment OCID to scan (defaults to tenancy)')
    parser.add_argument('--config', default='~/.oci/config', help='OCI config file')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile')
    parser.add_argument('--output', default='oci_keys.json', help='Output file path')
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
    
    # Save results to file
    try:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")
    except Exception as e:
        print(f"Error saving results: {e}")
    
    end_time = time.time()
    print(f"Completed in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()