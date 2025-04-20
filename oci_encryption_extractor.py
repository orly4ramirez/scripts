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

# Define all required OCI services
from oci.key_management import KmsVaultClient, KmsManagementClient
from oci.identity import IdentityClient
from oci.resource_search import ResourceSearchClient
from oci.secrets import SecretsClient, SecretsClientCompositeOperations
from oci.vault import VaultsClient, VaultsClientCompositeOperations

# Default regions to scan
DEFAULT_REGIONS = ['us-ashburn-1', 'us-phoenix-1']

# Configure logging
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add global resource counter for statistics
resource_stats = {
    'encryption_keys': 0,
    'vault_secrets': 0,
    'resources_using_keys': 0,
    'resources_using_secrets': 0
}

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
        vaults_client = oci.vault.VaultsClient(config)
        
        # For better debugging
        logger.info(f"Searching for secrets in vault: {vault_name}")
        
        # List all secrets in the compartment that belong to this vault
        try:
            # Using list_secrets_by_compartment method which is the correct method name
            secrets_response = oci.pagination.list_call_get_all_results(
                secrets_client.list_secrets,
                compartment_id=compartment_id,
                vault_id=vault_id
            )
            logger.info(f"Found {len(secrets_response.data)} secrets in vault {vault_name} using SecretsClient")
            return secrets_response.data
        except AttributeError:
            # Try a different method name that might exist in the SDK
            try:
                logger.info(f"Trying alternative method list_secrets_by_compartment for vault {vault_name}")
                secrets_response = oci.pagination.list_call_get_all_results(
                    secrets_client.list_secrets_by_compartment,
                    compartment_id=compartment_id,
                    vault_id=vault_id
                )
                logger.info(f"Found {len(secrets_response.data)} secrets in vault {vault_name} using list_secrets_by_compartment")
                return secrets_response.data
            except AttributeError:
                # If both methods fail, try the vaults client
                logger.warning(f"Error with SecretsClient methods. Trying VaultsClient for vault {vault_name}")
                
        # Try using the Vaults client as fallback
        try:
            vault_secrets_response = oci.pagination.list_call_get_all_results(
                vaults_client.list_secrets,
                compartment_id,
                vault_id=vault_id
            )
            logger.info(f"Found {len(vault_secrets_response.data)} secrets in vault {vault_name} using VaultsClient")
            return vault_secrets_response.data
        except AttributeError:
            logger.warning(f"Error: VaultsClient also has no list_secrets method for vault {vault_name}")
    except Exception as e:
        # Improved error message with more details
        logger.error(f"Error retrieving secrets in vault {vault_name}: {str(e)}")
        return []

def get_secret_details(config, secret_id, secret_name="Unknown secret"):
    """Retrieve details for a specific secret"""
    try:
        # Create a client for secrets
        secrets_client = oci.secrets.SecretsClient(config)
        
        # Get secret details
        secret_response = secrets_client.get_secret(secret_id)
        
        # Try to get secret bundle as well (may have additional information)
        try:
            # Try to get the content of the secret if allowed
            secret_bundle = secrets_client.get_secret_bundle(secret_id)
            logger.info(f"Successfully retrieved secret bundle for {secret_name}")
            
            # Combine the information (but don't include the actual secret value)
            secret_data = secret_response.data
            # We could potentially add more metadata from the bundle here
            return secret_data
        except Exception as e:
            # If we can't get the bundle, just return the basic details
            logger.warning(f"Could not retrieve secret bundle for {secret_name}: {e}")
            return secret_response.data
    except Exception as e:
        # Improved error message
        logger.error(f"Error retrieving details for secret {secret_name} (ID: {secret_id}): {str(e)}")
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
    global resource_stats
    try:
        logger.info(f"Searching for resources using key: {key_name}")
        
        # Comprehensive search query to find encrypted resources and their associations
        search_text = f"""
            query all resources
            where (
                definedTags.contains('*.\"EncryptionKey\".*') ||
                definedTags.contains('*.kmsKeyId.*') ||
                definedTags.contains('*.\"KmsKeyId\".*') ||
                definedTags.contains('*.\"key_id\".*') ||
                definedTags.contains('*.\"master_key_id\".*') ||
                definedTags.contains('*.\"MasterEncryptionKey\".*') ||
                freeformTags.contains('*EncryptionKey*') ||
                freeformTags.contains('*encryption*') ||
                freeformTags.contains('*key_id*') ||
                freeformTags.contains('*kms*') ||
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
                (resourceType = 'Vault') ||
                (resourceType = 'ObjectStorageObject' && isEncrypted = 'true') ||
                (resourceType = 'AutonomousContainerDatabase' && isEncrypted = 'true') ||
                (resourceType = 'BackupDestination' && isEncrypted = 'true') ||
                (resourceType = 'BootVolumeBackup' && isEncrypted = 'true')
            )
        """
        
        # Create search details without the problematic 'limit' parameter
        search_details = oci.resource_search.models.StructuredSearchDetails(
            query=search_text,
            matching_context_type=oci.resource_search.models.SearchDetails.MATCHING_CONTEXT_TYPE_HIGHLIGHTS
        )
        
        search_response = search_client.search_resources(search_details)
        
        # Filter results to find resources that reference this key
        resources = []
        
        # More comprehensive matching algorithm
        for item in search_response.data.items:
            resource_dict = oci.util.to_dict(item)
            resource_json = json.dumps(resource_dict, default=str)
            
            # Check for the key_id in the resource JSON
            if key_id in resource_json:
                resources.append(item)
                continue
                
            # Check for key_id in defined tags (more thorough check)
            if "defined_tags" in resource_dict:
                for namespace, tags in resource_dict.get("defined_tags", {}).items():
                    for tag_key, tag_value in tags.items():
                        if isinstance(tag_value, str) and key_id in tag_value:
                            resources.append(item)
                            break
        
        resource_count = len(resources)
        if resource_count > 0:
            logger.info(f"Found {resource_count} resources using key '{key_name}'")
            resource_stats['resources_using_keys'] += resource_count
        else:
            logger.info(f"No resources found using key '{key_name}'")
        
        return resources
    except Exception as e:
        logger.error(f"Error searching for resources using key '{key_name}': {str(e)}")
        return []

def find_resources_using_secret(search_client, secret_id, secret_name="Unknown secret"):
    """Find resources that use a specific secret"""
    global resource_stats
    try:
        logger.info(f"Searching for resources using secret: {secret_name}")
        
        # Comprehensive search query for resources using secrets
        search_text = f"""
            query all resources
            where (
                definedTags.contains('*.\"SecretId\".*') ||
                definedTags.contains('*.\"secretId\".*') ||
                definedTags.contains('*.\"secret_id\".*') ||
                definedTags.contains('*.\"secretOcid\".*') ||
                freeformTags.contains('*secret*') ||
                freeformTags.contains('*Secret*') ||
                freeformTags.contains('*secretId*') ||
                freeformTags.contains('*SecretId*') ||
                (resourceType = 'ApiGateway') ||
                (resourceType = 'Function') ||
                (resourceType = 'FunctionsApplication') ||
                (resourceType = 'Instance') ||
                (resourceType = 'AutonomousDatabase') ||
                (resourceType = 'Database') ||
                (resourceType = 'DbSystem') ||
                (resourceType = 'Cluster') ||
                (resourceType = 'VmCluster') ||
                (resourceType = 'StreamPool') ||
                (resourceType = 'ContainerInstance') ||
                (resourceType = 'OkeCluster') ||
                (resourceType = 'DevOpsProject') ||
                (resourceType = 'IdentityProvider')
            )
        """
        
        # Create search details without the problematic 'limit' parameter
        search_details = oci.resource_search.models.StructuredSearchDetails(
            query=search_text,
            matching_context_type=oci.resource_search.models.SearchDetails.MATCHING_CONTEXT_TYPE_HIGHLIGHTS
        )
        
        search_response = search_client.search_resources(search_details)
        
        # Filter results to find resources that reference this secret
        resources = []
        
        # More comprehensive matching algorithm
        for item in search_response.data.items:
            resource_dict = oci.util.to_dict(item)
            resource_json = json.dumps(resource_dict, default=str)
            
            # Check for the secret_id in the resource JSON
            if secret_id in resource_json:
                resources.append(item)
                continue
                
            # Check for secret_id in defined tags (more thorough check)
            if "defined_tags" in resource_dict:
                for namespace, tags in resource_dict.get("defined_tags", {}).items():
                    for tag_key, tag_value in tags.items():
                        if isinstance(tag_value, str) and secret_id in tag_value:
                            resources.append(item)
                            break
        
        resource_count = len(resources)
        if resource_count > 0:
            logger.info(f"Found {resource_count} resources using secret '{secret_name}'")
            resource_stats['resources_using_secrets'] += resource_count
        else:
            logger.info(f"No resources found using secret '{secret_name}'")
        
        return resources
    except Exception as e:
        logger.error(f"Error searching for resources using secret '{secret_name}': {str(e)}")
        return []

def process_key(region, key_data, compartment_data, vault_data, config, search_client):
    """Process a single key and collect all its details"""
    global resource_stats
    try:
        key_id = key_data.id
        key_name = key_data.display_name
        management_endpoint = vault_data.management_endpoint
        
        logger.info(f"Processing encryption key: {key_name} (ID: {key_id})")
        
        # Get key details
        key_details = get_key_details(
            config,
            key_id,
            management_endpoint,
            key_name
        )
        
        if not key_details:
            logger.warning(f"No details available for key {key_name}. Skipping.")
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
        
        # Increment key counter
        resource_stats['encryption_keys'] += 1
        
        # Convert key details to dict for storage
        key_details_dict = oci.util.to_dict(key_details)
        
        # Create key entry
        key_entry = {
            "region": region,
            "compartment_id": compartment_data.id,
            "compartment_name": compartment_data.name,
            "vault_id": vault_data.id,
            "vault_name": vault_data.display_name,
            "vault_management_endpoint": vault_data.management_endpoint,
            "vault_crypto_endpoint": vault_data.crypto_endpoint,
            "key_details": key_details_dict,
            "key_versions": [oci.util.to_dict(version) for version in key_versions],
            "resources_using_key": [oci.util.to_dict(resource) for resource in resources_using_key],
            "encryption_type": determine_key_type(key_details_dict),
            "entity_type": "Encryption Key"
        }
        
        logger.info(f"Completed processing key: {key_name}")
        return key_entry
    except Exception as e:
        logger.error(f"Error processing key {key_data.display_name if hasattr(key_data, 'display_name') else 'Unknown'}: {e}")
        return None

def process_secret(region, secret_data, compartment_data, vault_data, config, search_client):
    """Process a single secret and collect all its details"""
    global resource_stats
    try:
        secret_id = secret_data.id
        secret_name = secret_data.display_name
        
        logger.info(f"Processing secret: {secret_name} (ID: {secret_id})")
        
        # Get secret details
        secret_details = get_secret_details(
            config,
            secret_id,
            secret_name
        )
        
        if not secret_details:
            logger.warning(f"No details available for secret {secret_name}. Skipping.")
            return None
        
        # Find resources using this secret
        resources_using_secret = find_resources_using_secret(
            search_client,
            secret_id,
            secret_name
        )
        
        # Increment secret counter
        resource_stats['vault_secrets'] += 1
        
        # Create secret entry that matches the key entry format for consistency in CSV
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
                "current_key_version": "N/A",  # Secrets don't have versions like keys
                "algorithm": "N/A",  # Secrets don't have algorithm
                "protection_mode": secret_details.key_id is not None and "Key-protected" or "N/A"  # Check if the secret is protected by a key
            },
            "key_versions": [],
            "resources_using_key": [oci.util.to_dict(resource) for resource in resources_using_secret],
            "encryption_type": "Vault Secret",
            "entity_type": "VaultSecret"
        }
        
        logger.info(f"Completed processing secret: {secret_name}")
        return secret_entry
    except Exception as e:
        logger.error(f"Error processing secret {secret_data.display_name if hasattr(secret_data, 'display_name') else 'Unknown'}: {e}")
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
    
    logger.info(f"CSV report generated: {output_file}")

def process_region(region, config, compartment_id, max_workers, quiet):
    """Process a single region and return results"""
    global resource_stats
    # Copy config and update the region
    region_config = config.copy()
    region_config["region"] = region
    
    # Setup logging based on quiet mode
    if quiet:
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.INFO)
    
    def log_message(msg):
        if not quiet:
            logger.info(f"[{region}] {msg}")
    
    # Initialize OCI clients for this region
    try:
        identity_client = oci.identity.IdentityClient(region_config)
        search_client = oci.resource_search.ResourceSearchClient(region_config)
        
        # Test the connection
        identity_client.list_regions()
        log_message("Successfully connected to region")
    except Exception as e:
        logger.error(f"[{region}] Error initializing OCI clients: {e}")
        logger.error(f"[{region}] Skipping region.")
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
                            ): (key.id, key.display_name) for key in keys  # Store both ID and name
                        }
                        
                        for future in as_completed(futures):
                            key_id, key_name = futures[future]  # Unpack both values
                            try:
                                key_entry = future.result()
                                if key_entry:
                                    results.append(key_entry)
                            except Exception as e:
                                logger.error(f"    Error processing key '{key_name}': {str(e)}")
                else:
                    log_message(f"    No encryption keys found in vault {vault.display_name}")
            else:
                log_message(f"    No management endpoint available for vault {vault.display_name}. Skipping key processing.")
            
            # Process secrets in this vault
            try:
                # Try both direct method and search method to find secrets
                secrets = get_vault_secrets(
                    region_config,
                    compartment.id,
                    vault.id,
                    vault.display_name
                )
                
                # Try a second method to find secrets if none were found with the first method
                if not secrets:
                    try:
                        log_message(f"    Trying alternate method to find secrets in vault {vault.display_name}")
                        
                        # Use the search client as a backup method - create search details without limit parameter
                        search_text = f"""
                            query VaultSecret resources
                            where (vaultId = '{vault.id}')
                        """
                        
                        search_details = oci.resource_search.models.StructuredSearchDetails(
                            query=search_text,
                            matching_context_type=oci.resource_search.models.SearchDetails.MATCHING_CONTEXT_TYPE_HIGHLIGHTS
                        )
                        
                        search_response = search_client.search_resources(search_details)
                        
                        # Convert search results to a format compatible with our processing
                        if search_response.data.items:
                            log_message(f"    Found {len(search_response.data.items)} secrets via search in vault {vault.display_name}")
                            
                            # We need to create secret-like objects from the search results
                            from types import SimpleNamespace
                            search_secrets = []
                            
                            for item in search_response.data.items:
                                # Create a simple object with id and display_name attributes
                                secret_obj = SimpleNamespace(
                                    id=item.identifier,
                                    display_name=item.display_name if hasattr(item, 'display_name') else "Unknown Secret",
                                    compartment_id=item.compartment_id,
                                    lifecycle_state=item.lifecycle_state if hasattr(item, 'lifecycle_state') else "UNKNOWN"
                                )
                                search_secrets.append(secret_obj)
                            
                            secrets = search_secrets
                    except Exception as search_e:
                        logger.warning(f"    Error using search method for secrets in vault {vault.display_name}: {str(search_e)}")
                
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
                            ): (getattr(secret, 'id', f"unknown-{id(secret)}"), 
                                getattr(secret, 'display_name', "Unknown Secret")) for secret in secrets
                        }
                        
                        for future in as_completed(futures):
                            secret_id, secret_name = futures[future]  # Unpack both values
                            try:
                                secret_entry = future.result()
                                if secret_entry:
                                    results.append(secret_entry)
                            except Exception as e:
                                logger.error(f"    Error processing secret '{secret_name}': {str(e)}")
                else:
                    log_message(f"    No secrets found in vault {vault.display_name}")
            except Exception as e:
                logger.error(f"    Error processing secrets in vault {vault.display_name}: {str(e)}")
    
    # Report region statistics
    log_message(f"Region processing complete:")
    log_message(f"  - Found {sum(1 for r in results if r.get('entity_type') == 'Encryption Key')} encryption keys")
    log_message(f"  - Found {sum(1 for r in results if r.get('entity_type') == 'VaultSecret')} vault secrets")
    
    resource_count = sum(len(r.get('resources_using_key', [])) for r in results)
    log_message(f"  - Found {resource_count} resources using encryption keys/secrets")
    
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
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.INFO)
    
    # Setup logging based on quiet mode
    def log_message(msg):
        if not args.quiet:
            logger.info(msg)
    
    # Reset the global resource stats
    global resource_stats
    resource_stats = {
        'encryption_keys': 0,
        'vault_secrets': 0,
        'resources_using_keys': 0,
        'resources_using_secrets': 0
    }
    
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
        logger.error(f"Error loading OCI configuration: {e}")
        logger.error("Please check your OCI configuration and permissions.")
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
            logger.error("Error: Could not find compartment by name. Please check the name or use compartment ID instead.")
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
        log_message(f"Completed region {region}: Found {len(region_results)} keys/secrets in {region_time:.1f} seconds")
        
        combined_results.extend(region_results)
    
    # Generate CSV report with all results
    log_message(f"\nGenerating CSV report with combined results...")
    generate_csv_report(combined_results, output_file)
    
    # Count entity types in results
    encryption_keys_count = sum(1 for r in combined_results if r.get('entity_type') == 'Encryption Key')
    vault_secrets_count = sum(1 for r in combined_results if r.get('entity_type') == 'VaultSecret')
    
    # Count resources using keys/secrets
    resources_count = sum(len(r.get('resources_using_key', [])) for r in combined_results)
    
    # Summary
    total_time = time.time() - start_time
    print(f"\nSummary:")
    print(f"  Successfully processed {len(combined_results)} encryption-related items across {len(regions_to_scan)} regions")
    print(f"    - {encryption_keys_count} encryption keys")
    print(f"    - {vault_secrets_count} vault secrets")
    print(f"  Found {resources_count} resources using these encryption items")
    print(f"  Total execution time: {total_time:.1f} seconds")
    print(f"  CSV report: {output_file}")
    
    # Provide additional guidance
    if vault_secrets_count == 0:
        print("\nNote: No VaultSecret resources were found. This could be due to:")
        print("  - No secrets exist in the scanned compartments")
        print("  - The user running this script doesn't have permission to view secrets")
        print("  - The OCI Vault Secrets service isn't being used in this tenancy")
    
    if resources_count == 0:
        print("\nNote: No resources were found using any encryption keys or secrets. This could be due to:")
        print("  - The resources are in compartments not being scanned")
        print("  - The search query needs to be expanded for your specific environment")
        print("  - Resources might be using encryption but not properly tagged or linked")
    
    print("Done!")

if __name__ == "__main__":
    main()