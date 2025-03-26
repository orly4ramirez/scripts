#!/usr/bin/env python3
"""
OCI Resource Details Finder with Cross-Compartment References
------------------------------------------------------------
Lists all resources with detailed information in a specific OCI compartment,
including whether they are referenced from other compartments.
"""

import oci
import sys
import argparse
import datetime
import time
import json
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# Replace with your actual tenancy ID
TENANCY_ID = "ocid1.tenancy.oc1..aaaaaaaxxxxxxxx"  # <-- REPLACE THIS WITH YOUR TENANCY OCID

# Resource types to check - maintaining original list but fixing method issues
RESOURCE_TYPES = [
    # Compute
    ('compute_instances', 'Compute instances'),
    ('dedicated_vm_hosts', 'Dedicated VM hosts'),
    # Instance pools removed until correct method is determined
    # ('instance_pools', 'Instance pools'),
    ('boot_volumes', 'Boot volumes'),
    ('block_volumes', 'Block volumes'),
    
    # Networking
    ('vcns', 'Virtual Cloud Networks'),
    ('subnets', 'Subnets'),
    ('security_lists', 'Security lists'),
    ('network_security_groups', 'Network security groups'),
    ('load_balancers', 'Load balancers'),
    
    # Storage
    ('buckets', 'Object storage buckets'),
    ('file_systems', 'File systems'),
    
    # Database
    ('db_systems', 'DB systems'),
    ('autonomous_databases', 'Autonomous databases'),
    
    # Integration
    ('integration_instances', 'Integration Cloud instances'),
    ('api_gateways', 'API gateways'),
    
    # Security
    ('vaults', 'Vaults'),
    ('secrets', 'Secrets'),
    
    # SFTP
    ('sftp_servers', 'SFTP servers'),
]

# Attributes that commonly reference other resources
REFERENCE_ATTRIBUTES = [
    'subnet_id', 
    'vcn_id', 
    'compartment_id', 
    'source_id', 
    'target_id',
    'vault_id', 
    'database_id', 
    'instance_id', 
    'bucket_name',
    'network_security_group_id', 
    'key_id', 
    'load_balancer_id',
    'mount_target_id',
    'file_system_id',
    'image_id',
    'volume_id',
    'boot_volume_id',
    'drg_id',
    'route_table_id',
    'gateway_id'
]

def print_available_resource_types():
    """Print all available resource types that can be scanned."""
    print("\nAvailable resource types:")
    print("-" * 60)
    print(f"{'Resource Type ID':<30} {'Description':<40}")
    print("-" * 60)
    
    for resource_id, resource_name in sorted(RESOURCE_TYPES):
        print(f"{resource_id:<30} {resource_name:<40}")
        
    print("\nUsage example: --resource-type vcns")

def list_all_compartments(identity_client):
    """
    List all compartments in the tenancy with their names and IDs.
    Helps with debugging compartment name issues.
    """
    try:
        print("\nFetching all compartments in tenancy...")
        compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            TENANCY_ID,
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE"
        ).data
        
        # Get the root compartment (tenancy) as well
        try:
            tenancy = identity_client.get_compartment(TENANCY_ID).data
            compartments.append(tenancy)
        except Exception as e:
            print(f"Could not get tenancy details: {e}")
        
        # Sort compartments by name
        compartments.sort(key=lambda c: c.name.lower())
        
        print("\nAvailable compartments:")
        print("-" * 80)
        print(f"{'Compartment Name':<50} {'Compartment ID':<30} {'Status':<15}")
        print("-" * 80)
        
        for comp in compartments:
            print(f"{comp.name:<50} {comp.id:<30} {comp.lifecycle_state:<15}")
        
        return compartments
    except Exception as e:
        print(f"Error listing compartments: {e}")
        return []

def get_compartment_id_by_name(identity_client, compartment_name, parent_compartment_id=None, list_all=False):
    """
    Find a compartment ID by its name.
    Searches in the given parent compartment or tenancy root if no parent specified.
    
    Args:
        identity_client: OCI Identity client
        compartment_name: Name of compartment to find
        parent_compartment_id: ID of parent compartment to search in (optional)
        list_all: Whether to list all compartments for debugging (optional)
        
    Returns:
        str: Compartment OCID or None if not found
    """
    if parent_compartment_id is None:
        parent_compartment_id = TENANCY_ID
    
    print(f"Searching for compartment: '{compartment_name}'")
    
    # List all compartments if requested or if debugging
    if list_all:
        all_compartments = list_all_compartments(identity_client)
    else:
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
        print("Use the --list-compartments option to see all available compartments")
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
    """
    Get all compartments in the tenancy.
    
    Returns:
        dict: Dictionary mapping compartment IDs to compartment objects
    """
    compartments = {}
    
    try:
        # Use the hardcoded tenancy ID
        tenancy_id = TENANCY_ID
        
        # Get the tenancy (root compartment)
        tenancy = identity_client.get_compartment(tenancy_id).data
        compartments[tenancy_id] = tenancy
        
        # Get all other compartments
        all_compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            tenancy_id,
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
    """
    Extract key details from a resource object.
    
    Args:
        resource: An OCI resource object
        compartments: Dictionary of compartment objects (optional)
        
    Returns:
        dict: Dictionary with key resource details
    """
    details = {}
    
    # Common attributes to check
    common_attrs = [
        'id', 'display_name', 'name', 'lifecycle_state', 'time_created',
        'compartment_id', 'availability_domain', 'shape', 'size_in_gbs',
        'hostname', 'domain', 'size_in_mbs', 'ip_address', 'cidr_block',
        'vcn_id', 'subnet_id', 'public_ip', 'private_ip', 'status'
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
    
    # Initialize cross-compartment references
    details['referenced_from_compartments'] = []
    details['references_to_compartments'] = []
    
    return details

def find_cross_compartment_references(resources_by_type, target_compartment_id, compartments):
    """
    Find cross-compartment references for resources.
    
    Args:
        resources_by_type: Dictionary of resources organized by type
        target_compartment_id: ID of the compartment being analyzed
        compartments: Dictionary of all compartments by ID
        
    Returns:
        dict: Updated resources with cross-compartment reference information
    """
    print("Analyzing cross-compartment references...", end=' ')
    
    # First, create a mapping of all resource IDs to their details
    resource_id_map = {}
    
    # Track references by compartment
    inbound_compartments = {}
    outbound_compartments = {}
    total_inbound = 0
    total_outbound = 0
    
    for resource_type, info in resources_by_type.items():
        for resource in info['resources']:
            if 'id' in resource:
                resource_id_map[resource['id']] = {
                    'type': resource_type,
                    'details': resource,
                    'compartment_id': resource.get('compartment_id')
                }
    
    # Now check for references between resources
    for resource_type, info in resources_by_type.items():
        for resource in info['resources']:
            # Skip if resource doesn't have a compartment ID
            if 'compartment_id' not in resource:
                continue
                
            resource_compartment_id = resource['compartment_id']
            
            # Check if this resource references resources in other compartments
            for attr, value in resource.items():
                if attr in REFERENCE_ATTRIBUTES and isinstance(value, str) and value.startswith('ocid1.'):
                    # Check if this references a resource in another compartment
                    if value in resource_id_map:
                        referenced_resource = resource_id_map[value]
                        referenced_compartment_id = referenced_resource['compartment_id']
                        
                        if (referenced_compartment_id and 
                            referenced_compartment_id != resource_compartment_id):
                            
                            # Add outbound reference
                            if referenced_compartment_id not in resource.get('references_to_compartments', []):
                                reference_info = {
                                    'compartment_id': referenced_compartment_id,
                                    'compartment_name': compartments[referenced_compartment_id].name if referenced_compartment_id in compartments else "Unknown",
                                    'resource_type': referenced_resource['type'],
                                    'resource_id': value,
                                    'resource_name': referenced_resource['details'].get('display_name', 
                                                   referenced_resource['details'].get('name', 'Unnamed')),
                                    'reference_type': attr
                                }
                                resource.setdefault('references_to_compartments', []).append(reference_info)
                                
                                # Update outbound compartment tracking
                                comp_name = compartments[referenced_compartment_id].name if referenced_compartment_id in compartments else "Unknown"
                                outbound_compartments[comp_name] = outbound_compartments.get(comp_name, 0) + 1
                                total_outbound += 1
                            
                            # Add inbound reference to the referenced resource
                            ref_details = referenced_resource['details']
                            inbound_reference = {
                                'compartment_id': resource_compartment_id,
                                'compartment_name': compartments[resource_compartment_id].name if resource_compartment_id in compartments else "Unknown",
                                'resource_type': resource_type,
                                'resource_id': resource.get('id'),
                                'resource_name': resource.get('display_name', resource.get('name', 'Unnamed')),
                                'reference_type': attr
                            }
                            ref_details.setdefault('referenced_from_compartments', []).append(inbound_reference)
                            
                            # Update inbound compartment tracking
                            comp_name = compartments[resource_compartment_id].name if resource_compartment_id in compartments else "Unknown"
                            inbound_compartments[comp_name] = inbound_compartments.get(comp_name, 0) + 1
                            total_inbound += 1
    
    # Report cross-compartment references
    if total_inbound > 0 or total_outbound > 0:
        print(f"Found {total_inbound} inbound and {total_outbound} outbound cross-compartment references")
        
        if inbound_compartments:
            print("  Referenced from compartments:")
            for comp_name, count in sorted(inbound_compartments.items(), key=lambda x: x[1], reverse=True):
                print(f"    - {comp_name}: {count} references")
                
        if outbound_compartments:
            print("  References to compartments:")
            for comp_name, count in sorted(outbound_compartments.items(), key=lambda x: x[1], reverse=True):
                print(f"    - {comp_name}: {count} references")
    else:
        print("No cross-compartment references found")
    
    return resources_by_type

def get_resource_details(config, compartment_id, resource_spec, compartments=None):
    """Get detailed information about resources of a specific type in the compartment."""
    resource_type, resource_display = resource_spec
    resources = []
    
    # Print the resource type being scanned
    print(f"Scanning {resource_display}...", end=" ")
    
    try:
        if resource_type == 'compute_instances':
            client = oci.core.ComputeClient(config)
            instances = oci.pagination.list_call_get_all_results(
                client.list_instances, compartment_id
            ).data
            for instance in instances:
                resource_details = extract_resource_details(instance, compartments)
                # Get additional compute-specific details
                if hasattr(instance, 'shape'):
                    try:
                        shape_details = client.get_compute_image_capability_schema(instance.image_id).data
                        resource_details['shape_details'] = extract_resource_details(shape_details, compartments)
                    except Exception as e:
                        # Silently handle errors getting shape details
                        pass
                resources.append(resource_details)
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'dedicated_vm_hosts':
            client = oci.core.ComputeClient(config)
            hosts = oci.pagination.list_call_get_all_results(
                client.list_dedicated_vm_hosts, compartment_id
            ).data
            for host in hosts:
                resources.append(extract_resource_details(host, compartments))
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'boot_volumes':
            client = oci.core.BlockstorageClient(config)
            # Need to iterate through all ADs
            identity_client = oci.identity.IdentityClient(config)
            ads = oci.pagination.list_call_get_all_results(
                identity_client.list_availability_domains, compartment_id
            ).data
            
            for ad in ads:
                # Fix - use named parameters
                volumes = oci.pagination.list_call_get_all_results(
                    client.list_boot_volumes,
                    availability_domain=ad.name,
                    compartment_id=compartment_id
                ).data
                for volume in volumes:
                    resources.append(extract_resource_details(volume, compartments))
            
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'block_volumes':
            client = oci.core.BlockstorageClient(config)
            # Fix - use named parameters
            volumes = oci.pagination.list_call_get_all_results(
                client.list_volumes,
                compartment_id=compartment_id
            ).data
            for volume in volumes:
                resources.append(extract_resource_details(volume, compartments))
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'vcns':
            client = oci.core.VirtualNetworkClient(config)
            vcns = oci.pagination.list_call_get_all_results(
                client.list_vcns, compartment_id
            ).data
            for vcn in vcns:
                resource_details = extract_resource_details(vcn, compartments)
                # Get CIDR blocks
                if hasattr(vcn, 'cidr_blocks'):
                    resource_details['cidr_blocks'] = vcn.cidr_blocks
                resources.append(resource_details)
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'subnets':
            client = oci.core.VirtualNetworkClient(config)
            subnets = oci.pagination.list_call_get_all_results(
                client.list_subnets, compartment_id
            ).data
            for subnet in subnets:
                resource_details = extract_resource_details(subnet, compartments)
                # Add VCN name if possible
                if hasattr(subnet, 'vcn_id'):
                    try:
                        vcn = client.get_vcn(subnet.vcn_id).data
                        resource_details['vcn_name'] = vcn.display_name if hasattr(vcn, 'display_name') else None
                    except:
                        pass
                resources.append(resource_details)
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'security_lists':
            client = oci.core.VirtualNetworkClient(config)
            security_lists = oci.pagination.list_call_get_all_results(
                client.list_security_lists, compartment_id
            ).data
            for sl in security_lists:
                resource_details = extract_resource_details(sl, compartments)
                # Summarize ingress and egress rules
                if hasattr(sl, 'ingress_security_rules'):
                    resource_details['ingress_rule_count'] = len(sl.ingress_security_rules)
                if hasattr(sl, 'egress_security_rules'):
                    resource_details['egress_rule_count'] = len(sl.egress_security_rules)
                resources.append(resource_details)
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'network_security_groups':
            client = oci.core.VirtualNetworkClient(config)
            # Fix - use named parameters
            nsgs = oci.pagination.list_call_get_all_results(
                client.list_network_security_groups,
                compartment_id=compartment_id
            ).data
            for nsg in nsgs:
                resource_details = extract_resource_details(nsg, compartments)
                # Get NSG rules count
                try:
                    rules = oci.pagination.list_call_get_all_results(
                        client.list_network_security_group_security_rules, 
                        network_security_group_id=nsg.id
                    ).data
                    resource_details['rule_count'] = len(rules)
                except:
                    pass
                resources.append(resource_details)
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'load_balancers':
            client = oci.load_balancer.LoadBalancerClient(config)
            lbs = oci.pagination.list_call_get_all_results(
                client.list_load_balancers, compartment_id
            ).data
            for lb in lbs:
                resource_details = extract_resource_details(lb, compartments)
                # Add backend set and listener counts
                if hasattr(lb, 'backend_sets'):
                    resource_details['backend_set_count'] = len(lb.backend_sets)
                if hasattr(lb, 'listeners'):
                    resource_details['listener_count'] = len(lb.listeners)
                resources.append(resource_details)
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'buckets':
            client = oci.object_storage.ObjectStorageClient(config)
            namespace = client.get_namespace().data
            buckets = oci.pagination.list_call_get_all_results(
                client.list_buckets, namespace, compartment_id
            ).data
            
            for bucket in buckets:
                # Get detailed bucket info
                try:
                    bucket_details = client.get_bucket(namespace, bucket.name).data
                    resource_details = extract_resource_details(bucket_details, compartments)
                    resources.append(resource_details)
                except:
                    # Fall back to basic info
                    resources.append(extract_resource_details(bucket, compartments))
                    
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'file_systems':
            client = oci.file_storage.FileStorageClient(config)
            # Need ADs for file systems
            identity_client = oci.identity.IdentityClient(config)
            ads = oci.pagination.list_call_get_all_results(
                identity_client.list_availability_domains, compartment_id
            ).data
            for ad in ads:
                file_systems = oci.pagination.list_call_get_all_results(
                    client.list_file_systems, compartment_id, availability_domain=ad.name
                ).data
                for fs in file_systems:
                    resources.append(extract_resource_details(fs, compartments))
                    
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'db_systems':
            client = oci.database.DatabaseClient(config)
            db_systems = oci.pagination.list_call_get_all_results(
                client.list_db_systems, compartment_id
            ).data
            for db in db_systems:
                resource_details = extract_resource_details(db, compartments)
                # Add DB home and database counts
                if hasattr(db, 'db_home'):
                    resource_details['db_home'] = db.db_home
                    try:
                        db_homes = oci.pagination.list_call_get_all_results(
                            client.list_db_homes, compartment_id, db_system_id=db.id
                        ).data
                        resource_details['db_home_count'] = len(db_homes)
                        
                        # Get databases
                        db_count = 0
                        for home in db_homes:
                            try:
                                databases = oci.pagination.list_call_get_all_results(
                                    client.list_databases, compartment_id, db_home_id=home.id
                                ).data
                                db_count += len(databases)
                            except:
                                pass
                        resource_details['database_count'] = db_count
                    except:
                        pass
                resources.append(resource_details)
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'autonomous_databases':
            client = oci.database.DatabaseClient(config)
            adbs = oci.pagination.list_call_get_all_results(
                client.list_autonomous_databases, compartment_id
            ).data
            for adb in adbs:
                resource_details = extract_resource_details(adb, compartments)
                # Add ADB specific details
                for attr in ['db_name', 'db_workload', 'db_version', 'cpu_core_count', 'data_storage_size_in_tbs']:
                    if hasattr(adb, attr):
                        resource_details[attr] = getattr(adb, attr)
                resources.append(resource_details)
                
            if resources:
                print(f"Found {len(resources)} {resource_display}")
            else:
                print(f"No {resource_display} found")
            
        elif resource_type == 'integration_instances':
            try:
                client = oci.integration.IntegrationInstanceClient(config)
                instances = oci.pagination.list_call_get_all_results(
                    client.list_integration_instances, compartment_id
                ).data
                
                for instance in instances:
                    resource_details = extract_resource_details(instance, compartments)
                    resources.append(resource_details)
                    
                if resources:
                    print(f"Found {len(resources)} {resource_display}")
                else:
                    print(f"No {resource_display} found")
            except Exception as e:
                print(f"Error: {str(e)}")
            
        elif resource_type == 'api_gateways':
            try:
                # Try different API method names until we find the right one
                client = oci.apigateway.ApiGatewayClient(config)
                try:
                    # Try the most likely method names
                    gateways = oci.pagination.list_call_get_all_results(
                        client.list_api_gateways, compartment_id
                    ).data
                except AttributeError:
                    try:
                        # Maybe it's this one
                        gateways = oci.pagination.list_call_get_all_results(
                            client.list_gateways, compartment_id
                        ).data
                    except AttributeError:
                        # Try one more
                        gateways = oci.pagination.list_call_get_all_results(
                            client.list_apis, compartment_id
                        ).data
                
                for gateway in gateways:
                    resource_details = extract_resource_details(gateway, compartments)
                    # Count deployments - skip this since we don't know the right method
                    resources.append(resource_details)
                    
                if resources:
                    print(f"Found {len(resources)} {resource_display}")
                else:
                    print(f"No {resource_display} found")
            except Exception as e:
                print(f"Error: {str(e)}")
            
        elif resource_type == 'vaults':
            try:
                client = oci.key_management.KmsVaultClient(config)
                vaults = oci.pagination.list_call_get_all_results(
                    client.list_vaults, compartment_id
                ).data
                
                for vault in vaults:
                    resource_details = extract_resource_details(vault, compartments)
                    resources.append(resource_details)
                    
                if resources:
                    print(f"Found {len(resources)} {resource_display}")
                else:
                    print(f"No {resource_display} found")
            except Exception as e:
                print(f"Error: {str(e)}")
            
        elif resource_type == 'secrets':
            try:
                client = oci.vault.VaultsClient(config)
                secrets = oci.pagination.list_call_get_all_results(
                    client.list_secrets, compartment_id
                ).data
                
                for secret in secrets:
                    resource_details = extract_resource_details(secret, compartments)
                    # For secrets, add vault name if possible
                    if hasattr(secret, 'vault_id'):
                        try:
                            vault_client = oci.key_management.KmsVaultClient(config)
                            vault = vault_client.get_vault(secret.vault_id).data
                            resource_details['vault_name'] = vault.display_name if hasattr(vault, 'display_name') else None
                        except:
                            pass
                    resources.append(resource_details)
                    
                if resources:
                    print(f"Found {len(resources)} {resource_display}")
                else:
                    print(f"No {resource_display} found")
            except Exception as e:
                print(f"Error: {str(e)}")
            
        elif resource_type == 'sftp_servers':
            # Try File Storage SFTP
            try:
                # Don't try to use oci.transfer, use file_storage instead
                client = oci.file_storage.FileStorageClient(config)
                
                # See if it has transfer-related methods
                if hasattr(client, 'list_transfer_servers'):
                    servers = oci.pagination.list_call_get_all_results(
                        client.list_transfer_servers, compartment_id
                    ).data
                    
                    for server in servers:
                        resource_details = extract_resource_details(server, compartments)
                        
                        # Get SFTP users if the method exists
                        if hasattr(client, 'list_transfer_users'):
                            try:
                                users = oci.pagination.list_call_get_all_results(
                                    client.list_transfer_users, compartment_id, transfer_server_id=server.id
                                ).data
                                resource_details['user_count'] = len(users)
                            except:
                                pass
                        
                        resources.append(resource_details)
                else:
                    # Method not available in this version
                    print("SFTP transfer methods not available")
                
                if resources:
                    print(f"Found {len(resources)} {resource_display}")
                else:
                    print(f"No {resource_display} found")
            except Exception as e:
                print(f"Error: {str(e)}")
                
    except Exception as e:
        print(f"Error: {str(e)}")
        
    return (resource_type, resource_display, resources)

def scan_resources(config, compartment_id, resource_type_filter=None):
    """Scan resources in the compartment and return details."""
    print(f"Scanning resources in compartment {compartment_id}...")
    
    # Get all compartments for cross-reference lookup
    identity_client = oci.identity.IdentityClient(config)
    compartments = get_all_compartments(identity_client)
    print(f"Found {len(compartments)} compartments in the tenancy")
    
    # Filter resource types if requested
    if resource_type_filter:
        resource_types_to_scan = [(rt, rd) for rt, rd in RESOURCE_TYPES if rt == resource_type_filter]
        if not resource_types_to_scan:
            print(f"Error: Resource type '{resource_type_filter}' not found.")
            print_available_resource_types()
            sys.exit(1)
        print(f"Filtering to scan only: {resource_types_to_scan[0][1]}")
    else:
        resource_types_to_scan = RESOURCE_TYPES
    
    # Create a thread pool to scan resources in parallel
    results = {}
    start_time = time.time()
    
    print("\nBeginning resource scan...")
    
    # Using sequential scanning for better visibility
    for resource_spec in resource_types_to_scan:
        try:
            resource_type, resource_display, resources = get_resource_details(
                config, compartment_id, resource_spec, compartments
            )
            results[resource_type] = {
                'display_name': resource_display,
                'resources': resources,
                'count': len(resources)
            }
        except Exception as e:
            print(f"Error scanning {resource_spec[1]}: {e}")
    
    # Analyze cross-compartment references
    results = find_cross_compartment_references(results, compartment_id, compartments)
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    print(f"\nCompleted scan in {elapsed:.2f} seconds")
    
    return results

def print_resource_summary(results):
    """Print a summary of all resources found during the scan."""
    print("\nResource Summary:")
    print("-" * 80)
    print(f"{'Resource Type':<40} {'Count':>10} {'Referenced From':>15} {'References To':>15}")
    print("-" * 80)
    
    total_count = 0
    total_referenced_from = 0
    total_references_to = 0
    
    # Sort by resource display name
    for resource_type, info in sorted(results.items(), key=lambda x: x[1]['display_name']):
        count = len(info['resources'])
        total_count += count
        
        # Count cross-compartment references
        refs_from = 0
        refs_to = 0
        
        for resource in info['resources']:
            if resource.get('referenced_from_compartments'):
                refs_from += len(resource.get('referenced_from_compartments'))
            if resource.get('references_to_compartments'):
                refs_to += len(resource.get('references_to_compartments'))
        
        total_referenced_from += refs_from
        total_references_to += refs_to
        
        print(f"{info['display_name']:<40} {count:>10} {refs_from:>15} {refs_to:>15}")
    
    print("-" * 80)
    print(f"{'TOTAL':.<40} {total_count:>10} {total_referenced_from:>15} {total_references_to:>15}")
    print("-" * 80)

def save_to_json(results, compartment_info, output_file):
    """Save results to a JSON file."""
    output = {
        'scan_time': datetime.datetime.now().isoformat(),
        'compartment': compartment_info,
        'resources': results
    }
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    
    print(f"Results saved to {output_file}")

def save_to_csv(results, compartment_info, output_dir):
    """Save results to CSV files."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create a summary file
    summary_file = os.path.join(output_dir, "resource_summary.csv")
    with open(summary_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Resource Type', 'Count', 'Referenced From Other Compartments', 'References To Other Compartments'])
        
        for resource_type, info in results.items():
            # Count cross-compartment references
            refs_from = 0
            refs_to = 0
            
            for resource in info['resources']:
                if resource.get('referenced_from_compartments'):
                    refs_from += 1
                if resource.get('references_to_compartments'):
                    refs_to += 1
            
            writer.writerow([
                info['display_name'], 
                info['count'],
                refs_from,
                refs_to
            ])
    
    # Create detailed files for each resource type
    for resource_type, info in results.items():
        if not info['resources']:
            continue
            
        # Create a CSV file for this resource type
        resource_file = os.path.join(output_dir, f"{resource_type}.csv")
        
        # Get basic fields from all resources
        basic_fields = set()
        for resource in info['resources']:
            for key in resource.keys():
                if key not in ['referenced_from_compartments', 'references_to_compartments']:
                    basic_fields.add(key)
        
        # Sort fields for consistent output
        sorted_fields = sorted(basic_fields)
        
        # Add reference columns
        all_fields = sorted_fields + [
            'referenced_from_compartments_count',
            'referenced_from_compartments_details',
            'references_to_compartments_count',
            'references_to_compartments_details'
        ]
        
        with open(resource_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_fields)
            writer.writeheader()
            
            for resource in info['resources']:
                # Prepare row with basic fields
                row = {field: resource.get(field, None) for field in sorted_fields}
                
                # Add cross-compartment reference information
                from_refs = resource.get('referenced_from_compartments', [])
                to_refs = resource.get('references_to_compartments', [])
                
                row['referenced_from_compartments_count'] = len(from_refs)
                row['references_to_compartments_count'] = len(to_refs)
                
                # Format reference details as strings
                if from_refs:
                    refs_detail = []
                    for ref in from_refs:
                        refs_detail.append(f"{ref.get('compartment_name', 'Unknown')} ({ref.get('resource_type', 'Unknown')})")
                    row['referenced_from_compartments_details'] = '; '.join(refs_detail)
                
                if to_refs:
                    refs_detail = []
                    for ref in to_refs:
                        refs_detail.append(f"{ref.get('compartment_name', 'Unknown')} ({ref.get('resource_type', 'Unknown')})")
                    row['references_to_compartments_details'] = '; '.join(refs_detail)
                
                writer.writerow(row)
    
    # Create a specific file for cross-compartment references
    refs_file = os.path.join(output_dir, "cross_compartment_references.csv")
    with open(refs_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Resource Type', 'Resource Name', 'Resource ID',
            'Reference Type', 'Direction',
            'Related Compartment', 'Related Resource Type', 'Related Resource Name'
        ])
        
        for resource_type, info in results.items():
            for resource in info['resources']:
                # Add inbound references
                for ref in resource.get('referenced_from_compartments', []):
                    writer.writerow([
                        resource_type,
                        resource.get('display_name', resource.get('name', 'Unnamed')),
                        resource.get('id', 'Unknown'),
                        ref.get('reference_type', 'Unknown'),
                        'Inbound',
                        ref.get('compartment_name', 'Unknown'),
                        ref.get('resource_type', 'Unknown'),
                        ref.get('resource_name', 'Unknown')
                    ])
                
                # Add outbound references
                for ref in resource.get('references_to_compartments', []):
                    writer.writerow([
                        resource_type,
                        resource.get('display_name', resource.get('name', 'Unnamed')),
                        resource.get('id', 'Unknown'),
                        ref.get('reference_type', 'Unknown'),
                        'Outbound',
                        ref.get('compartment_name', 'Unknown'),
                        ref.get('resource_type', 'Unknown'),
                        ref.get('resource_name', 'Unknown')
                    ])
    
    print(f"CSV files saved to {output_dir}")

def print_cross_compartment_summary(results, compartment_info):
    """Print a summary of cross-compartment references to the console."""
    print("\nCross-Compartment Reference Summary:")
    print("-" * 80)
    print(f"{'Resource Type':<25} {'Referenced From':<15} {'References To':<15}")
    print("-" * 80)
    
    total_inbound = 0
    total_outbound = 0
    
    for resource_type, info in sorted(results.items(), key=lambda x: x[1]['display_name']):
        # Count cross-compartment references
        refs_from = 0
        refs_to = 0
        
        for resource in info['resources']:
            if resource.get('referenced_from_compartments'):
                refs_from += len(resource.get('referenced_from_compartments'))
            if resource.get('references_to_compartments'):
                refs_to += len(resource.get('references_to_compartments'))
        
        if refs_from > 0 or refs_to > 0:
            print(f"{info['display_name']:<25} {refs_from:<15} {refs_to:<15}")
            total_inbound += refs_from
            total_outbound += refs_to
    
    print("-" * 80)
    print(f"{'TOTAL':<25} {total_inbound:<15} {total_outbound:<15}")
    
    if total_inbound == 0 and total_outbound == 0:
        print("\nNo cross-compartment references found.")
    else:
        print("\nUse --output-format json or csv for detailed reference information")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Find OCI resource details by compartment name')
    parser.add_argument('--compartment', '-c', required=True, help='Compartment name to scan')
    parser.add_argument('--config', default='~/.oci/config', help='OCI config file (default: ~/.oci/config)')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile (default: DEFAULT)')
    parser.add_argument('--output-format', choices=['json', 'csv', 'console'], default='console', 
                        help='Output format (default: console)')
    parser.add_argument('--output', help='Output file for JSON or directory for CSV')
    parser.add_argument('--list-compartments', action='store_true', 
                        help='List all available compartments before scanning')
    parser.add_argument('--resource-type', 
                        help='Scan only a specific resource type (e.g., compute_instances, vcns, buckets)')
    parser.add_argument('--list-resource-types', action='store_true',
                        help='List all available resource types that can be scanned')
    
    args = parser.parse_args()
    
    # List resource types if requested
    if args.list_resource_types:
        print_available_resource_types()
        sys.exit(0)
    
    # Special case for "help" as resource type
    if args.resource_type and args.resource_type.lower() == 'help':
        print_available_resource_types()
        sys.exit(0)
    
    # Load OCI config
    try:
        config = oci.config.from_file(args.config, args.profile)
        oci.config.validate_config(config)
    except Exception as e:
        print(f"Error loading OCI config: {e}")
        sys.exit(1)
    
    # Create identity client
    identity_client = oci.identity.IdentityClient(config)
    
    # List all compartments if requested
    if args.list_compartments:
        list_all_compartments(identity_client)
        
    # Get compartment ID from name
    compartment_id = get_compartment_id_by_name(identity_client, args.compartment, list_all=args.list_compartments)
    if not compartment_id:
        print("\nTips for finding your compartment:")
        print("1. Use the --list-compartments option to see all available compartments")
        print("2. Check for case sensitivity issues in the compartment name")
        print("3. Verify the compartment name in the OCI console")
        print("4. Make sure your OCI config has permission to access the compartment")
        sys.exit(1)
    
    # Get compartment details
    compartment_info = {}
    try:
        compartment = identity_client.get_compartment(compartment_id).data
        compartment_info = {
            'id': compartment.id,
            'name': compartment.name,
            'description': compartment.description,
            'lifecycle_state': compartment.lifecycle_state
        }
        print(f"Scanning compartment: {compartment.name} (ID: {compartment.id})")
    except Exception as e:
        print(f"Error getting compartment details: {e}")
        sys.exit(1)
    
    # Scan resources
    results = scan_resources(config, compartment_id, args.resource_type)
    
    # Print resource summary
    print_resource_summary(results)
    
    # Determine default output file/directory if not specified
    if args.output_format in ['json', 'csv'] and not args.output:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        if args.output_format == 'json':
            args.output = f"oci_resources_{timestamp}.json"
        else:
            args.output = f"oci_resources_{timestamp}"
    
    # Output results based on format
    if args.output_format == 'json':
        save_to_json(results, compartment_info, args.output)
    elif args.output_format == 'csv':
        save_to_csv(results, compartment_info, args.output)
    
    print("\nTo see detailed resource information, use --output-format json or csv")

if __name__ == "__main__":
    main()