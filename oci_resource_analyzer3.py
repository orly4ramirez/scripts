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

# Resource types to check
RESOURCE_TYPES = [
    # Compute
    ('compute_instances', 'Compute instances'),
    ('dedicated_vm_hosts', 'Dedicated VM hosts'),
    ('instance_pools', 'Instance pools'),
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

def get_compartment_id_by_name(identity_client, compartment_name, parent_compartment_id=None):
    """
    Find a compartment ID by its name.
    Searches in the given parent compartment or tenancy root if no parent specified.
    """
    if parent_compartment_id is None:
        # Get tenancy ID as root compartment
        parent_compartment_id = identity_client.get_tenancy(identity_client.tenancy_id).data.id
    
    # List all compartments in the parent
    compartments = []
    try:
        compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            parent_compartment_id,
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE",
            lifecycle_state="ACTIVE"
        ).data
    except Exception as e:
        print(f"Error listing compartments: {e}")
        return None
    
    # Look for an exact match first
    for compartment in compartments:
        if compartment.name.lower() == compartment_name.lower():
            return compartment.id
    
    # If no exact match, look for partial matches
    matches = [c for c in compartments if compartment_name.lower() in c.name.lower()]
    
    if not matches:
        print(f"No compartment found with name '{compartment_name}'")
        return None
    
    if len(matches) == 1:
        return matches[0].id
    
    # If multiple matches, let user choose
    print(f"Multiple compartments found matching '{compartment_name}':")
    for i, comp in enumerate(matches):
        print(f"[{i+1}] {comp.name} (ID: {comp.id})")
    
    choice = input("Enter the number of the compartment to use: ")
    try:
        index = int(choice) - 1
        if 0 <= index < len(matches):
            return matches[index].id
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
        # Get tenancy ID
        tenancy_id = identity_client.get_tenancy(identity_client.tenancy_id).data.id
        
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
    print("Analyzing cross-compartment references...")
    
    # First, create a mapping of all resource IDs to their details
    resource_id_map = {}
    
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
    
    return resources_by_type

def get_resource_details(client_factory, compartment_id, resource_spec, compartments=None):
    """Get detailed information about resources of a specific type in the compartment."""
    resource_type, resource_display = resource_spec
    resources = []
    
    try:
        if resource_type == 'compute_instances':
            client = client_factory.create_client(oci.core.ComputeClient)
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
                    except:
                        pass
                resources.append(resource_details)
            
        elif resource_type == 'dedicated_vm_hosts':
            client = client_factory.create_client(oci.core.ComputeClient)
            hosts = oci.pagination.list_call_get_all_results(
                client.list_dedicated_vm_hosts, compartment_id
            ).data
            for host in hosts:
                resources.append(extract_resource_details(host, compartments))
            
        elif resource_type == 'instance_pools':
            client = client_factory.create_client(oci.core.ComputeClient)
            pools = oci.pagination.list_call_get_all_results(
                client.list_instance_pools, compartment_id
            ).data
            for pool in pools:
                resources.append(extract_resource_details(pool, compartments))
            
        elif resource_type == 'boot_volumes':
            client = client_factory.create_client(oci.core.BlockstorageClient)
            # Need to iterate through all ADs
            identity_client = client_factory.create_client(oci.identity.IdentityClient)
            ads = oci.pagination.list_call_get_all_results(
                identity_client.list_availability_domains, compartment_id
            ).data
            for ad in ads:
                volumes = oci.pagination.list_call_get_all_results(
                    client.list_boot_volumes, compartment_id, availability_domain=ad.name
                ).data
                for volume in volumes:
                    resources.append(extract_resource_details(volume, compartments))
            
        elif resource_type == 'block_volumes':
            client = client_factory.create_client(oci.core.BlockstorageClient)
            volumes = oci.pagination.list_call_get_all_results(
                client.list_volumes, compartment_id
            ).data
            for volume in volumes:
                resources.append(extract_resource_details(volume, compartments))
            
        elif resource_type == 'vcns':
            client = client_factory.create_client(oci.core.VirtualNetworkClient)
            vcns = oci.pagination.list_call_get_all_results(
                client.list_vcns, compartment_id
            ).data
            for vcn in vcns:
                resource_details = extract_resource_details(vcn, compartments)
                # Get CIDR blocks
                if hasattr(vcn, 'cidr_blocks'):
                    resource_details['cidr_blocks'] = vcn.cidr_blocks
                resources.append(resource_details)
            
        elif resource_type == 'subnets':
            client = client_factory.create_client(oci.core.VirtualNetworkClient)
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
            
        elif resource_type == 'security_lists':
            client = client_factory.create_client(oci.core.VirtualNetworkClient)
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
            
        elif resource_type == 'network_security_groups':
            client = client_factory.create_client(oci.core.VirtualNetworkClient)
            nsgs = oci.pagination.list_call_get_all_results(
                client.list_network_security_groups, compartment_id
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
            
        elif resource_type == 'load_balancers':
            client = client_factory.create_client(oci.load_balancer.LoadBalancerClient)
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
            
        elif resource_type == 'buckets':
            client = client_factory.create_client(oci.object_storage.ObjectStorageClient)
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
            
        elif resource_type == 'file_systems':
            client = client_factory.create_client(oci.file_storage.FileStorageClient)
            # Need ADs for file systems
            identity_client = client_factory.create_client(oci.identity.IdentityClient)
            ads = oci.pagination.list_call_get_all_results(
                identity_client.list_availability_domains, compartment_id
            ).data
            for ad in ads:
                file_systems = oci.pagination.list_call_get_all_results(
                    client.list_file_systems, compartment_id, availability_domain=ad.name
                ).data
                for fs in file_systems:
                    resources.append(extract_resource_details(fs, compartments))
            
        elif resource_type == 'db_systems':
            client = client_factory.create_client(oci.database.DatabaseClient)
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
            
        elif resource_type == 'autonomous_databases':
            client = client_factory.create_client(oci.database.DatabaseClient)
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
            
        elif resource_type == 'integration_instances':
            try:
                client = client_factory.create_client(oci.integration.IntegrationInstanceClient)
                instances = oci.pagination.list_call_get_all_results(
                    client.list_integration_instances, compartment_id
                ).data
                
                for instance in instances:
                    resource_details = extract_resource_details(instance, compartments)
                    resources.append(resource_details)
            except:
                # This service might not be available in all regions
                pass
            
        elif resource_type == 'api_gateways':
            try:
                client = client_factory.create_client(oci.apigateway.ApiGatewayClient)
                gateways = oci.pagination.list_call_get_all_results(
                    client.list_gateways, compartment_id
                ).data
                
                for gateway in gateways:
                    resource_details = extract_resource_details(gateway, compartments)
                    # Count deployments
                    try:
                        deployments = oci.pagination.list_call_get_all_results(
                            client.list_deployments, compartment_id, gateway_id=gateway.id
                        ).data
                        resource_details['deployment_count'] = len(deployments)
                    except:
                        pass
                    resources.append(resource_details)
            except:
                # This service might not be available in all regions
                pass
            
        elif resource_type == 'vaults':
            try:
                client = client_factory.create_client(oci.key_management.KmsVaultClient)
                vaults = oci.pagination.list_call_get_all_results(
                    client.list_vaults, compartment_id
                ).data
                
                for vault in vaults:
                    resource_details = extract_resource_details(vault, compartments)
                    resources.append(resource_details)
            except:
                # This service might not be available in all regions
                pass
            
        elif resource_type == 'secrets':
            try:
                client = client_factory.create_client(oci.vault.VaultsClient)
                secrets = oci.pagination.list_call_get_all_results(
                    client.list_secrets, compartment_id
                ).data
                
                for secret in secrets:
                    resource_details = extract_resource_details(secret, compartments)
                    # For secrets, add vault name if possible
                    if hasattr(secret, 'vault_id'):
                        try:
                            vault_client = client_factory.create_client(oci.key_management.KmsVaultClient)
                            vault = vault_client.get_vault(secret.vault_id).data
                            resource_details['vault_name'] = vault.display_name if hasattr(vault, 'display_name') else None
                        except:
                            pass
                    resources.append(resource_details)
            except:
                # This service might not be available in all regions
                pass
            
        elif resource_type == 'sftp_servers':
            # Try File Storage SFTP
            try:
                client = client_factory.create_client(oci.file_storage.FileStorageClient)
                servers = oci.pagination.list_call_get_all_results(
                    client.list_transfer_servers, compartment_id
                ).data
                
                for server in servers:
                    resource_details = extract_resource_details(server, compartments)
                    
                    # Get SFTP users
                    try:
                        users = oci.pagination.list_call_get_all_results(
                            client.list_transfer_users, compartment_id, transfer_server_id=server.id
                        ).data
                        resource_details['user_count'] = len(users)
                    except:
                        pass
                    
                    resources.append(resource_details)
            except:
                # Try Transfer service
                try:
                    client = client_factory.create_client(oci.transfer.TransferClient)
                    servers = oci.pagination.list_call_get_all_results(
                        client.list_transfer_servers, compartment_id
                    ).data
                    
                    for server in servers:
                        resources.append(extract_resource_details(server, compartments))
                except:
                    # This service might not be available in all regions
                    pass
                
    except Exception as e:
        print(f"Error getting {resource_display}: {e}")
        
    return (resource_type, resource_display, resources)

def scan_resources(config, compartment_id):
    """Scan all resources in the compartment and return details."""
    print(f"Scanning resources in compartment {compartment_id}...")
    
    # Create client factory
    try:
        # Try instance principals first
        client_factory = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        client_factory.get_security_token()
        print("Using instance principals authentication")
    except:
        # Fall back to config file
        client_factory = oci.config.from_file(config_file=config)
        print("Using config file authentication")
    
    # Get all compartments for cross-reference lookup
    identity_client = oci.identity.IdentityClient(config)
    compartments = get_all_compartments(identity_client)
    print(f"Found {len(compartments)} compartments in the tenancy")
    
    # Create a thread pool to scan resources in parallel
    results = {}
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(get_resource_details, client_factory, compartment_id, resource_spec, compartments): 
            resource_spec for resource_spec in RESOURCE_TYPES
        }
        
        for i, future in enumerate(as_completed(futures)):
            resource_spec = futures[future]
            try:
                resource_type, resource_display, resources = future.result()
                results[resource_type] = {
                    'display_name': resource_display,
                    'resources': resources,
                    'count': len(resources)
                }
                
                # Progress indicator
                print(f"Progress: {i+1}/{len(RESOURCE_TYPES)} resources checked", end="\r")
            except Exception as e:
                print(f"Error checking {resource_spec[1]}: {e}")
    
    # Analyze cross-compartment references
    results = find_cross_compartment_references(results, compartment_id, compartments)
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    print(f"\nCompleted scan in {elapsed:.2f} seconds")
    
    return results

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
    results = scan_resources(config, compartment_id)
    
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
    else:
        # Console output
        print("\nResource summary:")
        print("-" * 60)
        print(f"{'Resource Type':<40} {'Count':>10}")
        print("-" * 60)
        
        # Sort by count
        sorted_results = sorted(results.items(), key=lambda x: x[1]['count'], reverse=True)
        
        for resource_type, info in sorted_results:
            print(f"{info['display_name']:<40} {info['count']:>10}")
        
        # Print cross-compartment reference summary
        print_cross_compartment_summary(results, compartment_info)
        
        print("\nTo see detailed resource information, use --output-format json or csv")

if __name__ == "__main__":
    main()