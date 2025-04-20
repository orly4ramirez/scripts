#!/usr/bin/env python3
"""
OCI Tenancy Explorer (Direct API Approach)

This script extracts all resources from a specified OCI compartment (including child compartments)
using direct API calls and outputs detailed information to a CSV file.

Usage: python oci_tenancy_explorer_direct.py --compartment-name "your-compartment-name" [--output-file "output.csv"] [--recursive]
"""

import oci
import csv
import sys
import os
import argparse
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor

# Resource types to check - based on the attachment script
RESOURCE_TYPES = [
    # Compute Group
    ('compute_instances', 'Compute instances', 'compute'),
    ('dedicated_vm_hosts', 'Dedicated VM hosts', 'compute'),
    ('boot_volumes', 'Boot volumes', 'compute'),
    ('block_volumes', 'Block volumes', 'compute'),
    ('vnics', 'Virtual Network Interfaces', 'compute'),
    
    # Network Group
    ('vcns', 'Virtual Cloud Networks', 'network'),
    ('subnets', 'Subnets', 'network'),
    ('security_lists', 'Security lists', 'network'),
    ('network_security_groups', 'Network security groups', 'network'),
    ('load_balancers', 'Load balancers', 'network'),
    ('private_ips', 'Private IPs', 'network'),
    ('public_ips', 'Public IPs', 'network'),
    ('nat_gateways', 'NAT Gateways', 'network'),
    ('internet_gateways', 'Internet Gateways', 'network'),
    ('route_tables', 'Route Tables', 'network'),
    ('dhcp_options', 'DHCP Options', 'network'),
    ('dns_resolvers', 'DNS Resolvers', 'network'),
    ('dns_views', 'DNS Views', 'network'),
    
    # Database Group
    ('db_systems', 'DB systems', 'database'),
    ('autonomous_databases', 'Autonomous databases', 'database'),
    ('autonomous_db_backups', 'Autonomous database backups', 'database'),
    
    # Storage Group
    ('buckets', 'Object storage buckets', 'storage'),
    ('file_systems', 'File systems', 'storage'),
    ('sftp_servers', 'SFTP servers', 'storage'),
    
    # Security Group
    ('vaults', 'Vaults', 'security'),
    ('secrets', 'Secrets', 'security'),
    ('keys', 'Encryption Keys', 'security'),
    ('policies', 'Policies', 'security'),
    
    # Management Group
    ('logs', 'Logs', 'management'),
    ('log_groups', 'Log Groups', 'management'),
    ('ons_subscriptions', 'Notification Subscriptions', 'management'),
    ('ons_topics', 'Notification Topics', 'management'),
    
    # Integration Group
    ('integration_instances', 'Integration Cloud instances', 'integration'),
    ('api_gateways', 'API gateways', 'integration'),
    
    # DevOps Build Resources
    ('build_pipelines', 'Build Pipelines', 'devops'),
    ('build_runs', 'Build Runs', 'devops'),
    ('repositories', 'Code Repositories', 'devops'),
    ('triggers', 'Build Triggers', 'devops'),
    ('artifacts', 'Build Artifacts', 'devops'),
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
    'gateway_id',
    'nat_gateway_id',
    'internet_gateway_id',
    'dhcp_options_id',
    'dns_resolver_id',
    # Added more reference attributes that might be missed
    'backup_id',
    'topic_id',
    'attachment_id',
    'private_ip_id',
    'public_ip_id',
    'security_list_id',
    'log_group_id',
    'log_id',
    'vnic_id',
    'endpoint_id',
    'resource_id',
]

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Extract all resources from an OCI compartment using direct API calls')
    parser.add_argument('--compartment-name', required=True, help='Name of the compartment to extract resources from')
    parser.add_argument('--output-file', default=None, help='Output CSV file path (default: compartment_name_resources_timestamp.csv)')
    parser.add_argument('--config-file', default='~/.oci/config', help='OCI config file path (default: ~/.oci/config)')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile (default: DEFAULT)')
    parser.add_argument('--recursive', action='store_true', help='Include child compartments')
    parser.add_argument('--max-workers', type=int, default=10, help='Maximum number of parallel workers (default: 10)')
    parser.add_argument('--resource-type', help='Scan only a specific resource type (e.g., compute_instances, vcns, buckets)')
    parser.add_argument('--resource-group', help='Scan only resources in a specific group (e.g., network, compute)')
    return parser.parse_args()

def get_compartment_id_by_name(identity_client, tenancy_id, compartment_name):
    """Find compartment ID by name."""
    # Check if it's the root compartment (tenancy)
    try:
        tenancy = identity_client.get_compartment(tenancy_id).data
        if compartment_name.lower() == tenancy.name.lower():
            return tenancy_id
    except Exception as e:
        print(f"Error checking tenancy: {e}")
    
    # List all compartments in the tenancy
    try:
        compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            compartment_id=tenancy_id,
            compartment_id_in_subtree=True
        ).data
    except Exception as e:
        print(f"Error listing compartments: {e}")
        sys.exit(1)
    
    # Find the compartment with matching name (case-insensitive)
    for compartment in compartments:
        if compartment.name.lower() == compartment_name.lower() and compartment.lifecycle_state == "ACTIVE":
            return compartment.id
    
    # If we get here, the compartment wasn't found
    raise Exception(f"Compartment '{compartment_name}' not found or not active.")

def get_all_compartments(identity_client, tenancy_id):
    """Get all compartments in the tenancy."""
    compartments = []
    try:
        # Include the root tenancy
        tenancy = identity_client.get_compartment(tenancy_id).data
        compartments.append(tenancy)
        
        # Get all other compartments
        child_compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            compartment_id=tenancy_id,
            compartment_id_in_subtree=True,
            lifecycle_state="ACTIVE"
        ).data
        
        compartments.extend(child_compartments)
    except Exception as e:
        print(f"Error getting compartments: {e}")
    
    return compartments

def get_compartment_path(compartment_id, compartment_map):
    """Get the full path of a compartment."""
    if compartment_id not in compartment_map:
        return "Unknown"
    
    compartment = compartment_map[compartment_id]
    if hasattr(compartment, 'compartment_id') and compartment.compartment_id in compartment_map and compartment.compartment_id != compartment_id:
        parent_path = get_compartment_path(compartment.compartment_id, compartment_map)
        return f"{parent_path} / {compartment.name}"
    else:
        return compartment.name

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

def extract_resource_details(resource, compartments=None, resource_type='Unknown', service_group='Unknown'):
    """
    Extract key details from a resource object.
    
    Args:
        resource: An OCI resource object
        compartments: Dictionary of compartment objects (optional)
        resource_type: Type of resource for categorization
        service_group: Service group for categorization
        
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
            if isinstance(value, datetime):
                value = value.isoformat()
            details[attr] = value
    
    # Check for lifecycle state in multiple attributes
    state_attrs = ['lifecycle_state', 'status', 'state', 'resource_state', 'state_code']
    lifecycle_state_found = False
    
    for state_attr in state_attrs:
        if hasattr(resource, state_attr) and getattr(resource, state_attr):
            details['lifecycle_state'] = getattr(resource, state_attr)
            lifecycle_state_found = True
            break
    
    if not lifecycle_state_found:
        details['lifecycle_state'] = 'N/A'
    
    # Add compartment name if possible
    if compartments and hasattr(resource, 'compartment_id') and resource.compartment_id in compartments:
        details['compartment_name'] = compartments[resource.compartment_id].name
    
    # Extract resource ID - use the most appropriate field
    if 'id' in details:
        details['resource_id'] = details['id']
    elif hasattr(resource, 'identifier'):
        details['resource_id'] = resource.identifier
    else:
        details['resource_id'] = 'N/A'
    
    # Extract display name
    if 'display_name' in details:
        details['resource_name'] = details['display_name']
    elif 'name' in details:
        details['resource_name'] = details['name']
    elif hasattr(resource, 'display_name') and resource.display_name:
        details['resource_name'] = resource.display_name
    elif hasattr(resource, 'name') and resource.name:
        details['resource_name'] = resource.name
    else:
        details['resource_name'] = 'Unnamed'
    
    # Add resource type and service information
    details['resource_type'] = resource_type
    details['service'] = service_group
    
    # Extract freeform and defined tags if available
    if hasattr(resource, 'freeform_tags') and resource.freeform_tags:
        details['freeform_tags'] = resource.freeform_tags
        
    if hasattr(resource, 'defined_tags') and resource.defined_tags:
        details['defined_tags'] = resource.defined_tags
        
        # Extract resource group from defined tags
        details['resource_group'] = extract_resource_group(resource.defined_tags)
    else:
        details['resource_group'] = 'N/A'
        
    # Extract region if available in the resource ID
    if details['resource_id'] != 'N/A':
        parts = details['resource_id'].split('.')
        if len(parts) > 3:
            details['region'] = parts[3]
        else:
            details['region'] = 'N/A'
    else:
        details['region'] = 'N/A'
        
    # Format time created
    if 'time_created' in details and details['time_created']:
        if isinstance(details['time_created'], str):
            # Keep it as is if already a string
            pass
        else:
            # Convert to string format if it's a datetime object
            try:
                details['time_created'] = details['time_created'].strftime('%Y-%m-%d %H:%M:%S')
            except:
                details['time_created'] = str(details['time_created'])
    else:
        details['time_created'] = 'N/A'
    
    # Initialize cross-compartment references
    details['cross_compartment_references'] = 'None'
    
    # Get compute-specific info
    if resource_type == 'Compute instances':
        # Ensure shape info
        details['shape'] = getattr(resource, 'shape', 'N/A')
        
        # Get OCPU count and memory if available
        shape_config = getattr(resource, 'shape_config', None)
        if shape_config:
            details['ocpu_count'] = getattr(shape_config, 'ocpus', 'N/A')
            details['memory'] = f"{getattr(shape_config, 'memory_in_gbs', 'N/A')} GB"
        else:
            details['ocpu_count'] = 'N/A'
            details['memory'] = 'N/A'
            
        # Public access
        details['public_access'] = 'Yes' if getattr(resource, 'public_ip', None) else 'No'
        
    # Get network-specific info
    elif resource_type in ['Virtual Cloud Networks', 'Subnets']:
        details['cidr_block'] = getattr(resource, 'cidr_block', 'N/A')
        if resource_type == 'Subnets':
            details['public_access'] = 'No' if getattr(resource, 'prohibit_public_ip_on_vnic', False) else 'Yes'
        else:
            details['public_access'] = 'N/A'
            
    # Get storage-specific info
    elif resource_type in ['Block volumes', 'Boot volumes']:
        details['storage_size'] = f"{getattr(resource, 'size_in_gbs', 'N/A')} GB"
        
    # Get database-specific info
    elif resource_type in ['DB systems', 'Autonomous databases']:
        if resource_type == 'Autonomous databases':
            details['storage_size'] = f"{getattr(resource, 'data_storage_size_in_tbs', 'N/A')} TB"
            details['ocpu_count'] = getattr(resource, 'cpu_core_count', 'N/A')
        else:
            details['storage_size'] = f"{getattr(resource, 'data_storage_size_in_gbs', 'N/A')} GB"
            details['ocpu_count'] = getattr(resource, 'cpu_core_count', 'N/A')
    
    return details

def get_resource_details(config, compartment_id, resource_spec, compartments=None):
    """Get detailed information about resources of a specific type in the compartment."""
    resource_type, resource_display, resource_group = resource_spec
    resources = []
    
    # Print the resource type being scanned
    print(f"Scanning {resource_display}...", end=" ")
    
    try:
        # COMPUTE RESOURCES
        if resource_type == 'compute_instances':
            client = oci.core.ComputeClient(config)
            instances = oci.pagination.list_call_get_all_results(
                client.list_instances, compartment_id=compartment_id
            ).data
            for instance in instances:
                resource_details = extract_resource_details(instance, compartments, resource_display, resource_group)
                resources.append(resource_details)
                
        elif resource_type == 'dedicated_vm_hosts':
            client = oci.core.ComputeClient(config)
            hosts = oci.pagination.list_call_get_all_results(
                client.list_dedicated_vm_hosts, compartment_id=compartment_id
            ).data
            for host in hosts:
                resources.append(extract_resource_details(host, compartments, resource_display, resource_group))
                
        elif resource_type == 'vnics':
            # VNICs are typically accessed through compute instances
            client = oci.core.ComputeClient(config)
            network_client = oci.core.VirtualNetworkClient(config)
            
            # First get all instances
            instances = oci.pagination.list_call_get_all_results(
                client.list_instances, compartment_id=compartment_id
            ).data
            
            for instance in instances:
                # Get the VNIC attachments for each instance
                vnic_attachments = oci.pagination.list_call_get_all_results(
                    client.list_vnic_attachments,
                    compartment_id=compartment_id,
                    instance_id=instance.id
                ).data
                
                for attachment in vnic_attachments:
                    if attachment.lifecycle_state == "ATTACHED":
                        try:
                            vnic = network_client.get_vnic(attachment.vnic_id).data
                            resource_details = extract_resource_details(vnic, compartments, resource_display, resource_group)
                            resource_details['instance_id'] = instance.id
                            resource_details['instance_name'] = instance.display_name
                            resources.append(resource_details)
                        except Exception as e:
                            # Skip this VNIC if there's an error
                            pass
                
        elif resource_type == 'boot_volumes':
            client = oci.core.BlockstorageClient(config)
            # Need to iterate through all ADs
            identity_client = oci.identity.IdentityClient(config)
            ads = oci.pagination.list_call_get_all_results(
                identity_client.list_availability_domains, compartment_id=compartment_id
            ).data
            
            for ad in ads:
                volumes = oci.pagination.list_call_get_all_results(
                    client.list_boot_volumes,
                    availability_domain=ad.name,
                    compartment_id=compartment_id
                ).data
                for volume in volumes:
                    resources.append(extract_resource_details(volume, compartments, resource_display, resource_group))
            
        elif resource_type == 'block_volumes':
            client = oci.core.BlockstorageClient(config)
            volumes = oci.pagination.list_call_get_all_results(
                client.list_volumes, compartment_id=compartment_id
            ).data
            for volume in volumes:
                resources.append(extract_resource_details(volume, compartments, resource_display, resource_group))
                
        # NETWORK RESOURCES
        elif resource_type == 'vcns':
            client = oci.core.VirtualNetworkClient(config)
            vcns = oci.pagination.list_call_get_all_results(
                client.list_vcns, compartment_id=compartment_id
            ).data
            for vcn in vcns:
                resources.append(extract_resource_details(vcn, compartments, resource_display, resource_group))
                
        elif resource_type == 'subnets':
            client = oci.core.VirtualNetworkClient(config)
            subnets = oci.pagination.list_call_get_all_results(
                client.list_subnets, compartment_id=compartment_id
            ).data
            for subnet in subnets:
                resource_details = extract_resource_details(subnet, compartments, resource_display, resource_group)
                # Add VCN name if possible
                if hasattr(subnet, 'vcn_id'):
                    try:
                        vcn = client.get_vcn(subnet.vcn_id).data
                        resource_details['vcn_name'] = vcn.display_name if hasattr(vcn, 'display_name') else None
                    except:
                        pass
                resources.append(resource_details)
                
        elif resource_type == 'security_lists':
            client = oci.core.VirtualNetworkClient(config)
            security_lists = oci.pagination.list_call_get_all_results(
                client.list_security_lists, compartment_id=compartment_id
            ).data
            for sl in security_lists:
                resource_details = extract_resource_details(sl, compartments, resource_display, resource_group)
                resources.append(resource_details)
                
        elif resource_type == 'network_security_groups':
            client = oci.core.VirtualNetworkClient(config)
            nsgs = oci.pagination.list_call_get_all_results(
                client.list_network_security_groups, compartment_id=compartment_id
            ).data
            for nsg in nsgs:
                resources.append(extract_resource_details(nsg, compartments, resource_display, resource_group))
                
        elif resource_type == 'private_ips':
            client = oci.core.VirtualNetworkClient(config)
            
            # Get all VCNs and their subnets
            vcns = oci.pagination.list_call_get_all_results(
                client.list_vcns, compartment_id=compartment_id
            ).data
            
            for vcn in vcns:
                subnets = oci.pagination.list_call_get_all_results(
                    client.list_subnets, compartment_id=compartment_id, vcn_id=vcn.id
                ).data
                
                for subnet in subnets:
                    private_ips = oci.pagination.list_call_get_all_results(
                        client.list_private_ips, subnet_id=subnet.id
                    ).data
                    
                    for private_ip in private_ips:
                        resource_details = extract_resource_details(private_ip, compartments, resource_display, resource_group)
                        resource_details['vcn_id'] = vcn.id
                        resource_details['subnet_id'] = subnet.id
                        resources.append(resource_details)
                        
        elif resource_type == 'public_ips':
            client = oci.core.VirtualNetworkClient(config)
            
            # Get public IPs in the region
            public_ips = oci.pagination.list_call_get_all_results(
                client.list_public_ips,
                compartment_id=compartment_id,
                scope="REGION"
            ).data
            
            for public_ip in public_ips:
                resources.append(extract_resource_details(public_ip, compartments, resource_display, resource_group))
                
            # Also get public IPs in the availability domain
            identity_client = oci.identity.IdentityClient(config)
            ads = oci.pagination.list_call_get_all_results(
                identity_client.list_availability_domains, compartment_id=compartment_id
            ).data
            
            for ad in ads:
                ad_public_ips = oci.pagination.list_call_get_all_results(
                    client.list_public_ips,
                    compartment_id=compartment_id,
                    scope="AVAILABILITY_DOMAIN", 
                    availability_domain=ad.name
                ).data
                
                for public_ip in ad_public_ips:
                    resources.append(extract_resource_details(public_ip, compartments, resource_display, resource_group))
                    
        elif resource_type == 'nat_gateways':
            client = oci.core.VirtualNetworkClient(config)
            gateways = oci.pagination.list_call_get_all_results(
                client.list_nat_gateways, compartment_id=compartment_id
            ).data
            
            for gateway in gateways:
                resources.append(extract_resource_details(gateway, compartments, resource_display, resource_group))
                
        elif resource_type == 'internet_gateways':
            client = oci.core.VirtualNetworkClient(config)
            
            # Get all VCNs first
            vcns = oci.pagination.list_call_get_all_results(
                client.list_vcns, compartment_id=compartment_id
            ).data
            
            for vcn in vcns:
                gateways = oci.pagination.list_call_get_all_results(
                    client.list_internet_gateways, compartment_id=compartment_id, vcn_id=vcn.id
                ).data
                
                for gateway in gateways:
                    resource_details = extract_resource_details(gateway, compartments, resource_display, resource_group)
                    resource_details['vcn_id'] = vcn.id
                    resources.append(resource_details)
                    
        elif resource_type == 'route_tables':
            client = oci.core.VirtualNetworkClient(config)
            
            # Get all VCNs first
            vcns = oci.pagination.list_call_get_all_results(
                client.list_vcns, compartment_id=compartment_id
            ).data
            
            for vcn in vcns:
                route_tables = oci.pagination.list_call_get_all_results(
                    client.list_route_tables, compartment_id=compartment_id, vcn_id=vcn.id
                ).data
                
                for table in route_tables:
                    resource_details = extract_resource_details(table, compartments, resource_display, resource_group)
                    resource_details['vcn_id'] = vcn.id
                    resources.append(resource_details)
                    
        elif resource_type == 'dhcp_options':
            client = oci.core.VirtualNetworkClient(config)
            
            # Get all VCNs first
            vcns = oci.pagination.list_call_get_all_results(
                client.list_vcns, compartment_id=compartment_id
            ).data
            
            for vcn in vcns:
                dhcp_options = oci.pagination.list_call_get_all_results(
                    client.list_dhcp_options, compartment_id=compartment_id, vcn_id=vcn.id
                ).data
                
                for options in dhcp_options:
                    resource_details = extract_resource_details(options, compartments, resource_display, resource_group)
                    resource_details['vcn_id'] = vcn.id
                    resources.append(resource_details)
                    
        elif resource_type == 'dns_resolvers':
            try:
                client = oci.dns.DnsClient(config)
                
                resolvers = oci.pagination.list_call_get_all_results(
                    client.list_resolvers, compartment_id=compartment_id
                ).data
                
                for resolver in resolvers:
                    resources.append(extract_resource_details(resolver, compartments, resource_display, resource_group))
            except Exception:
                # Skip if DNS client not available
                pass
                
        elif resource_type == 'dns_views':
            try:
                client = oci.dns.DnsClient(config)
                
                views = oci.pagination.list_call_get_all_results(
                    client.list_views, compartment_id=compartment_id
                ).data
                
                for view in views:
                    resources.append(extract_resource_details(view, compartments, resource_display, resource_group))
            except Exception:
                # Skip if DNS client not available
                pass
                
        elif resource_type == 'load_balancers':
            try:
                client = oci.load_balancer.LoadBalancerClient(config)
                lbs = oci.pagination.list_call_get_all_results(
                    client.list_load_balancers, compartment_id=compartment_id
                ).data
                for lb in lbs:
                    resources.append(extract_resource_details(lb, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Load Balancer client not available
                pass
        
        # DATABASE RESOURCES
        elif resource_type == 'db_systems':
            try:
                client = oci.database.DatabaseClient(config)
                db_systems = oci.pagination.list_call_get_all_results(
                    client.list_db_systems, compartment_id=compartment_id
                ).data
                for db in db_systems:
                    resources.append(extract_resource_details(db, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Database client not available
                pass
                
        elif resource_type == 'autonomous_databases':
            try:
                client = oci.database.DatabaseClient(config)
                adbs = oci.pagination.list_call_get_all_results(
                    client.list_autonomous_databases, compartment_id=compartment_id
                ).data
                for adb in adbs:
                    resources.append(extract_resource_details(adb, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Database client not available
                pass
                
        elif resource_type == 'autonomous_db_backups':
            try:
                client = oci.database.DatabaseClient(config)
                
                # Get autonomous databases first
                adbs = oci.pagination.list_call_get_all_results(
                    client.list_autonomous_databases, compartment_id=compartment_id
                ).data
                
                for adb in adbs:
                    try:
                        # Get backups for this ADB
                        backups = oci.pagination.list_call_get_all_results(
                            client.list_autonomous_database_backups, autonomous_database_id=adb.id
                        ).data
                        
                        for backup in backups:
                            resource_details = extract_resource_details(backup, compartments, resource_display, resource_group)
                            resource_details['autonomous_database_id'] = adb.id
                            resource_details['autonomous_database_name'] = adb.display_name
                            resources.append(resource_details)
                    except Exception:
                        # Skip if can't get backups for this ADB
                        pass
            except Exception:
                # Skip if Database client not available
                pass
                    
        # STORAGE RESOURCES
        elif resource_type == 'buckets':
            try:
                client = oci.object_storage.ObjectStorageClient(config)
                namespace = client.get_namespace().data
                buckets = oci.pagination.list_call_get_all_results(
                    client.list_buckets, namespace_name=namespace, compartment_id=compartment_id
                ).data
                
                for bucket in buckets:
                    # Get detailed bucket info
                    try:
                        bucket_details = client.get_bucket(namespace_name=namespace, bucket_name=bucket.name).data
                        resource_details = extract_resource_details(bucket_details, compartments, resource_display, resource_group)
                        resources.append(resource_details)
                    except:
                        # Fall back to basic info
                        resources.append(extract_resource_details(bucket, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Object Storage client not available
                pass
                
        elif resource_type == 'file_systems':
            try:
                client = oci.file_storage.FileStorageClient(config)
                # Need ADs for file systems
                identity_client = oci.identity.IdentityClient(config)
                ads = oci.pagination.list_call_get_all_results(
                    identity_client.list_availability_domains, compartment_id=compartment_id
                ).data
                for ad in ads:
                    file_systems = oci.pagination.list_call_get_all_results(
                        client.list_file_systems, compartment_id=compartment_id, availability_domain=ad.name
                    ).data
                    for fs in file_systems:
                        resources.append(extract_resource_details(fs, compartments, resource_display, resource_group))
            except Exception:
                # Skip if File Storage client not available
                pass
                
        elif resource_type == 'sftp_servers':
            # Try File Storage SFTP
            try:
                client = oci.file_storage.FileStorageClient(config)
                
                # See if it has transfer-related methods
                if hasattr(client, 'list_transfer_servers'):
                    servers = oci.pagination.list_call_get_all_results(
                        client.list_transfer_servers, compartment_id=compartment_id
                    ).data
                    
                    for server in servers:
                        resources.append(extract_resource_details(server, compartments, resource_display, resource_group))
            except Exception:
                # Skip if client not available or method doesn't exist
                pass
                
        # SECURITY RESOURCES
        elif resource_type == 'vaults':
            try:
                client = oci.key_management.KmsVaultClient(config)
                vaults = oci.pagination.list_call_get_all_results(
                    client.list_vaults, compartment_id=compartment_id
                ).data
                
                for vault in vaults:
                    resources.append(extract_resource_details(vault, compartments, resource_display, resource_group))
            except Exception:
                # Skip if KMS client not available
                pass
                
        elif resource_type == 'secrets':
            try:
                client = oci.vault.VaultsClient(config)
                secrets = oci.pagination.list_call_get_all_results(
                    client.list_secrets, compartment_id=compartment_id
                ).data
                
                for secret in secrets:
                    resource_details = extract_resource_details(secret, compartments, resource_display, resource_group)
                    # For secrets, add vault name if possible
                    if hasattr(secret, 'vault_id'):
                        try:
                            vault_client = oci.key_management.KmsVaultClient(config)
                            vault = vault_client.get_vault(secret.vault_id).data
                            resource_details['vault_name'] = vault.display_name if hasattr(vault, 'display_name') else None
                        except:
                            pass
                    resources.append(resource_details)
            except Exception:
                # Skip if Vault client not available
                pass
                
        elif resource_type == 'keys':
            try:
                # KMS client for key management
                vault_client = oci.key_management.KmsVaultClient(config)
                vaults = oci.pagination.list_call_get_all_results(
                    vault_client.list_vaults, compartment_id=compartment_id
                ).data
                
                for vault in vaults:
                    # For each vault, we need to create a specific client with the vault's management endpoint
                    try:
                        # Get vault details to get management endpoint
                        vault_details = vault_client.get_vault(vault.id).data
                        
                        # Only proceed if vault is active
                        if vault_details.lifecycle_state != "ACTIVE":
                            continue
                            
                        # Create a new config with the vault's management endpoint
                        vault_config = config.copy()
                        
                        # Create a client with the vault endpoint
                        kms_client = oci.key_management.KmsManagementClient(
                            vault_config, 
                            service_endpoint=vault_details.management_endpoint
                        )
                        
                        # List keys in this vault
                        vault_keys = oci.pagination.list_call_get_all_results(
                            kms_client.list_keys, compartment_id=compartment_id
                        ).data
                        
                        for key in vault_keys:
                            resource_details = extract_resource_details(key, compartments, resource_display, resource_group)
                            # Add vault information
                            resource_details['vault_id'] = vault.id
                            resource_details['vault_name'] = vault.display_name
                            resources.append(resource_details)
                    except Exception:
                        # Skip if can't access vault
                        pass
            except Exception:
                # Skip if KMS client not available
                pass
                
        elif resource_type == 'policies':
            try:
                client = oci.identity.IdentityClient(config)
                policies = oci.pagination.list_call_get_all_results(
                    client.list_policies, compartment_id=compartment_id
                ).data
                
                for policy in policies:
                    resources.append(extract_resource_details(policy, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Identity client not available
                pass
                
        # MANAGEMENT RESOURCES
        elif resource_type == 'logs':
            try:
                client = oci.logging.LoggingManagementClient(config)
                
                # Get log groups first
                log_groups = oci.pagination.list_call_get_all_results(
                    client.list_log_groups, compartment_id=compartment_id
                ).data
                
                for group in log_groups:
                    # Get logs in each group
                    logs = oci.pagination.list_call_get_all_results(
                        client.list_logs, log_group_id=group.id
                    ).data
                    
                    for log in logs:
                        resource_details = extract_resource_details(log, compartments, resource_display, resource_group)
                        resource_details['log_group_id'] = group.id
                        resources.append(resource_details)
            except Exception:
                # Skip if Logging client not available
                pass
                
        elif resource_type == 'log_groups':
            try:
                client = oci.logging.LoggingManagementClient(config)
                log_groups = oci.pagination.list_call_get_all_results(
                    client.list_log_groups, compartment_id=compartment_id
                ).data
                
                for group in log_groups:
                    resources.append(extract_resource_details(group, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Logging client not available
                pass
                
        elif resource_type == 'ons_subscriptions':
            try:
                client = oci.ons.NotificationDataPlaneClient(config)
                subscriptions = oci.pagination.list_call_get_all_results(
                    client.list_subscriptions, compartment_id=compartment_id
                ).data
                
                for subscription in subscriptions:
                    resources.append(extract_resource_details(subscription, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Notification client not available
                pass
                
        elif resource_type == 'ons_topics':
            try:
                client = oci.ons.NotificationControlPlaneClient(config)
                topics = oci.pagination.list_call_get_all_results(
                    client.list_topics, compartment_id=compartment_id
                ).data
                
                for topic in topics:
                    resources.append(extract_resource_details(topic, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Notification client not available
                pass
                
        # INTEGRATION RESOURCES
        elif resource_type == 'integration_instances':
            try:
                client = oci.integration.IntegrationInstanceClient(config)
                instances = oci.pagination.list_call_get_all_results(
                    client.list_integration_instances, compartment_id=compartment_id
                ).data
                
                for instance in instances:
                    resources.append(extract_resource_details(instance, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Integration client not available
                pass
                
        elif resource_type == 'api_gateways':
            try:
                # Try different API method names until we find the right one
                client = oci.apigateway.ApiGatewayClient(config)
                try:
                    # Try the most likely method names
                    gateways = oci.pagination.list_call_get_all_results(
                        client.list_gateways, compartment_id=compartment_id
                    ).data
                except AttributeError:
                    try:
                        # Maybe it's this one
                        gateways = oci.pagination.list_call_get_all_results(
                            client.list_api_gateways, compartment_id=compartment_id
                        ).data
                    except AttributeError:
                        # Try one more
                        gateways = oci.pagination.list_call_get_all_results(
                            client.list_apis, compartment_id=compartment_id
                        ).data
                
                for gateway in gateways:
                    resources.append(extract_resource_details(gateway, compartments, resource_display, resource_group))
            except Exception:
                # Skip if API Gateway client not available
                pass
                
        # DEVOPS RESOURCES
        elif resource_type == 'build_pipelines':
            try:
                client = oci.devops.DevopsClient(config)
                pipelines = oci.pagination.list_call_get_all_results(
                    client.list_build_pipelines, compartment_id=compartment_id
                ).data
                
                for pipeline in pipelines:
                    resources.append(extract_resource_details(pipeline, compartments, resource_display, resource_group))
            except Exception:
                # Skip if DevOps client not available
                pass

        elif resource_type == 'build_runs':
            try:
                client = oci.devops.DevopsClient(config)
                runs = oci.pagination.list_call_get_all_results(
                    client.list_build_runs, compartment_id=compartment_id
                ).data
                
                for run in runs:
                    resources.append(extract_resource_details(run, compartments, resource_display, resource_group))
            except Exception:
                # Skip if DevOps client not available
                pass

        elif resource_type == 'repositories':
            try:
                client = oci.devops.DevopsClient(config)
                repos = oci.pagination.list_call_get_all_results(
                    client.list_repositories, compartment_id=compartment_id
                ).data
                
                for repo in repos:
                    resources.append(extract_resource_details(repo, compartments, resource_display, resource_group))
            except Exception:
                # Skip if DevOps client not available
                pass

        elif resource_type == 'triggers':
            try:
                client = oci.devops.DevopsClient(config)
                triggers = oci.pagination.list_call_get_all_results(
                    client.list_triggers, compartment_id=compartment_id
                ).data
                
                for trigger in triggers:
                    resources.append(extract_resource_details(trigger, compartments, resource_display, resource_group))
            except Exception:
                # Skip if DevOps client not available
                pass

        elif resource_type == 'artifacts':
            try:
                client = oci.artifacts.ArtifactsClient(config)
                artifacts = oci.pagination.list_call_get_all_results(
                    client.list_generic_artifacts, compartment_id=compartment_id
                ).data
                
                for artifact in artifacts:
                    resources.append(extract_resource_details(artifact, compartments, resource_display, resource_group))
            except Exception:
                # Skip if Artifacts client not available
                pass
                
        print(f"Found {len(resources)} resources")
    except Exception as e:
        print(f"Error: {str(e)}")
        
    return (resource_type, resource_display, resources)

def scan_resources(config, compartment_id, resource_type_filter=None, resource_group_filter=None, max_workers=10):
    """Scan resources in the compartment and return details."""
    print(f"Scanning resources in compartment {compartment_id}...")
    
    # Get all compartments for cross-reference lookup
    identity_client = oci.identity.IdentityClient(config)
    compartments = get_all_compartments(identity_client, config["tenancy"])
    compartment_map = {c.id: c for c in compartments}
    print(f"Found {len(compartment_map)} compartments in the tenancy")
    
    # Filter resource types by group if requested
    if resource_group_filter:
        resource_types_to_scan = [(rt, rd, rg) for rt, rd, rg in RESOURCE_TYPES if rg == resource_group_filter]
        if not resource_types_to_scan:
            print(f"No resources found for group: {resource_group_filter}")
            resource_types_to_scan = RESOURCE_TYPES
        else:
            print(f"Filtering to scan {resource_group_filter} resources ({len(resource_types_to_scan)} resource types)")
    else:
        resource_types_to_scan = RESOURCE_TYPES
    
    # Further filter by specific resource type if requested
    if resource_type_filter:
        resource_types_to_scan = [(rt, rd, rg) for rt, rd, rg in resource_types_to_scan if rt == resource_type_filter]
        if not resource_types_to_scan:
            print(f"Resource type '{resource_type_filter}' not found.")
            print("Available resource types:")
            for rt, rd, _ in RESOURCE_TYPES:
                print(f"  - {rt}: {rd}")
            resource_types_to_scan = RESOURCE_TYPES
        else:
            print(f"Filtering to scan only: {resource_types_to_scan[0][1]}")
    
    # Scan resources in parallel
    results = {}
    start_time = time.time()
    
    print("\nBeginning resource scan...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(get_resource_details, config, compartment_id, resource_spec, compartment_map): resource_spec
            for resource_spec in resource_types_to_scan
        }
        
        for future in futures:
            try:
                resource_type, resource_display, resources = future.result()
                results[resource_type] = {
                    'display_name': resource_display,
                    'resources': resources,
                    'count': len(resources)
                }
            except Exception as e:
                print(f"Error in resource scan: {e}")
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    print(f"\nCompleted scan in {elapsed:.2f} seconds")
    
    return results, compartment_map

def find_cross_compartment_references(resources_by_type, compartment_map):
    """Find cross-compartment references."""
    print("Analyzing cross-compartment references...")
    
    # Create a more comprehensive map of resource IDs to resource details
    resource_id_map = {}
    
    # First pass - collect all resource IDs
    for resource_type, info in resources_by_type.items():
        for resource in info['resources']:
            # Add primary resource ID
            if 'resource_id' in resource and resource['resource_id'] != 'N/A':
                resource_id_map[resource['resource_id']] = {
                    'type': resource_type,
                    'details': resource
                }
    
    # Track cross-compartment references
    cross_compartment_refs = 0
    
    # Second pass - find cross-compartment references
    for resource_type, info in resources_by_type.items():
        for resource in info['resources']:
            if 'compartment_id' not in resource:
                continue
                
            resource_compartment_id = resource['compartment_id']
            
            # Check all resource attributes for potential cross-compartment references
            for attr, value in resource.items():
                if (attr.endswith('_id') and isinstance(value, str) and 
                    value.startswith('ocid1.') and value in resource_id_map):
                    
                    # Found a reference to another resource
                    referenced_resource = resource_id_map[value]
                    referenced_details = referenced_resource['details']
                    
                    # Only proceed if we have compartment ID for both resources
                    if 'compartment_id' not in referenced_details:
                        continue
                        
                    referenced_compartment_id = referenced_details['compartment_id']
                    
                    # Is this a cross-compartment reference?
                    if (referenced_compartment_id != resource_compartment_id and 
                        attr in REFERENCE_ATTRIBUTES):
                        cross_compartment_refs += 1
                        
                        # Add cross-compartment reference info
                        if 'cross_compartment_references' not in resource or resource['cross_compartment_references'] == 'None':
                            resource['cross_compartment_references'] = ''
                            
                        # Add reference details with compartment name
                        ref_compartment_name = get_compartment_path(referenced_compartment_id, compartment_map) if referenced_compartment_id in compartment_map else 'Unknown'
                        
                        # Add the resource name if available
                        ref_resource_name = referenced_details.get('resource_name', 'Unnamed')
                        resource['cross_compartment_references'] += f"{attr}: {ref_resource_name} [{value}] (in {ref_compartment_name}); "
    
    # Clean up cross-compartment references formatting
    for resource_type, info in resources_by_type.items():
        for resource in info['resources']:
            if 'cross_compartment_references' in resource and resource['cross_compartment_references'].endswith('; '):
                resource['cross_compartment_references'] = resource['cross_compartment_references'][:-2]
                
            if 'cross_compartment_references' not in resource or not resource['cross_compartment_references']:
                resource['cross_compartment_references'] = 'None'
    
    print(f"Found {cross_compartment_refs} cross-compartment references")
    
    return resources_by_type

def flatten_resources(resources_by_type, compartment_info, compartment_map):
    """Flatten resources into a list for CSV output."""
    flattened = []
    
    for resource_type, info in resources_by_type.items():
        for resource in info['resources']:
            # Add full compartment path if it has a compartment_id
            if 'compartment_id' in resource and resource['compartment_id'] in compartment_map:
                resource['compartment_name'] = get_compartment_path(resource['compartment_id'], compartment_map)
            elif 'compartment_name' not in resource:
                resource['compartment_name'] = compartment_info.get('name', 'Unknown')
            
            # Ensure lifecycle state is properly captured
            if 'lifecycle_state' in resource and (resource['lifecycle_state'] == 'N/A' or not resource['lifecycle_state']):
                # Check for status field as an alternative
                if 'status' in resource and resource['status'] != 'N/A':
                    resource['lifecycle_state'] = resource['status']
                # For bucket objects
                elif resource_type == 'buckets' and not resource['lifecycle_state']:
                    resource['lifecycle_state'] = 'ACTIVE'  # Default for buckets
                # For IP addresses
                elif resource_type in ['private_ips', 'public_ips'] and not resource['lifecycle_state']:
                    if 'is_reserved' in resource and resource['is_reserved']:
                        resource['lifecycle_state'] = 'RESERVED'
                    elif 'assigned' in resource and resource['assigned']:
                        resource['lifecycle_state'] = 'ASSIGNED'
                    else:
                        resource['lifecycle_state'] = 'AVAILABLE'
            
            # Rename fields to match our desired CSV schema
            field_mapping = {
                'resource_id': 'Resource ID',
                'resource_name': 'Resource Name',
                'resource_type': 'Resource Type',
                'service': 'Service',
                'compartment_id': 'Compartment ID',
                'compartment_name': 'Compartment Name',
                'region': 'Region',
                'availability_domain': 'Availability Domain',
                'lifecycle_state': 'Lifecycle State',
                'time_created': 'Time Created',
                'defined_tags': 'Defined Tags',
                'freeform_tags': 'Freeform Tags',
                'cross_compartment_references': 'Cross-Compartment References',
                'shape': 'Shape',
                'ocpu_count': 'OCPU Count',
                'memory': 'Memory',
                'storage_size': 'Storage Size',
                'cidr_block': 'CIDR Block',
                'public_access': 'Public Access'
            }
            
            # Create a new resource with the remapped fields
            mapped_resource = {}
            for old_key, new_key in field_mapping.items():
                if old_key in resource:
                    mapped_resource[new_key] = resource[old_key]
                else:
                    mapped_resource[new_key] = 'N/A'
            
            # Add any remaining fields that aren't in our mapping
            for key, value in resource.items():
                if key not in field_mapping.keys() and key not in ['id', 'display_name', 'name', 'resource_group']:
                    mapped_resource[key] = value
            
            flattened.append(mapped_resource)
    
    return flattened

def get_all_regions(identity_client, tenancy_id):
    """Get all available regions in OCI."""
    try:
        regions = identity_client.list_region_subscriptions(tenancy_id).data
        return [region.region_name for region in regions]
    except Exception as e:
        print(f"Error getting regions: {e}")
        return []

def main():
    """Main function."""
    args = parse_arguments()
    start_time = time.time()
    
    print(f"OCI Tenancy Explorer")
    print(f"==================")
    
    # Get all profiles from config file
    config_file = os.path.expanduser(args.config_file)
    profiles = get_config_profiles(config_file)
    print(f"Found profiles: {', '.join(profiles)}")
    
    # Initialize variables
    all_resources = []
    tenancy_id = None
    compartment_hierarchy = {}
    all_compartments = []
    
    # Setup with first profile to get compartment and regions
    primary_profile = profiles[0] if profiles else "DEFAULT"
    try:
        config = oci.config.from_file(config_file, primary_profile)
        print(f"Using profile {primary_profile} to initialize...")
        identity_client = oci.identity.IdentityClient(config)
        tenancy_id = config.get('tenancy')
        
        print(f"Looking for compartment: {args.compartment_name}")
        compartment = get_compartment_by_name(identity_client, tenancy_id, args.compartment_name)
        print(f"Found compartment: {compartment.name}")
        
        # Get all regions
        print("Getting all available regions...")
        all_regions = get_all_regions(identity_client, tenancy_id)
        print(f"Will scan the following regions: {', '.join(all_regions)}")
        
        # Get compartments
        compartments_to_scan = []
        if args.recursive:
            print("Scanning for child compartments...")
            all_compartments = get_all_compartments(identity_client, tenancy_id)
            compartment_hierarchy = build_compartment_hierarchy(identity_client, tenancy_id, all_compartments)
            compartments_to_scan = [c for c in all_compartments 
                                if c.id == compartment.id or 
                                (hasattr(c, 'compartment_id') and c.compartment_id == compartment.id)]
            print(f"Found {len(compartments_to_scan)} compartments to scan:")
            for c in compartments_to_scan:
                print(f"  - {compartment_hierarchy.get(c.id, c.name)}")
        else:
            compartments_to_scan = [compartment]
            print(f"Scanning single compartment: {compartment.name}")
        
        # Process all regions
        for region in all_regions:
            print(f"\nSwitching to region: {region}")
            
            # Create new config for this region
            region_config = dict(config)
            region_config['region'] = region
            
            print(f"Initializing OCI clients for region: {region}...")
            clients = get_service_clients(region_config)
            
            for comp in compartments_to_scan:
                comp_full_path = get_compartment_full_path(comp.name, comp.id, compartment_hierarchy)
                print(f"\nExploring compartment: {comp_full_path} in region {region}...")
                resources = explore_tenancy(comp.id, comp_full_path, clients, region, args.max_workers)
                all_resources.extend(resources)
                
    except Exception as e:
        print(f"Error in main processing: {e}")
        sys.exit(1)
    
    print(f"\nResource exploration complete. Found {len(all_resources)} resources across all regions and services.")
    write_csv(all_resources, args.output_file)
    
    elapsed_time = time.time() - start_time
    print(f"Total execution time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()