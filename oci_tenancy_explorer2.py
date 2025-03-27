#!/usr/bin/env python3
"""
OCI Tenancy Explorer

This script extracts all resources from a specified OCI compartment (including child compartments)
and outputs detailed information to a CSV file.

Usage: python oci_tenancy_explorer.py --compartment-name "your-compartment-name" [--output-file "output.csv"] [--recursive]
"""

import oci
import csv
import sys
import os
import argparse
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor

# Resource types to check
RESOURCE_TYPES = [
    # Compute
    'instances',
    'dedicated_vm_hosts',
    'boot_volumes',
    'block_volumes',
    'volume_attachments',
    'boot_volume_attachments',
    
    # Network
    'vcns',
    'subnets',
    'route_tables',
    'security_lists',
    'network_security_groups',
    'internet_gateways',
    'nat_gateways',
    'service_gateways',
    'local_peering_gateways',
    'drgs',
    'public_ips',
    
    # Database
    'db_systems',
    'autonomous_databases',
    'autonomous_database_backups',
    
    # Storage
    'buckets',
    'file_systems',
    'mount_targets',
    
    # Load Balancer
    'load_balancers',
    
    # Other services
    'functions',
    'api_gateways',
    'dns_zones',
    'dns_resolvers',
    'log_groups',
    'logs',
    'policies',
    'vaults',
    'secrets',
]

# Attributes that commonly reference other resources
REFERENCE_ATTRIBUTES = [
    'subnet_id', 
    'vcn_id', 
    'compartment_id', 
    'vault_id', 
    'instance_id', 
    'network_security_group_id', 
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

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Extract all resources from an OCI compartment')
    parser.add_argument('--compartment-name', required=True, help='Name of the compartment to extract resources from')
    parser.add_argument('--output-file', default=None, help='Output CSV file path (default: compartment_name_resources_timestamp.csv)')
    parser.add_argument('--config-file', default='~/.oci/config', help='OCI config file path (default: ~/.oci/config)')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile (default: DEFAULT)')
    parser.add_argument('--recursive', action='store_true', help='Include child compartments')
    parser.add_argument('--max-workers', type=int, default=10, help='Maximum number of parallel workers (default: 10)')
    parser.add_argument('--search-api', action='store_true', help='Use Resource Search API for discovery (default: use direct API calls)')
    return parser.parse_args()

def get_compartment_id_by_name(identity_client, tenancy_id, compartment_name):
    """Find compartment ID by name."""
    try:
        # Check if it's the root compartment (tenancy)
        tenancy = identity_client.get_compartment(tenancy_id).data
        if compartment_name.lower() == tenancy.name.lower():
            return tenancy_id
    except Exception as e:
        print(f"Error checking tenancy: {e}")
    
    # List all compartments in the tenancy
    compartments = []
    try:
        compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            compartment_id=tenancy_id,
            compartment_id_in_subtree=True
        ).data
    except Exception as e:
        print(f"Error listing compartments: {e}")
        sys.exit(1)
    
    # Find the compartment with matching name
    for compartment in compartments:
        if compartment.name.lower() == compartment_name.lower() and compartment.lifecycle_state == "ACTIVE":
            return compartment.id
    
    # If we get here, the compartment wasn't found
    raise Exception(f"Compartment '{compartment_name}' not found or not active.")

def get_all_compartments(identity_client, tenancy_id, parent_compartment_id=None):
    """Get all compartments in the tenancy or within a parent compartment."""
    compartments = []
    try:
        # Include the root tenancy
        tenancy = identity_client.get_compartment(tenancy_id).data
        compartments.append(tenancy)
        
        if parent_compartment_id is None:
            parent_compartment_id = tenancy_id
            
        # Get all child compartments
        child_compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            compartment_id=parent_compartment_id,
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

def find_cross_compartment_references(resources, compartment_map):
    """Find resources that reference or are referenced by resources in other compartments."""
    print("Analyzing cross-compartment references...")
    
    # Create a map of resource IDs to their details
    resource_id_map = {}
    for resource in resources:
        if 'Resource ID' in resource and resource['Resource ID'] != 'N/A':
            resource_id_map[resource['Resource ID']] = resource
    
    # Check for references between resources
    for resource in resources:
        resource_compartment_id = resource.get('Compartment ID')
        if not resource_compartment_id:
            continue
            
        # Check common reference attributes
        reference_found = False
        for key, value in resource.items():
            if key in REFERENCE_ATTRIBUTES and isinstance(value, str) and value.startswith('ocid1.'):
                # Check if this is a reference to a resource in another compartment
                if value in resource_id_map:
                    referenced_resource = resource_id_map[value]
                    referenced_compartment_id = referenced_resource.get('Compartment ID')
                    
                    if (referenced_compartment_id and 
                        referenced_compartment_id != resource_compartment_id):
                        
                        # This is a cross-compartment reference
                        reference_found = True
                        
                        # Add outbound reference info
                        if 'Cross-Compartment References' not in resource or resource['Cross-Compartment References'] == 'None':
                            resource['Cross-Compartment References'] = ''
                            
                        resource['Cross-Compartment References'] += f"{key}:{value} (in {compartment_map.get(referenced_compartment_id, 'Unknown')}); "
    
    # Clean up trailing separators
    for resource in resources:
        if 'Cross-Compartment References' in resource and resource['Cross-Compartment References'].endswith('; '):
            resource['Cross-Compartment References'] = resource['Cross-Compartment References'][:-2]
            
        if not resource.get('Cross-Compartment References'):
            resource['Cross-Compartment References'] = 'None'
    
    return resources

def get_resources_search_api(search_client, compartment_id):
    """Get resources using the Resource Search API."""
    print(f"Discovering resources in compartment {compartment_id} using Resource Search API...")
    
    query = f"query all resources where compartmentId = '{compartment_id}'"
    search_details = oci.resource_search.models.StructuredSearchDetails(
        type="Structured",
        query=query
    )
    
    try:
        response = oci.pagination.list_call_get_all_results(
            search_client.search_resources,
            search_details=search_details,
            limit=1000
        )
        return response.data.items
    except Exception as e:
        print(f"Error using Resource Search API: {e}")
        return []

def get_instances(compute_client, compartment_id):
    """Get compute instances."""
    resources = []
    try:
        instances = oci.pagination.list_call_get_all_results(
            compute_client.list_instances, 
            compartment_id=compartment_id
        ).data
        
        for instance in instances:
            # Get basic attributes
            resource = {
                'Resource Type': 'Instance',
                'Resource ID': instance.id,
                'Name': instance.display_name,
                'Compartment ID': instance.compartment_id,
                'Region': instance.region,
                'Availability Domain': instance.availability_domain,
                'Shape': instance.shape,
                'Lifecycle State': instance.lifecycle_state,
                'Time Created': instance.time_created.strftime('%Y-%m-%d %H:%M:%S') if instance.time_created else 'N/A',
                'Defined Tags': str(instance.defined_tags) if instance.defined_tags else '{}',
                'Freeform Tags': str(instance.freeform_tags) if instance.freeform_tags else '{}',
            }
            
            # Get Resource Group
            resource['Resource Group'] = extract_resource_group(instance.defined_tags)
            
            # Additional instance-specific details
            if hasattr(instance, 'shape_config') and instance.shape_config:
                resource['OCPU Count'] = instance.shape_config.ocpus if hasattr(instance.shape_config, 'ocpus') else 'N/A'
                resource['Memory'] = f"{instance.shape_config.memory_in_gbs} GB" if hasattr(instance.shape_config, 'memory_in_gbs') else 'N/A'
            else:
                resource['OCPU Count'] = 'N/A'
                resource['Memory'] = 'N/A'
                
            # Extract network info
            resource['Public IP'] = getattr(instance, 'public_ip', 'N/A')
            resource['Private IP'] = getattr(instance, 'private_ip', 'N/A')
            resource['Subnet ID'] = getattr(instance, 'subnet_id', 'N/A')
            
            resources.append(resource)
        
        print(f"Found {len(resources)} compute instances")
    except Exception as e:
        print(f"Error getting compute instances: {e}")
    
    return resources

def get_vcns(network_client, compartment_id):
    """Get Virtual Cloud Networks."""
    resources = []
    try:
        vcns = oci.pagination.list_call_get_all_results(
            network_client.list_vcns, 
            compartment_id=compartment_id
        ).data
        
        for vcn in vcns:
            # Get basic attributes
            resource = {
                'Resource Type': 'VCN',
                'Resource ID': vcn.id,
                'Name': vcn.display_name,
                'Compartment ID': vcn.compartment_id,
                'Lifecycle State': vcn.lifecycle_state,
                'Time Created': vcn.time_created.strftime('%Y-%m-%d %H:%M:%S') if vcn.time_created else 'N/A',
                'Defined Tags': str(vcn.defined_tags) if vcn.defined_tags else '{}',
                'Freeform Tags': str(vcn.freeform_tags) if vcn.freeform_tags else '{}',
                'CIDR Block': vcn.cidr_block,
                'DNS Label': getattr(vcn, 'dns_label', 'N/A')
            }
            
            # Get Resource Group
            resource['Resource Group'] = extract_resource_group(vcn.defined_tags)
            
            # Add region information if available in the ID
            if vcn.id:
                parts = vcn.id.split('.')
                if len(parts) > 3:
                    resource['Region'] = parts[3]
                else:
                    resource['Region'] = 'N/A'
            else:
                resource['Region'] = 'N/A'
                
            # Add availability domain (not applicable for VCNs)
            resource['Availability Domain'] = 'N/A'
            
            resources.append(resource)
        
        print(f"Found {len(resources)} vcns")
    except Exception as e:
        print(f"Error getting vcns: {e}")
    
    return resources

def get_subnets(network_client, compartment_id):
    """Get Subnets."""
    resources = []
    try:
        subnets = oci.pagination.list_call_get_all_results(
            network_client.list_subnets, 
            compartment_id=compartment_id
        ).data
        
        for subnet in subnets:
            # Get basic attributes
            resource = {
                'Resource Type': 'Subnet',
                'Resource ID': subnet.id,
                'Name': subnet.display_name,
                'Compartment ID': subnet.compartment_id,
                'Lifecycle State': subnet.lifecycle_state,
                'Time Created': subnet.time_created.strftime('%Y-%m-%d %H:%M:%S') if subnet.time_created else 'N/A',
                'Defined Tags': str(subnet.defined_tags) if subnet.defined_tags else '{}',
                'Freeform Tags': str(subnet.freeform_tags) if subnet.freeform_tags else '{}',
                'CIDR Block': subnet.cidr_block,
                'VCN ID': subnet.vcn_id,
                'DNS Label': getattr(subnet, 'dns_label', 'N/A'),
                'Availability Domain': subnet.availability_domain if subnet.availability_domain else 'Regional',
                'Public Access': 'No' if getattr(subnet, 'prohibit_public_ip_on_vnic', False) else 'Yes',
                'Route Table ID': getattr(subnet, 'route_table_id', 'N/A')
            }
            
            # Get Resource Group
            resource['Resource Group'] = extract_resource_group(subnet.defined_tags)
            
            # Add region information if available in the ID
            if subnet.id:
                parts = subnet.id.split('.')
                if len(parts) > 3:
                    resource['Region'] = parts[3]
                else:
                    resource['Region'] = 'N/A'
            else:
                resource['Region'] = 'N/A'
                
            resources.append(resource)
        
        print(f"Found {len(resources)} subnets")
    except Exception as e:
        print(f"Error getting subnets: {e}")
    
    return resources

def get_block_volumes(block_storage_client, compartment_id):
    """Get Block Volumes."""
    resources = []
    try:
        volumes = oci.pagination.list_call_get_all_results(
            block_storage_client.list_volumes, 
            compartment_id=compartment_id
        ).data
        
        for volume in volumes:
            # Get basic attributes
            resource = {
                'Resource Type': 'Block Volume',
                'Resource ID': volume.id,
                'Name': volume.display_name,
                'Compartment ID': volume.compartment_id,
                'Lifecycle State': volume.lifecycle_state,
                'Time Created': volume.time_created.strftime('%Y-%m-%d %H:%M:%S') if volume.time_created else 'N/A',
                'Defined Tags': str(volume.defined_tags) if volume.defined_tags else '{}',
                'Freeform Tags': str(volume.freeform_tags) if volume.freeform_tags else '{}',
                'Availability Domain': volume.availability_domain,
                'Size': f"{volume.size_in_gbs} GB" if hasattr(volume, 'size_in_gbs') else 'N/A',
                'Storage Size': f"{volume.size_in_gbs} GB" if hasattr(volume, 'size_in_gbs') else 'N/A',
                'Volume Backup Policy': getattr(volume, 'backup_policy_id', 'N/A')
            }
            
            # Get Resource Group
            resource['Resource Group'] = extract_resource_group(volume.defined_tags)
            
            # Add region information if available in the ID
            if volume.id:
                parts = volume.id.split('.')
                if len(parts) > 3:
                    resource['Region'] = parts[3]
                else:
                    resource['Region'] = 'N/A'
            else:
                resource['Region'] = 'N/A'
                
            resources.append(resource)
        
        print(f"Found {len(resources)} block volumes")
    except Exception as e:
        print(f"Error getting block volumes: {e}")
    
    return resources

def get_boot_volumes(block_storage_client, identity_client, compartment_id):
    """Get Boot Volumes (requires iterating through ADs)."""
    resources = []
    try:
        # Get ADs first
        ads = oci.pagination.list_call_get_all_results(
            identity_client.list_availability_domains,
            compartment_id=compartment_id
        ).data
        
        for ad in ads:
            try:
                volumes = oci.pagination.list_call_get_all_results(
                    block_storage_client.list_boot_volumes,
                    availability_domain=ad.name,
                    compartment_id=compartment_id
                ).data
                
                for volume in volumes:
                    # Get basic attributes
                    resource = {
                        'Resource Type': 'Boot Volume',
                        'Resource ID': volume.id,
                        'Name': volume.display_name,
                        'Compartment ID': volume.compartment_id,
                        'Lifecycle State': volume.lifecycle_state,
                        'Time Created': volume.time_created.strftime('%Y-%m-%d %H:%M:%S') if volume.time_created else 'N/A',
                        'Defined Tags': str(volume.defined_tags) if volume.defined_tags else '{}',
                        'Freeform Tags': str(volume.freeform_tags) if volume.freeform_tags else '{}',
                        'Availability Domain': volume.availability_domain,
                        'Size': f"{volume.size_in_gbs} GB" if hasattr(volume, 'size_in_gbs') else 'N/A',
                        'Storage Size': f"{volume.size_in_gbs} GB" if hasattr(volume, 'size_in_gbs') else 'N/A',
                        'Volume Backup Policy': getattr(volume, 'backup_policy_id', 'N/A')
                    }
                    
                    # Get Resource Group
                    resource['Resource Group'] = extract_resource_group(volume.defined_tags)
                    
                    # Add region information if available in the ID
                    if volume.id:
                        parts = volume.id.split('.')
                        if len(parts) > 3:
                            resource['Region'] = parts[3]
                        else:
                            resource['Region'] = 'N/A'
                    else:
                        resource['Region'] = 'N/A'
                        
                    resources.append(resource)
            except Exception as ad_error:
                print(f"Error getting boot volumes in AD {ad.name}: {ad_error}")
        
        print(f"Found {len(resources)} boot volumes")
    except Exception as e:
        print(f"Error getting boot volumes: {e}")
    
    return resources

def get_buckets(object_storage_client, compartment_id):
    """Get Object Storage Buckets."""
    resources = []
    try:
        # Get namespace first
        namespace = object_storage_client.get_namespace().data
        
        # Then list buckets
        buckets = oci.pagination.list_call_get_all_results(
            object_storage_client.list_buckets,
            namespace_name=namespace,
            compartment_id=compartment_id
        ).data
        
        for bucket in buckets:
            # Basic bucket info doesn't have all details, so get the details
            try:
                bucket_details = object_storage_client.get_bucket(
                    namespace_name=namespace,
                    bucket_name=bucket.name
                ).data
                
                # Get basic attributes
                resource = {
                    'Resource Type': 'Object Storage Bucket',
                    'Resource ID': f"ocid1.bucket.{bucket_details.namespace}.{bucket_details.name}" if hasattr(bucket_details, 'namespace') else 'N/A',
                    'Name': bucket_details.name,
                    'Compartment ID': bucket_details.compartment_id,
                    'Region': getattr(bucket_details, 'region', 'N/A'),
                    'Lifecycle State': getattr(bucket_details, 'lifecycle_state', 'N/A'),
                    'Time Created': bucket_details.time_created.strftime('%Y-%m-%d %H:%M:%S') if hasattr(bucket_details, 'time_created') and bucket_details.time_created else 'N/A',
                    'Defined Tags': str(bucket_details.defined_tags) if hasattr(bucket_details, 'defined_tags') and bucket_details.defined_tags else '{}',
                    'Freeform Tags': str(bucket_details.freeform_tags) if hasattr(bucket_details, 'freeform_tags') and bucket_details.freeform_tags else '{}',
                    'Storage Tier': getattr(bucket_details, 'storage_tier', 'N/A'),
                    'Public Access': 'Yes' if hasattr(bucket_details, 'public_access_type') and bucket_details.public_access_type != 'NoPublicAccess' else 'No',
                    'Versioning': getattr(bucket_details, 'versioning', 'N/A')
                }
                
                # Buckets don't have ADs
                resource['Availability Domain'] = 'N/A'
                
                # Get Resource Group
                resource['Resource Group'] = extract_resource_group(bucket_details.defined_tags if hasattr(bucket_details, 'defined_tags') else None)
                
                resources.append(resource)
            except Exception as bucket_error:
                # If can't get details, use the basic info
                resource = {
                    'Resource Type': 'Object Storage Bucket',
                    'Resource ID': f"ocid1.bucket.{bucket.namespace}.{bucket.name}" if hasattr(bucket, 'namespace') else 'N/A',
                    'Name': bucket.name,
                    'Compartment ID': bucket.compartment_id,
                    'Region': 'N/A',
                    'Availability Domain': 'N/A',
                    'Lifecycle State': 'N/A',
                    'Time Created': bucket.time_created.strftime('%Y-%m-%d %H:%M:%S') if hasattr(bucket, 'time_created') and bucket.time_created else 'N/A',
                    'Defined Tags': '{}',
                    'Freeform Tags': '{}',
                    'Resource Group': 'N/A'
                }
                resources.append(resource)
        
        print(f"Found {len(resources)} buckets")
    except Exception as e:
        print(f"Error getting buckets: {e}")
    
    return resources

def get_database_systems(database_client, compartment_id):
    """Get Database Systems."""
    resources = []
    try:
        db_systems = oci.pagination.list_call_get_all_results(
            database_client.list_db_systems,
            compartment_id=compartment_id
        ).data
        
        for db in db_systems:
            # Get basic attributes
            resource = {
                'Resource Type': 'DB System',
                'Resource ID': db.id,
                'Name': db.display_name,
                'Compartment ID': db.compartment_id,
                'Lifecycle State': db.lifecycle_state,
                'Time Created': db.time_created.strftime('%Y-%m-%d %H:%M:%S') if db.time_created else 'N/A',
                'Defined Tags': str(db.defined_tags) if db.defined_tags else '{}',
                'Freeform Tags': str(db.freeform_tags) if db.freeform_tags else '{}',
                'Availability Domain': db.availability_domain,
                'Shape': db.shape,
                'OCPU Count': getattr(db, 'cpu_core_count', 'N/A'),
                'Storage Size': f"{getattr(db, 'data_storage_size_in_gbs', 'N/A')} GB" if hasattr(db, 'data_storage_size_in_gbs') else 'N/A',
                'Database Edition': getattr(db, 'database_edition', 'N/A'),
                'License Type': getattr(db, 'license_model', 'N/A')
            }
            
            # Get Resource Group
            resource['Resource Group'] = extract_resource_group(db.defined_tags)
            
            # Add region information if available in the ID
            if db.id:
                parts = db.id.split('.')
                if len(parts) > 3:
                    resource['Region'] = parts[3]
                else:
                    resource['Region'] = 'N/A'
            else:
                resource['Region'] = 'N/A'
                
            resources.append(resource)
        
        print(f"Found {len(resources)} DB systems")
    except Exception as e:
        print(f"Error getting DB systems: {e}")
    
    return resources

def get_autonomous_databases(database_client, compartment_id):
    """Get Autonomous Databases."""
    resources = []
    try:
        adbs = oci.pagination.list_call_get_all_results(
            database_client.list_autonomous_databases,
            compartment_id=compartment_id
        ).data
        
        for adb in adbs:
            # Get basic attributes
            resource = {
                'Resource Type': 'Autonomous Database',
                'Resource ID': adb.id,
                'Name': adb.display_name,
                'Compartment ID': adb.compartment_id,
                'Lifecycle State': adb.lifecycle_state,
                'Time Created': adb.time_created.strftime('%Y-%m-%d %H:%M:%S') if adb.time_created else 'N/A',
                'Defined Tags': str(adb.defined_tags) if adb.defined_tags else '{}',
                'Freeform Tags': str(adb.freeform_tags) if adb.freeform_tags else '{}',
                'Availability Domain': 'N/A',  # Autonomous DBs don't have an AD
                'DB Name': getattr(adb, 'db_name', 'N/A'),
                'DB Workload': getattr(adb, 'db_workload', 'N/A'),
                'OCPU Count': getattr(adb, 'cpu_core_count', 'N/A'),
                'Storage Size': f"{getattr(adb, 'data_storage_size_in_tbs', 'N/A')} TB" if hasattr(adb, 'data_storage_size_in_tbs') else 'N/A',
                'License Type': getattr(adb, 'license_model', 'N/A')
            }
            
            # Get Resource Group
            resource['Resource Group'] = extract_resource_group(adb.defined_tags)
            
            # Add region information if available in the ID
            if adb.id:
                parts = adb.id.split('.')
                if len(parts) > 3:
                    resource['Region'] = parts[3]
                else:
                    resource['Region'] = 'N/A'
            else:
                resource['Region'] = 'N/A'
                
            resources.append(resource)
        
        print(f"Found {len(resources)} Autonomous Databases")
    except Exception as e:
        print(f"Error getting Autonomous Databases: {e}")
    
    return resources

def get_load_balancers(load_balancer_client, compartment_id):
    """Get Load Balancers."""
    resources = []
    try:
        lbs = oci.pagination.list_call_get_all_results(
            load_balancer_client.list_load_balancers,
            compartment_id=compartment_id
        ).data
        
        for lb in lbs:
            # Get basic attributes
            resource = {
                'Resource Type': 'Load Balancer',
                'Resource ID': lb.id,
                'Name': lb.display_name,
                'Compartment ID': lb.compartment_id,
                'Lifecycle State': lb.lifecycle_state,
                'Time Created': lb.time_created.strftime('%Y-%m-%d %H:%M:%S') if lb.time_created else 'N/A',
                'Defined Tags': str(lb.defined_tags) if lb.defined_tags else '{}',
                'Freeform Tags': str(lb.freeform_tags) if lb.freeform_tags else '{}',
                'Availability Domain': 'N/A',  # LBs don't have ADs
                'Shape': getattr(lb, 'shape_name', 'N/A'),
                'Public Access': 'No' if getattr(lb, 'is_private', False) else 'Yes',
                'Subnet IDs': str(lb.subnet_ids) if hasattr(lb, 'subnet_ids') else 'N/A'
            }
            
            # Get Resource Group
            resource['Resource Group'] = extract_resource_group(lb.defined_tags)
            
            # Add region information if available in the ID
            if lb.id:
                parts = lb.id.split('.')
                if len(parts) > 3:
                    resource['Region'] = parts[3]
                else:
                    resource['Region'] = 'N/A'
            else:
                resource['Region'] = 'N/A'
                
            resources.append(resource)
        
        print(f"Found {len(resources)} Load Balancers")
    except Exception as e:
        print(f"Error getting Load Balancers: {e}")
    
    return resources

def get_file_systems(file_storage_client, identity_client, compartment_id):
    """Get File Systems."""
    resources = []
    try:
        # Get ADs first
        ads = oci.pagination.list_call_get_all_results(
            identity_client.list_availability_domains,
            compartment_id=compartment_id
        ).data
        
        for ad in ads:
            try:
                file_systems = oci.pagination.list_call_get_all_results(
                    file_storage_client.list_file_systems,
                    compartment_id=compartment_id,
                    availability_domain=ad.name
                ).data
                
                for fs in file_systems:
                    # Get basic attributes
                    resource = {
                        'Resource Type': 'File System',
                        'Resource ID': fs.id,
                        'Name': fs.display_name,
                        'Compartment ID': fs.compartment_id,
                        'Lifecycle State': fs.lifecycle_state,
                        'Time Created': fs.time_created.strftime('%Y-%m-%d %H:%M:%S') if fs.time_created else 'N/A',
                        'Defined Tags': str(fs.defined_tags) if fs.defined_tags else '{}',
                        'Freeform Tags': str(fs.freeform_tags) if fs.freeform_tags else '{}',
                        'Availability Domain': fs.availability_domain,
                        'Size': f"{getattr(fs, 'metered_bytes', 0) / (1024**3):.2f} GB" if hasattr(fs, 'metered_bytes') else 'N/A'
                    }
                    
                    # Get Resource Group
                    resource['Resource Group'] = extract_resource_group(fs.defined_tags)
                    
                    # Add region information if available in the ID
                    if fs.id:
                        parts = fs.id.split('.')
                        if len(parts) > 3:
                            resource['Region'] = parts[3]
                        else:
                            resource['Region'] = 'N/A'
                    else:
                        resource['Region'] = 'N/A'
                        
                    resources.append(resource)
            except Exception as ad_error:
                print(f"Error getting file systems in AD {ad.name}: {ad_error}")
        
        print(f"Found {len(resources)} File Systems")
    except Exception as e:
        print(f"Error getting File Systems: {e}")
    
    return resources

def get_resources_direct_api(config, compartment_id, available_regions=None):
    """Get resources using direct API calls."""
    print(f"Discovering resources in compartment {compartment_id} using direct API calls...")
    
    all_resources = []
    
    # Initialize clients
    compute_client = oci.core.ComputeClient(config)
    network_client = oci.core.VirtualNetworkClient(config)
    block_storage_client = oci.core.BlockstorageClient(config)
    object_storage_client = oci.object_storage.ObjectStorageClient(config)
    database_client = oci.database.DatabaseClient(config)
    load_balancer_client = oci.load_balancer.LoadBalancerClient(config)
    identity_client = oci.identity.IdentityClient(config)
    file_storage_client = oci.file_storage.FileStorageClient(config)
    
    # Call resource-specific methods
    all_resources.extend(get_instances(compute_client, compartment_id))
    all_resources.extend(get_vcns(network_client, compartment_id))
    all_resources.extend(get_subnets(network_client, compartment_id))
    all_resources.extend(get_block_volumes(block_storage_client, compartment_id))
    all_resources.extend(get_boot_volumes(block_storage_client, identity_client, compartment_id))
    all_resources.extend(get_buckets(object_storage_client, compartment_id))
    all_resources.extend(get_database_systems(database_client, compartment_id))
    all_resources.extend(get_autonomous_databases(database_client, compartment_id))
    all_resources.extend(get_load_balancers(load_balancer_client, compartment_id))
    all_resources.extend(get_file_systems(file_storage_client, identity_client, compartment_id))
    
    # Add additional resource types as needed
    
    return all_resources

def process_search_result(resource, compartment_path):
    """Process a resource returned by the Resource Search API."""
    # Basic resource information
    resource_type = resource.resource_type.split('.')[-1] if '.' in resource.resource_type else resource.resource_type
    service = resource.resource_type.split('.')[0] if '.' in resource.resource_type else ''
    
    # Extract region from OCID
    region = resource.identifier.split('.')[3] if len(resource.identifier.split('.')) > 3 else 'N/A'
    
    # Format time created
    time_created = resource.time_created
    if time_created and hasattr(time_created, 'strftime'):
        time_created = time_created.strftime('%Y-%m-%d %H:%M:%S')
    
    # Extract resource group
    resource_group = extract_resource_group(resource.defined_tags)
    
    # Create the resource record
    return {
        'Compartment Name': compartment_path,
        'Resource Name': resource.display_name,
        'Resource Group': resource_group,
        'Compartment ID': resource.compartment_id,
        'Service': service,
        'Resource Type': resource_type,
        'Resource ID': resource.identifier,
        'Region': region,
        'Availability Domain': resource.availability_domain if resource.availability_domain else 'N/A',
        'Lifecycle State': resource.lifecycle_state,
        'Time Created': time_created,
        'Defined Tags': str(resource.defined_tags) if resource.defined_tags else '{}',
        'Freeform Tags': str(resource.freeform_tags) if resource.freeform_tags else '{}'
    }

def main():
    """Main function."""
    args = parse_arguments()
    start_time = time.time()
    
    # Set default output file if not specified
    if not args.output_file:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output_file = f"{args.compartment_name}_resources_{timestamp}.csv"
    
    print(f"OCI Tenancy Explorer")
    print(f"==================")
    
    # Load OCI configuration
    config_file = os.path.expanduser(args.config_file)
    try:
        config = oci.config.from_file(config_file, args.profile)
    except Exception as e:
        print(f"Error loading OCI configuration: {e}")
        print("Make sure you have set up the OCI CLI configuration file at ~/.oci/config")
        sys.exit(1)
    
    # Initialize clients
    identity_client = oci.identity.IdentityClient(config)
    search_client = oci.resource_search.ResourceSearchClient(config)
    
    # Get tenancy ID from config
    tenancy_id = config["tenancy"]
    
    # Get compartment ID
    try:
        compartment_id = get_compartment_id_by_name(identity_client, tenancy_id, args.compartment_name)
        print(f"Found compartment ID: {compartment_id}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Get all compartments for path resolution
    all_compartments = get_all_compartments(identity_client, tenancy_id)
    compartment_map = {c.id: c for c in all_compartments}
    
    # Determine which compartments to search
    compartments_to_search = []
    if args.recursive:
        # Get parent compartment
        parent_compartment = identity_client.get_compartment(compartment_id).data
        compartments_to_search.append(parent_compartment)
        
        # Get child compartments
        child_compartments = [c for c in all_compartments if hasattr(c, 'compartment_id') and c.compartment_id == compartment_id]
        compartments_to_search.extend(child_compartments)
        
        print(f"Recursively searching {args.compartment_name} and {len(child_compartments)} child compartments")
    else:
        # Just search the specified compartment
        compartments_to_search.append(identity_client.get_compartment(compartment_id).data)
        print(f"Searching single compartment: {args.compartment_name}")
    
    # Collect all resources
    all_resources = []
    
    for compartment in compartments_to_search:
        compartment_path = get_compartment_path(compartment.id, compartment_map)
        print(f"\nProcessing compartment: {compartment_path}")
        
        # Discover resources
        if args.search_api:
            # Use Resource Search API
            resources = get_resources_search_api(search_client, compartment.id)
            
            # Process the search results
            for resource in resources:
                resource_record = process_search_result(resource, compartment_path)
                all_resources.append(resource_record)
                
            print(f"Found {len(resources)} resources in {compartment_path}")
        else:
            # Use direct API calls
            compartment_resources = get_resources_direct_api(config, compartment.id)
            
            # Add compartment path to each resource
            for resource in compartment_resources:
                resource['Compartment Name'] = compartment_path
                
            all_resources.extend(compartment_resources)
            
            print(f"Found {len(compartment_resources)} resources in {compartment_path}")
    
    print(f"\nDiscovered {len(all_resources)} total resources")
    
    # Find cross-compartment references
    all_resources = find_cross_compartment_references(all_resources, compartment_map)
    
    # Define CSV headers - make sure all possible fields are included
    required_headers = [
        'Compartment Name', 
        'Resource Name', 
        'Resource Group',
        'Compartment ID', 
        'Service', 
        'Resource Type', 
        'Resource ID',
        'Region', 
        'Availability Domain', 
        'Shape',
        'OCPU Count',
        'Memory',
        'Storage Size',
        'CIDR Block',
        'Public Access',
        'Lifecycle State', 
        'Time Created',
        'Cross-Compartment References',
        'Defined Tags', 
        'Freeform Tags'
    ]
    
    # Add any additional headers found in resources
    all_headers = set(required_headers)
    for resource in all_resources:
        all_headers.update(resource.keys())
    
    # Sort headers with required headers first, then alphabetically for the rest
    headers = required_headers + sorted(h for h in all_headers if h not in required_headers)
    
    # Write to CSV
    print(f"\nWriting resources to {args.output_file}")
    with open(args.output_file, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(all_resources)
    
    elapsed_time = time.time() - start_time
    print(f"Finished in {elapsed_time:.2f} seconds")
    print(f"Results saved to {args.output_file}")

if __name__ == "__main__":
    main()