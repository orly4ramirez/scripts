#!/usr/bin/env python3
"""
OCI Tenancy Explorer

This script emulates the OCI Tenancy Explorer functionality by recursively discovering
all resources within a compartment (including child compartments) and exporting
the results to a CSV file.

Usage: python oci_tenancy_explorer.py --compartment-name "your-compartment-name" [--recursive] [--output-file "output.csv"]
"""

import argparse
import csv
import oci
import sys
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='OCI Tenancy Explorer - Extract all resources from OCI compartments')
    parser.add_argument('--compartment-name', required=True, help='Name of the compartment to extract resources from')
    parser.add_argument('--recursive', action='store_true', help='Recursively search child compartments')
    parser.add_argument('--output-file', default='oci_resources.csv', help='Output CSV file path (default: oci_resources.csv)')
    parser.add_argument('--config-file', default='~/.oci/config', help='OCI config file path (default: ~/.oci/config)')
    parser.add_argument('--profile', default='DEFAULT', help='OCI config profile (default: DEFAULT)')
    parser.add_argument('--max-workers', type=int, default=10, help='Maximum number of worker threads (default: 10)')
    return parser.parse_args()

def get_all_compartments(identity_client, tenancy_id, parent_compartment_id=None):
    """Get all compartments in the tenancy or within a parent compartment."""
    try:
        if parent_compartment_id is None:
            parent_compartment_id = tenancy_id
            
        all_compartments = []
        
        # Get tenancy as a compartment
        if parent_compartment_id == tenancy_id:
            tenancy = identity_client.get_compartment(tenancy_id).data
            all_compartments.append(tenancy)
        
        # Get all compartments under parent
        compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            parent_compartment_id,
            compartment_id_in_subtree=False,  # Just immediate children
            lifecycle_state="ACTIVE"
        ).data
        
        all_compartments.extend(compartments)
        
        # Recursively get children of each compartment
        for compartment in compartments:
            child_compartments = get_all_compartments(identity_client, tenancy_id, compartment.id)
            all_compartments.extend(child_compartments)
            
        return all_compartments
    except Exception as e:
        print(f"Error listing compartments: {e}")
        return []

def get_compartment_by_name(identity_client, tenancy_id, compartment_name):
    """Find compartment by name."""
    # First check if it's the tenancy (root compartment)
    try:
        tenancy = identity_client.get_compartment(tenancy_id).data
        if tenancy.name == compartment_name:
            return tenancy
    except Exception as e:
        print(f"Error getting tenancy info: {e}")
    
    # Get all compartments and find the one with the matching name
    all_compartments = get_all_compartments(identity_client, tenancy_id)
    
    matching_compartments = [c for c in all_compartments if c.name == compartment_name]
    
    if not matching_compartments:
        print(f"Compartment '{compartment_name}' not found or not accessible")
        sys.exit(1)
    
    if len(matching_compartments) > 1:
        print(f"Warning: Multiple compartments found with name '{compartment_name}'. Using the first one.")
        
    return matching_compartments[0]

def get_resources(service_name, resource_type, list_resources_func, compartment_id, region=None, compartment_name='Unknown'):
    """Get resources of a specific type with enhanced details."""
    try:
        resources = []
        
        # Handle special cases where list function might need additional parameters
        if service_name == "Object Storage" and resource_type == "Buckets":
            # Special handling for buckets which require namespace
            namespace = list_resources_func().data
            bucket_list_func = lambda compartment_id: oci.object_storage.ObjectStorageClient.list_buckets(namespace, compartment_id)
            resources = oci.pagination.list_call_get_all_results(bucket_list_func, compartment_id).data
        elif service_name == "Logging" and "Logs" in resource_type:
            # The log group ID is passed instead of compartment ID
            log_group_id = compartment_id  # In this case, compartment_id is actually log_group_id
            resources = oci.pagination.list_call_get_all_results(list_resources_func, log_group_id).data
        else:
            # Standard case for most resources
            resources = oci.pagination.list_call_get_all_results(list_resources_func, compartment_id=compartment_id).data
        
        results = []
        for resource in resources:
            # Extract common attributes safely
            resource_id = getattr(resource, 'id', 'N/A')
            
            # Try different name attributes that OCI uses
            resource_name = 'N/A'
            for name_attr in ['display_name', 'name']:
                if hasattr(resource, name_attr) and getattr(resource, name_attr) is not None:
                    resource_name = getattr(resource, name_attr)
                    break
            
            lifecycle_state = getattr(resource, 'lifecycle_state', 'N/A')
            time_created = getattr(resource, 'time_created', 'N/A')
            
            # Format time_created if it exists
            if time_created and time_created != 'N/A':
                if isinstance(time_created, (datetime, oci.util.datetime_with_timezone)):
                    time_created = time_created.strftime('%Y-%m-%d %H:%M:%S')
            
            # Resource OCID (Oracle Cloud ID) components
            ocid_parts = resource_id.split('.') if resource_id != 'N/A' else []
            resource_region = region or (ocid_parts[3] if len(ocid_parts) > 3 else 'N/A')
            
            # Get resource-specific details based on resource type
            resource_shape = 'N/A'
            resource_size = 'N/A'
            resource_size_unit = ''
            is_public = 'N/A'
            cidr_block = 'N/A'
            ocpu_count = 'N/A'
            memory_size = 'N/A'
            parent_resource = 'N/A'
            parent_compartment = 'N/A'
            last_modified = 'N/A'
            cross_compartment_refs = []
            resource_group = 'N/A'
            
            # Check for resource group membership (via defined tags)
            defined_tags = getattr(resource, 'defined_tags', {})
            if defined_tags and isinstance(defined_tags, dict):
                # Look for Oracle-ResourceGroup namespace in defined tags
                if 'Oracle-ResourceGroup' in defined_tags:
                    rg_tags = defined_tags['Oracle-ResourceGroup']
                    if isinstance(rg_tags, dict):
                        # Get the resource group name
                        if 'resourcegroup' in rg_tags:
                            resource_group = rg_tags['resourcegroup']
                        
                        # Or try alternative key names
                        elif 'ResourceGroup' in rg_tags:
                            resource_group = rg_tags['ResourceGroup']
                
                # Some resources might use a different tag format
                elif 'oracle-resourcegroup' in defined_tags:
                    rg_tags = defined_tags['oracle-resourcegroup']
                    if isinstance(rg_tags, dict):
                        for tag_key, tag_value in rg_tags.items():
                            if 'resourcegroup' in tag_key.lower():
                                resource_group = tag_value
                                break
            
            # Extract resource-specific information
            if service_name == "Compute" and resource_type == "Instances":
                resource_shape = getattr(resource, 'shape', 'N/A')
                
                # Get OCPU and memory details if available
                shape_config = getattr(resource, 'shape_config', None)
                if shape_config:
                    ocpu_count = getattr(shape_config, 'ocpus', 'N/A')
                    memory_size = f"{getattr(shape_config, 'memory_in_gbs', 'N/A')} GB"
                
                # Check for public IP
                if hasattr(resource, 'public_ip') and resource.public_ip:
                    is_public = 'Yes'
                else:
                    is_public = 'No'
                
                # Check for cross-compartment subnet reference
                subnet_id = getattr(resource, 'subnet_id', None)
                if subnet_id:
                    cross_compartment_refs.append(f"Subnet:{subnet_id}")
                
                # Check for boot volume in different compartment
                boot_vol_attachment_id = getattr(resource, 'boot_volume_id', None)
                if boot_vol_attachment_id:
                    cross_compartment_refs.append(f"BootVolume:{boot_vol_attachment_id}")
                    
            elif service_name == "Block Storage" and resource_type in ["Block Volumes", "Boot Volumes"]:
                resource_size = f"{getattr(resource, 'size_in_gbs', 'N/A')} GB"
                resource_size_unit = 'GB'
                
                # Check for attachments to instances in different compartments
                if resource_type == "Block Volumes":
                    attachment_id = getattr(resource, 'attached_instance_id', None)
                    if attachment_id:
                        cross_compartment_refs.append(f"Instance:{attachment_id}")
                
            elif service_name == "Networking" and resource_type == "VCNs":
                cidr_block = getattr(resource, 'cidr_block', 'N/A')
                
            elif service_name == "Networking" and resource_type == "Subnets":
                cidr_block = getattr(resource, 'cidr_block', 'N/A')
                vcn_id = getattr(resource, 'vcn_id', 'N/A')
                parent_resource = f"VCN: {vcn_id}"
                
                # Check if VCN is in a different compartment
                if vcn_id != 'N/A':
                    cross_compartment_refs.append(f"VCN:{vcn_id}")
                    
                is_public = 'Yes' if getattr(resource, 'prohibit_public_ip_on_vnic', False) == False else 'No'
                
            elif service_name == "Networking" and resource_type in ["Route Tables", "Security Lists", "Network Security Groups"]:
                vcn_id = getattr(resource, 'vcn_id', 'N/A')
                parent_resource = f"VCN: {vcn_id}"
                
                # Check if VCN is in a different compartment
                if vcn_id != 'N/A':
                    cross_compartment_refs.append(f"VCN:{vcn_id}")
                
            elif service_name == "Database" and resource_type == "Autonomous Databases":
                resource_size = f"{getattr(resource, 'data_storage_size_in_tbs', 'N/A')} TB"
                resource_size_unit = 'TB'
                ocpu_count = getattr(resource, 'cpu_core_count', 'N/A')
                # Extract DB version
                db_version = getattr(resource, 'db_version', 'N/A')
                resource_shape = f"Autonomous DB v{db_version}" if db_version != 'N/A' else 'N/A'
                
                # Check for cross-compartment subnet reference
                subnet_id = getattr(resource, 'subnet_id', None)
                if subnet_id:
                    cross_compartment_refs.append(f"Subnet:{subnet_id}")
                
            elif service_name == "Database" and resource_type == "DB Systems":
                resource_shape = getattr(resource, 'shape', 'N/A')
                ocpu_count = getattr(resource, 'cpu_core_count', 'N/A')
                # Extract DB version
                db_version = getattr(resource, 'version', 'N/A')
                if db_version != 'N/A':
                    resource_shape = f"{resource_shape} v{db_version}"
                
                # Check for cross-compartment subnet reference
                subnet_id = getattr(resource, 'subnet_id', None)
                if subnet_id:
                    cross_compartment_refs.append(f"Subnet:{subnet_id}")
                    
            elif service_name == "Object Storage" and resource_type == "Buckets":
                # Try to get approximate size if available
                if hasattr(resource, 'approximate_size'):
                    approximate_size = getattr(resource, 'approximate_size', 'N/A')
                    if approximate_size != 'N/A':
                        size_bytes = int(approximate_size)
                        if size_bytes > 1024**4:  # TB
                            resource_size = f"{size_bytes/(1024**4):.2f} TB"
                            resource_size_unit = 'TB'
                        elif size_bytes > 1024**3:  # GB
                            resource_size = f"{size_bytes/(1024**3):.2f} GB" 
                            resource_size_unit = 'GB'
                        elif size_bytes > 1024**2:  # MB
                            resource_size = f"{size_bytes/(1024**2):.2f} MB"
                            resource_size_unit = 'MB'
                        else:
                            resource_size = f"{size_bytes} bytes"
                            resource_size_unit = 'bytes'
                
                # Check public access
                is_public = 'Yes' if getattr(resource, 'public_access_type', 'NoPublicAccess') != 'NoPublicAccess' else 'No'
                
            elif service_name == "Load Balancer" and resource_type == "Load Balancers":
                resource_shape = getattr(resource, 'shape_name', 'N/A')
                is_public = 'Yes' if getattr(resource, 'is_private', False) == False else 'No'
                
                # Check for cross-compartment subnet references
                subnet_ids = getattr(resource, 'subnet_ids', [])
                for subnet_id in subnet_ids:
                    if subnet_id:
                        cross_compartment_refs.append(f"Subnet:{subnet_id}")
                
                # Check for cross-compartment backend sets
                backend_sets = getattr(resource, 'backend_sets', {})
                for backend_set_name, backend_set in backend_sets.items():
                    if hasattr(backend_set, 'backends'):
                        for backend in backend_set.backends:
                            if hasattr(backend, 'instance_id') and backend.instance_id:
                                cross_compartment_refs.append(f"Instance:{backend.instance_id}")
                
            elif service_name == "Container Engine" and resource_type == "Clusters":
                k8s_version = getattr(resource, 'kubernetes_version', 'N/A')
                resource_shape = f"Kubernetes v{k8s_version}" if k8s_version != 'N/A' else 'N/A'
                
                # Check for cross-compartment VCN reference
                vcn_id = getattr(resource, 'vcn_id', None)
                if vcn_id:
                    cross_compartment_refs.append(f"VCN:{vcn_id}")
            
            # Get last modified time for applicable resources
            if hasattr(resource, 'time_updated'):
                last_modified = getattr(resource, 'time_updated', 'N/A')
                if last_modified and last_modified != 'N/A':
                    if isinstance(last_modified, (datetime, oci.util.datetime_with_timezone)):
                        last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')
            
            # Get additional details as a fallback for any attributes not explicitly handled
            details = {}
            for attr in dir(resource):
                if not attr.startswith('_') and not callable(getattr(resource, attr)) and attr not in [
                    'id', 'display_name', 'name', 'lifecycle_state', 'time_created', 'shape', 'shape_config',
                    'size_in_gbs', 'cidr_block', 'vcn_id', 'data_storage_size_in_tbs', 'cpu_core_count',
                    'db_version', 'version', 'approximate_size', 'public_access_type', 'is_private',
                    'kubernetes_version', 'time_updated', 'subnet_id', 'subnet_ids', 'backend_sets',
                    'defined_tags'
                ]:
                    value = getattr(resource, attr)
                    # Format simple values only
                    if isinstance(value, (str, int, float, bool)) or value is None:
                        details[attr] = value
            
            # Format additional details as a string
            details_str = '; '.join([f"{k}={v}" for k, v in details.items() if v is not None])
            
            # Format cross compartment references
            cross_compartment_str = '; '.join(cross_compartment_refs) if cross_compartment_refs else 'None'
            
            results.append({
                'Compartment Name': compartment_name,
                'Compartment ID': compartment_id,
                'Resource Group': resource_group,
                'Service': service_name,
                'Resource Type': resource_type,
                'Resource ID': resource_id,
                'Name': resource_name,
                'Region': resource_region,
                'Availability Domain': getattr(resource, 'availability_domain', 'N/A'),
                'Shape': resource_shape,
                'OCPU Count': ocpu_count,
                'Memory': memory_size,
                'Storage Size': resource_size,
                'CIDR Block': cidr_block,
                'Public Access': is_public,
                'Parent Resource': parent_resource,
                'Cross-Compartment References': cross_compartment_str,
                'Lifecycle State': lifecycle_state,
                'Time Created': time_created,
                'Last Modified': last_modified,
                'Defined Tags': str(getattr(resource, 'defined_tags', {})),
                'Freeform Tags': str(getattr(resource, 'freeform_tags', {})),
                'Additional Details': details_str
            })
        
        return results
    except Exception as e:
        print(f"Error fetching {service_name} - {resource_type}: {e}")
        return []

def get_service_clients(config):
    """Initialize all OCI service clients."""
    clients = {}
    
    # Core services
    clients['compute'] = oci.core.ComputeClient(config)
    clients['network'] = oci.core.VirtualNetworkClient(config)
    clients['block_storage'] = oci.core.BlockstorageClient(config)
    clients['object_storage'] = oci.object_storage.ObjectStorageClient(config)
    clients['database'] = oci.database.DatabaseClient(config)
    clients['identity'] = oci.identity.IdentityClient(config)
    clients['load_balancer'] = oci.load_balancer.LoadBalancerClient(config)
    clients['file_storage'] = oci.file_storage.FileStorageClient(config)
    
    # Additional services (initialize only what we need)
    try:
        clients['container_engine'] = oci.container_engine.ContainerEngineClient(config)
        clients['functions'] = oci.functions.FunctionsManagementClient(config)
        clients['streaming'] = oci.streaming.StreamAdminClient(config)
        clients['analytics'] = oci.analytics.AnalyticsClient(config)
        clients['apigateway'] = oci.apigateway.ApiGatewayClient(config)
        clients['nosql'] = oci.nosql.NosqlClient(config)
        clients['monitoring'] = oci.monitoring.MonitoringClient(config)
        clients['dns'] = oci.dns.DnsClient(config)
        # Skip KMS for now - requires service endpoint
        # clients['kms_management'] = oci.key_management.KmsManagementClient(config)
        clients['logs'] = oci.logging.LoggingManagementClient(config)
        clients['data_science'] = oci.data_science.DataScienceClient(config)
        clients['events'] = oci.events.EventsClient(config)
        clients['integration'] = oci.integration.IntegrationInstanceClient(config)
        clients['devops'] = oci.devops.DevopsClient(config)
        clients['budget'] = oci.budget.BudgetClient(config)
        clients['bastion'] = oci.bastion.BastionClient(config)
        clients['audit'] = oci.audit.AuditClient(config)
        clients['announcements'] = oci.announcements_service.AnnouncementClient(config)
        clients['usage'] = oci.usage_api.UsageapiClient(config)
        clients['oke'] = oci.container_engine.ContainerEngineClient(config)
        clients['email'] = oci.email.EmailClient(config)
        clients['data_catalog'] = oci.data_catalog.DataCatalogClient(config)
    except Exception as e:
        print(f"Warning: Some service clients could not be initialized: {e}")
    
    return clients

def define_resource_tasks(clients, compartment_id):
    """Define all resource extraction tasks."""
    resource_tasks = []
    
    # Map of service name -> list of (resource type, client method)
    service_resources = {
        "Compute": [
            ("Instances", clients['compute'].list_instances),
            ("Images", clients['compute'].list_images),
            ("Boot Volume Attachments", clients['compute'].list_boot_volume_attachments),
            ("Volume Attachments", clients['compute'].list_volume_attachments),
            ("Instance Configurations", clients['compute'].list_instance_configurations),
            ("Instance Pools", clients['compute'].list_instance_pools),
            ("Dedicated VM Hosts", clients['compute'].list_dedicated_vm_hosts),
            ("Cluster Networks", clients['compute'].list_cluster_networks),
            ("Compute Capacity Reports", clients['compute'].list_compute_capacity_reports),
        ],
        "Block Storage": [
            ("Block Volumes", clients['block_storage'].list_volumes),
            ("Boot Volumes", clients['block_storage'].list_boot_volumes),
            ("Volume Backups", clients['block_storage'].list_volume_backups),
            ("Volume Groups", clients['block_storage'].list_volume_groups),
            ("Volume Group Backups", clients['block_storage'].list_volume_group_backups),
        ],
        "Networking": [
            ("VCNs", clients['network'].list_vcns),
            ("Subnets", clients['network'].list_subnets),
            ("Internet Gateways", clients['network'].list_internet_gateways),
            ("NAT Gateways", clients['network'].list_nat_gateways),
            ("Service Gateways", clients['network'].list_service_gateways),
            ("Local Peering Gateways", clients['network'].list_local_peering_gateways),
            ("Route Tables", clients['network'].list_route_tables),
            ("Security Lists", clients['network'].list_security_lists),
            ("Network Security Groups", clients['network'].list_network_security_groups),
            ("DHCP Options", clients['network'].list_dhcp_options),
            ("DRGs", clients['network'].list_drgs),
            ("IPSec Connections", clients['network'].list_ip_sec_connections),
            ("Public IPs", clients['network'].list_public_ips),
            ("VLANs", clients['network'].list_vlans),
            ("Virtual Circuits", clients['network'].list_virtual_circuits),
        ],
        "Database": [
            ("DB Systems", clients['database'].list_db_systems),
            ("Autonomous Databases", clients['database'].list_autonomous_databases),
            ("Autonomous Database Backups", clients['database'].list_autonomous_database_backups),
            ("DB Backups", clients['database'].list_backups),
            ("Exadata Infrastructures", clients['database'].list_exadata_infrastructures),
            ("Autonomous Container Databases", clients['database'].list_autonomous_container_databases),
            ("Autonomous VM Clusters", clients['database'].list_autonomous_vm_clusters),
            ("DB Homes", clients['database'].list_db_homes),
        ],
        "Object Storage": [
            ("Buckets", clients['object_storage'].get_namespace),
        ],
        "File Storage": [
            ("File Systems", clients['file_storage'].list_file_systems),
            ("Mount Targets", clients['file_storage'].list_mount_targets),
            ("Export Sets", clients['file_storage'].list_export_sets),
        ],
        "Load Balancer": [
            ("Load Balancers", clients['load_balancer'].list_load_balancers),
        ],
    }
    
    # Add resources if their corresponding clients are available
    if 'container_engine' in clients:
        service_resources["Container Engine"] = [
            ("Clusters", clients['container_engine'].list_clusters),
            ("Node Pools", clients['container_engine'].list_node_pools),
        ]
    
    if 'functions' in clients:
        service_resources["Functions"] = [
            ("Applications", clients['functions'].list_applications),
        ]
    
    if 'streaming' in clients:
        service_resources["Streaming"] = [
            ("Stream Pools", clients['streaming'].list_stream_pools),
        ]
    
    if 'analytics' in clients:
        service_resources["Analytics"] = [
            ("Analytics Instances", clients['analytics'].list_analytics_instances),
        ]
    
    if 'apigateway' in clients:
        service_resources["API Gateway"] = [
            ("Gateways", clients['apigateway'].list_gateways),
            ("Deployments", clients['apigateway'].list_deployments),
        ]
    
    if 'nosql' in clients:
        service_resources["NoSQL"] = [
            ("Tables", clients['nosql'].list_tables),
        ]
    
    if 'monitoring' in clients:
        service_resources["Monitoring"] = [
            ("Alarms", clients['monitoring'].list_alarms),
        ]
    
    if 'dns' in clients:
        service_resources["DNS"] = [
            ("Zones", clients['dns'].list_zones),
        ]
    
    if 'data_science' in clients:
        service_resources["Data Science"] = [
            ("Projects", clients['data_science'].list_projects),
            ("Notebook Sessions", clients['data_science'].list_notebook_sessions),
            ("Models", clients['data_science'].list_models),
        ]
    
    if 'events' in clients:
        service_resources["Events"] = [
            ("Rules", clients['events'].list_rules),
        ]
    
    if 'devops' in clients:
        service_resources["DevOps"] = [
            ("Projects", clients['devops'].list_projects),
        ]
    
    if 'budget' in clients:
        service_resources["Budget"] = [
            ("Budgets", clients['budget'].list_budgets),
        ]
    
    if 'bastion' in clients:
        service_resources["Bastion"] = [
            ("Bastions", clients['bastion'].list_bastions),
        ]
    
    if 'email' in clients:
        service_resources["Email"] = [
            ("Senders", clients['email'].list_senders),
            ("Suppressions", clients['email'].list_suppressions),
        ]
    
    if 'data_catalog' in clients:
        service_resources["Data Catalog"] = [
            ("Catalogs", clients['data_catalog'].list_catalogs),
        ]
    
    # Create resource tasks from the service_resources map
    for service_name, resources in service_resources.items():
        for resource_type, list_func in resources:
            resource_tasks.append((service_name, resource_type, list_func, compartment_id))
    
    # Additional resources that require special handling
    
    # Skip KMS for now due to service endpoint requirement
    
    # Get Log Groups and Logs
    if 'logs' in clients:
        try:
            log_groups = oci.pagination.list_call_get_all_results(
                clients['logs'].list_log_groups,
                compartment_id=compartment_id
            ).data
            
            for log_group in log_groups:
                try:
                    resource_tasks.append(
                        ("Logging", f"Logs (Group: {log_group.display_name})",
                         lambda log_group_id=log_group.id: clients['logs'].list_logs(log_group_id),
                         log_group.id)  # Note: passing log_group.id instead of compartment_id
                    )
                except Exception as e:
                    print(f"Error setting up log listing for {log_group.display_name}: {e}")
        except Exception as e:
            print(f"Error listing log groups: {e}")
    
    return resource_tasks

def explore_tenancy(compartment_id, compartment_name, clients, max_workers=10):
    """Explore a compartment to find all resources."""
    # Define resource tasks for the compartment
    resource_tasks = define_resource_tasks(clients, compartment_id)
    
    # Extract resources in parallel
    all_resources = []
    
    print(f"\nExploring resources in {compartment_name}...")
    print(f"Found {len(resource_tasks)} resource types to scan")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        
        for service_name, resource_type, list_func, cid in resource_tasks:
            future = executor.submit(get_resources, service_name, resource_type, list_func, cid, None, compartment_name)
            futures.append((future, service_name, resource_type))
        
        completed = 0
        for future, service_name, resource_type in futures:
            try:
                resources = future.result()
                completed += 1
                
                # More concise progress indicator
                resource_count = len(resources)
                print(f"[{completed}/{len(futures)}] {service_name}/{resource_type}: {resource_count} found")
                
                all_resources.extend(resources)
            except Exception as e:
                print(f"[{completed}/{len(futures)}] {service_name}/{resource_type}: Error - {str(e)[:100]}")
                completed += 1
    
    return all_resources

def write_csv(resources, output_file):
    """Write resources to CSV file."""
    if not resources:
        print("No resources found to write to CSV.")
        return
    
    # Define CSV headers - Compartment Name first, then Resource Name, then Resource Group
    fieldnames = [
        'Compartment Name', 'Name', 'Resource Group', 'Compartment ID', 'Service', 'Resource Type', 'Resource ID',
        'Region', 'Availability Domain', 'Shape', 'OCPU Count', 'Memory', 'Storage Size', 
        'CIDR Block', 'Public Access', 'Parent Resource', 'Cross-Compartment References', 'Lifecycle State', 
        'Time Created', 'Last Modified', 'Defined Tags', 'Freeform Tags', 'Additional Details'
    ]
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(resources)
        print(f"Resource inventory successfully written to {output_file}")
    except Exception as e:
        print(f"Error writing to CSV file: {e}")

def get_compartment_path(identity_client, compartment, compartments_by_id):
    """Recursive function to build compartment path."""
    if compartment.id in compartments_by_id and compartment.compartment_id:
        parent = compartments_by_id.get(compartment.compartment_id)
        if parent:
            return get_compartment_path(identity_client, parent, compartments_by_id) + " / " + compartment.name
    return compartment.name

def build_compartment_hierarchy(identity_client, tenancy_id, compartments):
    """Build compartment hierarchy paths for all compartments."""
    compartments_by_id = {c.id: c for c in compartments}
    
    # Add tenancy as root
    try:
        tenancy = identity_client.get_compartment(tenancy_id).data
        compartments_by_id[tenancy_id] = tenancy
    except Exception as e:
        print(f"Error getting tenancy details: {e}")
    
    hierarchy = {}
    for compartment in compartments:
        path = get_compartment_path(identity_client, compartment, compartments_by_id)
        hierarchy[compartment.id] = path
    
    return hierarchy

def get_compartment_full_path(compartment_name, compartment_id, compartment_hierarchy):
    """Get the full path of a compartment if available in hierarchy."""
    if compartment_id in compartment_hierarchy:
        return compartment_hierarchy[compartment_id]
    return compartment_name

def main():
    """Main function."""
    args = parse_arguments()
    start_time = time.time()
    
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
    print("Initializing OCI clients...")
    clients = get_service_clients(config)
    tenancy_id = config.get('tenancy')
    
    # Find the target compartment
    print(f"Looking for compartment: {args.compartment_name}")
    compartment = get_compartment_by_name(clients['identity'], tenancy_id, args.compartment_name)
    print(f"Found compartment: {compartment.name} (ID: {compartment.id})")
    
    compartments_to_scan = []
    all_compartments = []
    
    if args.recursive:
        print("Scanning for child compartments...")
        
        # Get all compartments first
        all_compartments = get_all_compartments(clients['identity'], tenancy_id)
        
        # Build compartment hierarchy
        compartment_hierarchy = build_compartment_hierarchy(clients['identity'], tenancy_id, all_compartments)
        
        # Filter compartments to include target and its children
        compartments_to_scan = [c for c in all_compartments 
                               if c.id == compartment.id or 
                               (hasattr(c, 'compartment_id') and c.compartment_id == compartment.id)]
        
        # Print compartment hierarchy
        print(f"Found {len(compartments_to_scan)} compartments to scan:")
        for c in compartments_to_scan:
            if c.id in compartment_hierarchy:
                print(f"  - {compartment_hierarchy[c.id]} ({c.id})")
            else:
                print(f"  - {c.name} ({c.id})")
    else:
        compartments_to_scan = [compartment]
        print(f"Scanning single compartment: {compartment.name}")
    
    # Build compartment hierarchy for all compartments
    compartment_hierarchy = build_compartment_hierarchy(clients['identity'], tenancy_id, all_compartments)
    
    all_resources = []
    for comp in compartments_to_scan:
        # Get full compartment path
        comp_full_path = get_compartment_full_path(comp.name, comp.id, compartment_hierarchy)
        print(f"\nExploring compartment: {comp_full_path} ({comp.id})...")
        resources = explore_tenancy(comp.id, comp_full_path, clients, args.max_workers)
        all_resources.extend(resources)
    
    print(f"\nResource exploration complete. Found {len(all_resources)} resources across all services.")
    write_csv(all_resources, args.output_file)
    
    elapsed_time = time.time() - start_time
    print(f"Total execution time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()