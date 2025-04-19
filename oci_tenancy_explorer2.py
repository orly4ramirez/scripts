#!/usr/bin/env python3
# oci_tenancy_explorer2.py - Enhanced
#
# An improved OCI tenancy explorer that addresses:
# 1. Full resource coverage across all OCI services
# 2. Recursive compartment traversal
# 3. Cross-compartment resource relationship mapping
# 4. Multi-region support (Ashburn and Phoenix)
# 5. Clear CSV output showing compartment hierarchy and resource relationships

import oci
import argparse
import csv
import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path
import concurrent.futures
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("oci_explorer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_REGIONS = ["us-ashburn-1", "us-phoenix-1"]
MAX_WORKERS = 10
TIMEOUT = 30

# Comprehensive list of all resource types by service
RESOURCE_TYPES = {
    "compute": {
        "instances": {
            "list_fn": "list_instances",
            "client": "compute"
        },
        "images": {
            "list_fn": "list_images",
            "client": "compute"
        },
        "instance_configurations": {
            "list_fn": "list_instance_configurations",
            "client": "compute"
        },
        "dedicated_vm_hosts": {
            "list_fn": "list_dedicated_vm_hosts",
            "client": "compute"
        },
        "cluster_networks": {
            "list_fn": "list_cluster_networks",
            "client": "compute"
        }
    },
    "storage": {
        "volumes": {
            "list_fn": "list_volumes",
            "client": "blockstorage"
        },
        "volume_backups": {
            "list_fn": "list_volume_backups",
            "client": "blockstorage"
        },
        "volume_groups": {
            "list_fn": "list_volume_groups",
            "client": "blockstorage"
        },
        "boot_volumes": {
            "list_fn": "list_boot_volumes",
            "client": "blockstorage"
        },
        "boot_volume_backups": {
            "list_fn": "list_boot_volume_backups",
            "client": "blockstorage"
        }
    },
    "file_storage": {
        "file_systems": {
            "list_fn": "list_file_systems",
            "client": "file_storage"
        },
        "mount_targets": {
            "list_fn": "list_mount_targets",
            "client": "file_storage"
        },
        "export_sets": {
            "list_fn": "list_export_sets",
            "client": "file_storage"
        }
    },
    "networking": {
        "vcns": {
            "list_fn": "list_vcns",
            "client": "virtual_network"
        },
        "subnets": {
            "list_fn": "list_subnets",
            "client": "virtual_network"
        },
        "security_lists": {
            "list_fn": "list_security_lists",
            "client": "virtual_network"
        },
        "network_security_groups": {
            "list_fn": "list_network_security_groups",
            "client": "virtual_network"
        },
        "route_tables": {
            "list_fn": "list_route_tables",
            "client": "virtual_network"
        },
        "internet_gateways": {
            "list_fn": "list_internet_gateways",
            "client": "virtual_network"
        },
        "nat_gateways": {
            "list_fn": "list_nat_gateways",
            "client": "virtual_network"
        },
        "service_gateways": {
            "list_fn": "list_service_gateways",
            "client": "virtual_network"
        },
        "local_peering_gateways": {
            "list_fn": "list_local_peering_gateways",
            "client": "virtual_network"
        },
        "drgs": {
            "list_fn": "list_drgs",
            "client": "virtual_network"
        },
        "private_ips": {
            "list_fn": "list_private_ips",
            "client": "virtual_network"
        },
        "public_ips": {
            "list_fn": "list_public_ips",
            "client": "virtual_network"
        }
    },
    "load_balancer": {
        "load_balancers": {
            "list_fn": "list_load_balancers",
            "client": "load_balancer"
        }
    },
    "object_storage": {
        "buckets": {
            "list_fn": "list_buckets",
            "client": "object_storage",
            "extra_args": {"namespace_name": "namespace_name"}
        }
    },
    "database": {
        "db_systems": {
            "list_fn": "list_db_systems",
            "client": "database"
        },
        "autonomous_databases": {
            "list_fn": "list_autonomous_databases",
            "client": "database"
        },
        "db_homes": {
            "list_fn": "list_db_homes",
            "client": "database"
        },
        "backups": {
            "list_fn": "list_backups",
            "client": "database"
        }
    },
    "identity": {
        "dynamic_groups": {
            "list_fn": "list_dynamic_groups",
            "client": "identity",
            "compartment_id_param": "compartment_id",
            "global_service": True
        },
        "policies": {
            "list_fn": "list_policies",
            "client": "identity"
        },
        "tag_namespaces": {
            "list_fn": "list_tag_namespaces",
            "client": "identity"
        }
    },
    "functions": {
        "applications": {
            "list_fn": "list_applications",
            "client": "functions"
        },
        "functions": {
            "list_fn": "list_functions",
            "client": "functions",
            "parent_id_param": "application_id",
            "parent_resource": "applications"
        }
    },
    "api_gateway": {
        "gateways": {
            "list_fn": "list_gateways",
            "client": "api_gateway"
        },
        "deployments": {
            "list_fn": "list_deployments",
            "client": "api_gateway"
        }
    },
    "events": {
        "rules": {
            "list_fn": "list_rules",
            "client": "events"
        }
    },
    "streaming": {
        "stream_pools": {
            "list_fn": "list_stream_pools",
            "client": "streaming"
        },
        "streams": {
            "list_fn": "list_streams",
            "client": "streaming",
            "parent_id_param": "stream_pool_id",
            "parent_resource": "stream_pools"
        }
    },
    "monitoring": {
        "alarms": {
            "list_fn": "list_alarms",
            "client": "monitoring"
        }
    },
    "notifications": {
        "topics": {
            "list_fn": "list_topics",
            "client": "notifications"
        },
        "subscriptions": {
            "list_fn": "list_subscriptions",
            "client": "notifications"
        }
    },
    "resource_manager": {
        "stacks": {
            "list_fn": "list_stacks",
            "client": "resource_manager"
        }
    },
    "data_science": {
        "projects": {
            "list_fn": "list_projects",
            "client": "data_science"
        },
        "notebook_sessions": {
            "list_fn": "list_notebook_sessions",
            "client": "data_science"
        },
        "models": {
            "list_fn": "list_models",
            "client": "data_science"
        }
    },
    "service_connector": {
        "service_connectors": {
            "list_fn": "list_service_connectors",
            "client": "service_connector"
        }
    }
}

# Define resource relationships (which fields contain references to other resources)
RESOURCE_RELATIONSHIPS = {
    "instances": [
        {"field": "subnet_id", "target_type": "subnets"},
        {"field": "image_id", "target_type": "images"},
        {"field": "volume_attachments", "target_type": "volumes", "is_list": True, "field_map": "volume_id"}
    ],
    "subnets": [
        {"field": "vcn_id", "target_type": "vcns"},
        {"field": "route_table_id", "target_type": "route_tables"},
        {"field": "security_list_ids", "target_type": "security_lists", "is_list": True}
    ],
    "volumes": [
        {"field": "availability_domain", "target_type": None},
        {"field": "backup_policy_id", "target_type": None}
    ],
    "load_balancers": [
        {"field": "subnet_ids", "target_type": "subnets", "is_list": True},
        {"field": "network_security_group_ids", "target_type": "network_security_groups", "is_list": True}
    ],
    "route_tables": [
        {"field": "vcn_id", "target_type": "vcns"}
    ],
    "security_lists": [
        {"field": "vcn_id", "target_type": "vcns"}
    ],
    "network_security_groups": [
        {"field": "vcn_id", "target_type": "vcns"}
    ],
    "nat_gateways": [
        {"field": "vcn_id", "target_type": "vcns"}
    ],
    "internet_gateways": [
        {"field": "vcn_id", "target_type": "vcns"}
    ],
    "service_gateways": [
        {"field": "vcn_id", "target_type": "vcns"}
    ],
    "local_peering_gateways": [
        {"field": "vcn_id", "target_type": "vcns"},
        {"field": "peer_id", "target_type": "local_peering_gateways"}
    ],
    "mount_targets": [
        {"field": "subnet_id", "target_type": "subnets"}
    ],
    "db_systems": [
        {"field": "subnet_id", "target_type": "subnets"}
    ],
    "autonomous_databases": [
        {"field": "subnet_id", "target_type": "subnets"}
    ]
}

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="OCI Tenancy Explorer - discovers and maps relationships between resources"
    )
    
    # Authentication options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("--config", default="~/.oci/config",
        help="OCI configuration file (default: ~/.oci/config)")
    auth_group.add_argument("--profile", default="DEFAULT",
        help="Profile in the OCI config file (default: DEFAULT)")
    auth_group.add_argument("--instance-principals", action="store_true",
        help="Use instance principals for authentication")
    
    # Region options
    region_group = parser.add_argument_group("Regions")
    region_group.add_argument("--regions", default="us-ashburn-1,us-phoenix-1",
        help="Comma-separated list of regions to scan (default: us-ashburn-1,us-phoenix-1)")
    region_group.add_argument("--all-regions", action="store_true",
        help="Scan all available regions")
    
    # Compartment options
    compartment_group = parser.add_argument_group("Compartments")
    compartment_group.add_argument("--compartment", 
        help="Name of the compartment to scan")
    compartment_group.add_argument("--compartment-id", 
        help="OCID of the compartment to scan")
    compartment_group.add_argument("--recursive", action="store_true", default=True,
        help="Scan compartments recursively (default: True)")
    compartment_group.add_argument("--include-root", action="store_true", default=True,
        help="Include root compartment in scan (default: True)")
    
    # Resource options
    resource_group = parser.add_argument_group("Resources")
    resource_group.add_argument("--all-resources", action="store_true", default=True,
        help="Discover all resource types (default: True)")
    resource_group.add_argument("--resource-types",
        help="Comma-separated list of resource types to scan (e.g. instances,volumes)")
    resource_group.add_argument("--excluded-types",
        help="Comma-separated list of resource types to exclude")
    
    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--output-dir", default="./oci_resources",
        help="Output directory for CSV files (default: ./oci_resources)")
    output_group.add_argument("--output-prefix", default="oci_resources",
        help="Prefix for output filenames (default: oci_resources)")
    output_group.add_argument("--relationships", action="store_true", default=True,
        help="Discover and map relationships between resources (default: True)")
    
    # Performance options
    perf_group = parser.add_argument_group("Performance")
    perf_group.add_argument("--max-workers", type=int, default=MAX_WORKERS,
        help=f"Maximum number of worker threads (default: {MAX_WORKERS})")
    perf_group.add_argument("--no-parallel", action="store_true",
        help="Disable parallel processing")
    
    return parser.parse_args()

def setup_auth(args):
    """Set up OCI authentication"""
    try:
        if args.instance_principals:
            logger.info("Using instance principals authentication")
            config = {}
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        else:
            config_file = os.path.expanduser(args.config)
            logger.info(f"Using config file authentication: {config_file}, profile: {args.profile}")
            config = oci.config.from_file(config_file, args.profile)
            signer = None
            
        # Create identity client
        identity = oci.identity.IdentityClient(config=config, signer=signer)
        
        # Get tenancy information
        tenancy_id = get_tenancy_id(config, identity)
        tenancy = identity.get_tenancy(tenancy_id).data
        
        logger.info(f"Connected to tenancy: {tenancy.name} ({tenancy_id})")
        
        return config, signer, identity, tenancy
    
    except Exception as e:
        logger.error(f"Error setting up authentication: {str(e)}")
        sys.exit(1)

def get_tenancy_id(config, identity):
    """Get the tenancy OCID from config or derive it"""
    if config and 'tenancy' in config:
        return config['tenancy']
    
    try:
        # For instance principals, we need to determine the tenancy from the current user
        user = identity.get_user(identity.base_client.signer.user).data
        return user.compartment_id
    except Exception as e:
        logger.error(f"Could not determine tenancy ID: {str(e)}")
        sys.exit(1)

def get_regions(args, identity, tenancy_id):
    """Get list of regions to scan based on args"""
    if args.all_regions:
        try:
            region_subscriptions = identity.list_region_subscriptions(tenancy_id).data
            regions = [r.region_name for r in region_subscriptions]
            logger.info(f"Scanning all subscribed regions: {', '.join(regions)}")
            return regions
        except Exception as e:
            logger.error(f"Error retrieving regions: {str(e)}")
            logger.info(f"Falling back to default regions: {', '.join(DEFAULT_REGIONS)}")
            return DEFAULT_REGIONS
    else:
        regions = args.regions.split(',')
        logger.info(f"Scanning specified regions: {', '.join(regions)}")
        return regions

def get_compartments(identity, tenancy_id, args):
    """Get list of compartments to scan based on args"""
    all_compartments = []
    
    try:
        # Get root compartment
        if args.include_root:
            root_compartment = identity.get_tenancy(tenancy_id).data
            # Add path property
            root_compartment.path = root_compartment.name
            root_compartment.parent_id = None
            all_compartments.append(root_compartment)
            logger.info(f"Added root compartment: {root_compartment.name}")
        
        # Get all compartments
        if args.recursive:
            response = oci.pagination.list_call_get_all_results(
                identity.list_compartments,
                tenancy_id,
                compartment_id_in_subtree=True,
                lifecycle_state="ACTIVE"
            )
            compartments = response.data
        else:
            # Just direct children of root
            response = oci.pagination.list_call_get_all_results(
                identity.list_compartments,
                tenancy_id,
                lifecycle_state="ACTIVE"
            )
            compartments = response.data
            
        # Add all retrieved compartments to the list
        all_compartments.extend(compartments)
        logger.info(f"Retrieved {len(all_compartments)} compartments")
        
        # Create mapping for faster lookup
        compartment_map = {c.id: c for c in all_compartments}
        
        # Calculate paths for all compartments
        for compartment in all_compartments:
            if not hasattr(compartment, 'path'):
                compartment.path = get_compartment_path(compartment, compartment_map)
            # Store parent ID for easier relationship mapping
            if hasattr(compartment, 'compartment_id'):
                compartment.parent_id = compartment.compartment_id
        
        # Apply filtering if a specific compartment is requested
        target_compartments = []
        
        if args.compartment_id:
            # Get by OCID
            target_id = args.compartment_id
            target_compartments = filter_compartments_by_id(all_compartments, target_id, args.recursive)
            if not target_compartments:
                logger.error(f"Compartment with ID '{target_id}' not found")
                return all_compartments  # Fallback to all compartments
        
        elif args.compartment:
            # Get by name
            target_name = args.compartment
            target_compartments = filter_compartments_by_name(all_compartments, target_name, args.recursive)
            if not target_compartments:
                logger.error(f"Compartment with name '{target_name}' not found")
                return all_compartments  # Fallback to all compartments
        
        else:
            # No filtering, use all
            target_compartments = all_compartments
        
        logger.info(f"Scanning {len(target_compartments)} compartments")
        return target_compartments
    
    except Exception as e:
        logger.error(f"Error retrieving compartments: {str(e)}")
        return all_compartments  # Return what we have so far

def get_compartment_path(compartment, compartment_map):
    """Calculate the full path of a compartment"""
    if not hasattr(compartment, 'compartment_id') or not compartment.compartment_id:
        # This is the root compartment
        return compartment.name
    
    path_parts = [compartment.name]
    parent_id = compartment.compartment_id
    
    # Walk up the hierarchy
    while parent_id:
        if parent_id in compartment_map:
            parent = compartment_map[parent_id]
            path_parts.insert(0, parent.name)
            parent_id = parent.compartment_id if hasattr(parent, 'compartment_id') else None
        else:
            # Unknown parent, stop here
            break
    
    return " / ".join(path_parts)

def filter_compartments_by_id(compartments, target_id, recursive=True):
    """Filter compartments by ID, including children if recursive"""
    result = []
    target_compartment = None
    
    # Find the target compartment
    for c in compartments:
        if c.id == target_id:
            target_compartment = c
            result.append(c)
            break
    
    if not target_compartment:
        return []
    
    # Add children if recursive
    if recursive:
        for c in compartments:
            if hasattr(c, 'compartment_id') and c.compartment_id == target_id:
                result.append(c)
                # Recursively add grandchildren
                result.extend(filter_compartments_by_id(compartments, c.id, True))
    
    return result

def filter_compartments_by_name(compartments, target_name, recursive=True):
    """Filter compartments by name, including children if recursive"""
    result = []
    target_compartment = None
    
    # Find the target compartment (case insensitive)
    for c in compartments:
        if c.name.lower() == target_name.lower():
            target_compartment = c
            result.append(c)
            break
    
    if not target_compartment:
        return []
    
    # Add children if recursive
    if recursive:
        return filter_compartments_by_id(compartments, target_compartment.id, True)
    
    return result

def initialize_clients(config, signer, region):
    """Initialize OCI clients for the specified region"""
    regional_config = dict(config) if config else {}
    
    if regional_config and region:
        regional_config["region"] = region
    
    clients = {}
    
    # Core services
    clients["compute"] = oci.core.ComputeClient(config=regional_config, signer=signer)
    clients["blockstorage"] = oci.core.BlockstorageClient(config=regional_config, signer=signer)
    clients["virtual_network"] = oci.core.VirtualNetworkClient(config=regional_config, signer=signer)
    
    # Other services
    clients["identity"] = oci.identity.IdentityClient(config=regional_config, signer=signer)
    clients["object_storage"] = oci.object_storage.ObjectStorageClient(config=regional_config, signer=signer)
    clients["file_storage"] = oci.file_storage.FileStorageClient(config=regional_config, signer=signer)
    clients["database"] = oci.database.DatabaseClient(config=regional_config, signer=signer)
    clients["load_balancer"] = oci.load_balancer.LoadBalancerClient(config=regional_config, signer=signer)
    
    # Additional services
    try:
        clients["functions"] = oci.functions.FunctionsManagementClient(config=regional_config, signer=signer)
    except Exception:
        logger.warning("Functions service client initialization failed - skipping functions resources")
    
    try:
        clients["api_gateway"] = oci.apigateway.ApiGatewayClient(config=regional_config, signer=signer)
    except Exception:
        logger.warning("API Gateway service client initialization failed - skipping API Gateway resources")
    
    try:
        clients["events"] = oci.events.EventsClient(config=regional_config, signer=signer)
    except Exception:
        logger.warning("Events service client initialization failed - skipping Events resources")
    
    try:
        clients["monitoring"] = oci.monitoring.MonitoringClient(config=regional_config, signer=signer)
    except Exception:
        logger.warning("Monitoring service client initialization failed - skipping Monitoring resources")
    
    try:
        clients["notifications"] = oci.ons.NotificationControlPlaneClient(config=regional_config, signer=signer)
    except Exception:
        logger.warning("Notifications service client initialization failed - skipping Notifications resources")
    
    try:
        clients["streaming"] = oci.streaming.StreamAdminClient(config=regional_config, signer=signer)
    except Exception:
        logger.warning("Streaming service client initialization failed - skipping Streaming resources")
    
    try:
        clients["resource_manager"] = oci.resource_manager.ResourceManagerClient(config=regional_config, signer=signer)
    except Exception:
        logger.warning("Resource Manager service client initialization failed - skipping Resource Manager resources")
    
    try:
        clients["data_science"] = oci.data_science.DataScienceClient(config=regional_config, signer=signer)
    except Exception:
        logger.warning("Data Science service client initialization failed - skipping Data Science resources")
    
    try:
        clients["service_connector"] = oci.sch.ServiceConnectorClient(config=regional_config, signer=signer)
    except Exception:
        logger.warning("Service Connector Hub client initialization failed - skipping Service Connector resources")
    
    # Update timeouts for all clients
    for client_name, client in clients.items():
        if hasattr(client, "base_client") and hasattr(client.base_client, "timeout"):
            client.base_client.timeout = TIMEOUT
    
    logger.info(f"Initialized {len(clients)} service clients for region {region}")
    return clients

def get_resource_types_to_scan(args):
    """Determine which resource types to scan based on args"""
    if args.all_resources:
        # Include all resource types
        resource_types = {}
        for service, resources in RESOURCE_TYPES.items():
            for resource_type, config in resources.items():
                resource_types[resource_type] = config
        
        logger.info(f"Scanning all {len(resource_types)} resource types")
        return resource_types
    
    if args.resource_types:
        # Filter to specified resource types
        specified_types = args.resource_types.split(',')
        resource_types = {}
        
        for service, resources in RESOURCE_TYPES.items():
            for resource_type, config in resources.items():
                if resource_type in specified_types:
                    resource_types[resource_type] = config
        
        logger.info(f"Scanning specified {len(resource_types)} resource types: {args.resource_types}")
        return resource_types
    
    # Default to all resource types
    resource_types = {}
    for service, resources in RESOURCE_TYPES.items():
        for resource_type, config in resources.items():
            resource_types[resource_type] = config
    
    # Apply exclusions if specified
    if args.excluded_types:
        excluded = args.excluded_types.split(',')
        for excluded_type in excluded:
            if excluded_type in resource_types:
                del resource_types[excluded_type]
        
        logger.info(f"Excluded resource types: {args.excluded_types}")
    
    logger.info(f"Scanning {len(resource_types)} resource types")
    return resource_types

def discover_resources(clients, compartment, region, resource_types):
    """Discover resources in a compartment"""
    resources = {}
    
    logger.info(f"Discovering resources in compartment {compartment.name} ({compartment.id}) in region {region}")
    
    # Get object storage namespace (needed for bucket operations)
    namespace = None
    if "object_storage" in clients and clients["object_storage"]:
        try:
            namespace = clients["object_storage"].get_namespace().data
        except Exception as e:
            logger.warning(f"Error getting object storage namespace: {str(e)}")
    
    # Process each resource type
    for resource_type, config in resource_types.items():
        client_name = config.get("client")
        
        if client_name not in clients or not clients[client_name]:
            continue
        
        client = clients[client_name]
        list_fn_name = config.get("list_fn")
        
        if not hasattr(client, list_fn_name):
            continue
        
        list_fn = getattr(client, list_fn_name)
        
        # Check if this is a child resource that needs parent ID
        if "parent_id_param" in config and "parent_resource" in config:
            # Skip for now, will process after parent resources
            continue
        
        # Prepare arguments for the list call
        kwargs = {}
        
        # Add compartment ID unless it's a global service
        if not config.get("global_service", False):
            compartment_id_param = config.get("compartment_id_param", "compartment_id")
            kwargs[compartment_id_param] = compartment.id
        
        # Add extra arguments
        extra_args = config.get("extra_args", {})
        for arg_name, arg_value in extra_args.items():
            if arg_value == "namespace_name" and namespace:
                kwargs[arg_name] = namespace
            else:
                kwargs[arg_name] = arg_value
        
        # Discover resources
        try:
            resource_list = []
            
            # Handle pagination
            response = oci.pagination.list_call_get_all_results(
                list_fn,
                **kwargs
            )
            resource_list = response.data
            
            # Store resources
            resources[resource_type] = []
            for resource in resource_list:
                # Add metadata
                if not hasattr(resource, "region"):
                    resource.region = region
                if not hasattr(resource, "compartment_path"):
                    resource.compartment_path = compartment.path
                if not hasattr(resource, "compartment_name"):
                    resource.compartment_name = compartment.name
                if not hasattr(resource, "resource_type"):
                    resource.resource_type = resource_type
                
                resources[resource_type].append(resource)
            
            logger.info(f"  Found {len(resource_list)} {resource_type} in {compartment.name}")
            
        except Exception as e:
            logger.warning(f"  Error discovering {resource_type} in {compartment.name}: {str(e)}")
    
    # Now process child resources
    for resource_type, config in resource_types.items():
        if "parent_id_param" in config and "parent_resource" in config:
            parent_resource_type = config["parent_resource"]
            parent_id_param = config["parent_id_param"]
            client_name = config.get("client")
            
            if client_name not in clients or not clients[client_name]:
                continue
            
            if parent_resource_type not in resources:
                continue
            
            client = clients[client_name]
            list_fn_name = config.get("list_fn")
            
            if not hasattr(client, list_fn_name):
                continue
            
            list_fn = getattr(client, list_fn_name)
            
            # Process each parent resource
            resources[resource_type] = []
            for parent in resources[parent_resource_type]:
                # Prepare arguments
                kwargs = {}
                
                # Add compartment ID
                compartment_id_param = config.get("compartment_id_param", "compartment_id")
                kwargs[compartment_id_param] = compartment.id
                
                # Add parent ID
                kwargs[parent_id_param] = parent.id
                
                # Discover child resources
                try:
                    response = oci.pagination.list_call_get_all_results(
                        list_fn,
                        **kwargs
                    )
                    child_resources = response.data
                    
                    # Add metadata to child resources
                    for resource in child_resources:
                        if not hasattr(resource, "region"):
                            resource.region = region
                        if not hasattr(resource, "compartment_path"):
                            resource.compartment_path = compartment.path
                        if not hasattr(resource, "compartment_name"):
                            resource.compartment_name = compartment.name
                        if not hasattr(resource, "parent_id"):
                            resource.parent_id = parent.id
                        if not hasattr(resource, "resource_type"):
                            resource.resource_type = resource_type
                    
                    resources[resource_type].extend(child_resources)
                    
                except Exception as e:
                    logger.warning(f"  Error discovering {resource_type} for parent {parent.id}: {str(e)}")
            
            logger.info(f"  Found {len(resources[resource_type])} {resource_type} in {compartment.name}")
    
    # Add IDs to names mapping for relationship resolution
    for resource_type, resource_list in resources.items():
        for resource in resource_list:
            resource.compartment_id = compartment.id
    
    return resources

def map_relationships(all_resources):
    """Map relationships between resources across all compartments and regions"""
    logger.info("Mapping relationships between resources...")
    
    # Flatten resource lists into a dict keyed by type for easier lookup
    resource_map = {}
    for resource_type in all_resources.keys():
        resource_map[resource_type] = {r.id: r for r in all_resources.get(resource_type, [])}
    
    # Define a mapping of relationships
    relationships = []
    
    # Look for relationships based on the defined patterns
    for source_type, relation_config in RESOURCE_RELATIONSHIPS.items():
        if source_type not in all_resources:
            continue
        
        for source_resource in all_resources[source_type]:
            for relation in relation_config:
                field = relation["field"]
                target_type = relation["target_type"]
                is_list = relation.get("is_list", False)
                field_map = relation.get("field_map", None)
                
                # Skip if the target type is not found
                if target_type and target_type not in resource_map:
                    continue
                
                # Get the field value
                if hasattr(source_resource, field):
                    if is_list:
                        # Handle list fields
                        field_values = getattr(source_resource, field, [])
                        
                        if field_values:
                            if isinstance(field_values, list):
                                # Simple list of IDs
                                for target_id in field_values:
                                    if target_id and target_type and target_id in resource_map[target_type]:
                                        target = resource_map[target_type][target_id]
                                        relationship = {
                                            "source_id": source_resource.id,
                                            "source_type": source_type,
                                            "source_name": getattr(source_resource, "display_name", source_resource.id),
                                            "source_compartment_id": source_resource.compartment_id,
                                            "source_compartment_name": source_resource.compartment_name,
                                            "source_compartment_path": source_resource.compartment_path,
                                            "source_region": source_resource.region,
                                            "relationship_type": field,
                                            "target_id": target_id,
                                            "target_type": target_type,
                                            "target_name": getattr(target, "display_name", target.id),
                                            "target_compartment_id": target.compartment_id,
                                            "target_compartment_name": target.compartment_name,
                                            "target_compartment_path": target.compartment_path,
                                            "target_region": target.region
                                        }
                                        relationships.append(relationship)
                            elif field_map:
                                # Complex list of objects
                                for obj in field_values:
                                    if hasattr(obj, field_map):
                                        target_id = getattr(obj, field_map)
                                        if target_id and target_type and target_id in resource_map[target_type]:
                                            target = resource_map[target_type][target_id]
                                            relationship = {
                                                "source_id": source_resource.id,
                                                "source_type": source_type,
                                                "source_name": getattr(source_resource, "display_name", source_resource.id),
                                                "source_compartment_id": source_resource.compartment_id,
                                                "source_compartment_name": source_resource.compartment_name,
                                                "source_compartment_path": source_resource.compartment_path,
                                                "source_region": source_resource.region,
                                                "relationship_type": field,
                                                "target_id": target_id,
                                                "target_type": target_type,
                                                "target_name": getattr(target, "display_name", target.id),
                                                "target_compartment_id": target.compartment_id,
                                                "target_compartment_name": target.compartment_name,
                                                "target_compartment_path": target.compartment_path,
                                                "target_region": target.region
                                            }
                                            relationships.append(relationship)
                    else:
                        # Handle scalar fields
                        target_id = getattr(source_resource, field)
                        if target_id and target_type and target_id in resource_map[target_type]:
                            target = resource_map[target_type][target_id]
                            relationship = {
                                "source_id": source_resource.id,
                                "source_type": source_type,
                                "source_name": getattr(source_resource, "display_name", source_resource.id),
                                "source_compartment_id": source_resource.compartment_id,
                                "source_compartment_name": source_resource.compartment_name,
                                "source_compartment_path": source_resource.compartment_path,
                                "source_region": source_resource.region,
                                "relationship_type": field,
                                "target_id": target_id,
                                "target_type": target_type,
                                "target_name": getattr(target, "display_name", target.id),
                                "target_compartment_id": target.compartment_id,
                                "target_compartment_name": target.compartment_name,
                                "target_compartment_path": target.compartment_path,
                                "target_region": target.region
                            }
                            relationships.append(relationship)
    
    logger.info(f"Found {len(relationships)} relationships between resources")
    return relationships

def write_csv_output(all_resources, relationships, output_dir, prefix):
    """Write resources and relationships to CSV files"""
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Output file paths
    resources_file = os.path.join(output_dir, f"{prefix}_resources_{timestamp}.csv")
    relationships_file = os.path.join(output_dir, f"{prefix}_relationships_{timestamp}.csv")
    
    # Write resources CSV
    with open(resources_file, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow([
            "Resource Type", "Resource Name", "Resource ID", "Region",
            "Compartment Name", "Compartment ID", "Compartment Path",
            "State", "Time Created", "Defined Tags", "Freeform Tags"
        ])
        
        # Write data for each resource type
        for resource_type, resources in all_resources.items():
            for resource in resources:
                # Extract fields
                name = getattr(resource, "display_name", getattr(resource, "name", resource.id))
                state = getattr(resource, "lifecycle_state", "")
                time_created = getattr(resource, "time_created", "")
                if time_created:
                    time_created = time_created.strftime("%Y-%m-%d %H:%M:%S") if hasattr(time_created, "strftime") else time_created
                
                defined_tags = getattr(resource, "defined_tags", {})
                freeform_tags = getattr(resource, "freeform_tags", {})
                
                # Convert tags to string
                defined_tags_str = json.dumps(defined_tags) if defined_tags else ""
                freeform_tags_str = json.dumps(freeform_tags) if freeform_tags else ""
                
                # Write row
                writer.writerow([
                    resource_type,
                    name,
                    resource.id,
                    resource.region,
                    resource.compartment_name,
                    resource.compartment_id,
                    resource.compartment_path,
                    state,
                    time_created,
                    defined_tags_str,
                    freeform_tags_str
                ])
    
    logger.info(f"Wrote {sum(len(resources) for resources in all_resources.values())} resources to {resources_file}")
    
    # Write relationships CSV
    if relationships:
        with open(relationships_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "Source Type", "Source Name", "Source ID", "Source Region",
                "Source Compartment Name", "Source Compartment Path",
                "Relationship Type",
                "Target Type", "Target Name", "Target ID", "Target Region",
                "Target Compartment Name", "Target Compartment Path",
                "Cross-Region", "Cross-Compartment"
            ])
            
            # Write data for each relationship
            for rel in relationships:
                cross_region = rel["source_region"] != rel["target_region"]
                cross_compartment = rel["source_compartment_id"] != rel["target_compartment_id"]
                
                writer.writerow([
                    rel["source_type"],
                    rel["source_name"],
                    rel["source_id"],
                    rel["source_region"],
                    rel["source_compartment_name"],
                    rel["source_compartment_path"],
                    rel["relationship_type"],
                    rel["target_type"],
                    rel["target_name"],
                    rel["target_id"],
                    rel["target_region"],
                    rel["target_compartment_name"],
                    rel["target_compartment_path"],
                    "Yes" if cross_region else "No",
                    "Yes" if cross_compartment else "No"
                ])
        
        logger.info(f"Wrote {len(relationships)} relationships to {relationships_file}")
    
    return resources_file, relationships_file

def process_region(config, signer, region, compartments, resource_types, args):
    """Process a single region"""
    logger.info(f"Processing region: {region}")
    
    # Initialize clients for this region
    clients = initialize_clients(config, signer, region)
    
    if not clients:
        logger.error(f"Failed to initialize clients for region {region}")
        return {}
    
    # Discover resources in each compartment
    all_resources = {resource_type: [] for resource_type in resource_types.keys()}
    
    for compartment in compartments:
        resources = discover_resources(clients, compartment, region, resource_types)
        
        # Merge resources
        for resource_type, resources_list in resources.items():
            if resource_type in all_resources:
                all_resources[resource_type].extend(resources_list)
            else:
                all_resources[resource_type] = resources_list
    
    return all_resources

def main():
    """Main entry point"""
    # Parse arguments
    args = parse_args()
    
    # Set up authentication
    config, signer, identity, tenancy = setup_auth(args)
    
    # Get regions to scan
    regions = get_regions(args, identity, tenancy.id)
    
    # Get compartments to scan
    compartments = get_compartments(identity, tenancy.id, args)
    
    # Get resource types to scan
    resource_types = get_resource_types_to_scan(args)
    
    # Discover resources across regions
    all_resources = {resource_type: [] for resource_type in resource_types.keys()}
    
    if not args.no_parallel and args.max_workers > 1 and len(regions) > 1:
        # Use parallel processing for regions
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.max_workers, len(regions))) as executor:
            future_to_region = {
                executor.submit(
                    process_region, config, signer, region, compartments, resource_types, args
                ): region for region in regions
            }
            
            for future in concurrent.futures.as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    region_resources = future.result()
                    
                    # Merge resources
                    for resource_type, resources_list in region_resources.items():
                        if resource_type in all_resources:
                            all_resources[resource_type].extend(resources_list)
                        else:
                            all_resources[resource_type] = resources_list
                            
                except Exception as e:
                    logger.error(f"Error processing region {region}: {str(e)}")
    else:
        # Process regions sequentially
        for region in regions:
            region_resources = process_region(config, signer, region, compartments, resource_types, args)
            
            # Merge resources
            for resource_type, resources_list in region_resources.items():
                if resource_type in all_resources:
                    all_resources[resource_type].extend(resources_list)
                else:
                    all_resources[resource_type] = resources_list
    
    # Map relationships between resources
    relationships = []
    if args.relationships:
        relationships = map_relationships(all_resources)
    
    # Write output files
    resources_file, relationships_file = write_csv_output(
        all_resources, relationships, args.output_dir, args.output_prefix
    )
    
    # Print summary
    total_resources = sum(len(resources) for resources in all_resources.values())
    logger.info(f"Summary: Discovered {total_resources} resources across {len(regions)} regions and {len(compartments)} compartments")
    logger.info(f"Resources CSV: {resources_file}")
    if relationships:
        logger.info(f"Relationships CSV: {relationships_file}")
    
    # Log resource counts by type
    logger.info("Resource counts by type:")
    for resource_type, resources in sorted(all_resources.items()):
        if resources:
            logger.info(f"  {resource_type}: {len(resources)}")

if __name__ == "__main__":
    # Example command:
    # python oci_tenancy_explorer2.py --regions us-ashburn-1,us-phoenix-1 --compartment YOUR_COMPARTMENT_NAME
    main()