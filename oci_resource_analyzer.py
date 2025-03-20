#!/usr/bin/env python3
"""
OCI Resource Analyzer
---------------------
This script extracts comprehensive details about OCI resources within a specified
compartment to help determine if resources are still needed.
"""

import oci
import json
import argparse
import datetime
import sys
from collections import defaultdict

# Configure command line arguments
parser = argparse.ArgumentParser(description='Extract detailed information about OCI resources')
parser.add_argument('--config', default='~/.oci/config', help='OCI config file path')
parser.add_argument('--profile', default='DEFAULT', help='OCI config profile')
parser.add_argument('--compartment-id', required=True, help='Compartment OCID to scan')
parser.add_argument('--output', default='oci_resources.json', help='Output file path')
args = parser.parse_args()

# Custom JSON encoder to handle datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)

# Helper function to get all resources with pagination
def get_all_resources(list_fn, **kwargs):
    items = []
    next_page = None
    
    while True:
        if next_page:
            kwargs["page"] = next_page
            
        response = list_fn(**kwargs)
        items.extend(response.data)
        
        if response.next_page:
            next_page = response.next_page
        else:
            break
    
    return items

# Helper function to get tags from a resource
def get_tags(resource):
    tags = {}
    if hasattr(resource, 'defined_tags') and resource.defined_tags:
        tags['defined_tags'] = resource.defined_tags
    if hasattr(resource, 'freeform_tags') and resource.freeform_tags:
        tags['freeform_tags'] = resource.freeform_tags
    return tags

# Helper function to get resource name
def get_resource_name(resource):
    if hasattr(resource, 'display_name'):
        return resource.display_name
    elif hasattr(resource, 'name'):
        return resource.name
    else:
        return "Unnamed resource"

# Convert OCI model object to dict
def oci_object_to_dict(obj):
    if hasattr(obj, '__dict__'):
        result = {}
        for key, value in obj.__dict__.items():
            if not key.startswith('_'):
                result[key] = oci_object_to_dict(value)
        return result
    elif isinstance(obj, list):
        return [oci_object_to_dict(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: oci_object_to_dict(value) for key, value in obj.items()}
    else:
        return obj

# Main function to scan OCI resources
def scan_oci_resources(compartment_id, config_path, profile_name):
    # Initialize the OCI config
    config = oci.config.from_file(config_path, profile_name)
    
    # Dictionary to store all resources
    all_resources = {}
    
    # Get Identity resources
    print("Scanning Identity resources...")
    identity_client = oci.identity.IdentityClient(config)
    
    # Get compartment details
    try:
        compartment = identity_client.get_compartment(compartment_id).data
        all_resources['compartment_info'] = oci_object_to_dict(compartment)
    except Exception as e:
        print(f"Error getting compartment details: {e}")
        sys.exit(1)
    
    # Get users (this will only work if you're scanning the root compartment or tenancy)
    try:
        all_resources['users'] = []
        users = get_all_resources(identity_client.list_users, compartment_id=compartment_id)
        for user in users:
            user_dict = oci_object_to_dict(user)
            # Get user groups
            user_groups = get_all_resources(identity_client.list_user_group_memberships, 
                                          compartment_id=compartment_id, 
                                          user_id=user.id)
            user_dict['groups'] = [oci_object_to_dict(group) for group in user_groups]
            all_resources['users'].append(user_dict)
    except Exception as e:
        print(f"Note: Could not get users (this is expected if not scanning the root compartment): {e}")
    
    # Get groups
    try:
        all_resources['groups'] = []
        groups = get_all_resources(identity_client.list_groups, compartment_id=compartment_id)
        for group in groups:
            group_dict = oci_object_to_dict(group)
            all_resources['groups'].append(group_dict)
    except Exception as e:
        print(f"Note: Could not get groups: {e}")
    
    # Get policies
    try:
        all_resources['policies'] = []
        policies = get_all_resources(identity_client.list_policies, compartment_id=compartment_id)
        for policy in policies:
            policy_dict = oci_object_to_dict(policy)
            all_resources['policies'].append(policy_dict)
    except Exception as e:
        print(f"Note: Could not get policies: {e}")
    
    # Get Compute instances
    print("Scanning Compute resources...")
    compute_client = oci.core.ComputeClient(config)
    
    all_resources['compute_instances'] = []
    instances = get_all_resources(compute_client.list_instances, compartment_id=compartment_id)
    
    for instance in instances:
        instance_dict = oci_object_to_dict(instance)
        
        # Get boot volume attachments
        try:
            boot_volumes = get_all_resources(compute_client.list_boot_volume_attachments, 
                                           compartment_id=compartment_id, 
                                           instance_id=instance.id)
            instance_dict['boot_volumes'] = [oci_object_to_dict(vol) for vol in boot_volumes]
        except Exception as e:
            print(f"Could not get boot volumes for instance {instance.id}: {e}")
        
        # Get volume attachments
        try:
            volumes = get_all_resources(compute_client.list_volume_attachments, 
                                      compartment_id=compartment_id, 
                                      instance_id=instance.id)
            instance_dict['volumes'] = [oci_object_to_dict(vol) for vol in volumes]
        except Exception as e:
            print(f"Could not get volumes for instance {instance.id}: {e}")
        
        # Get VNICs
        try:
            vnics = get_all_resources(compute_client.list_vnic_attachments, 
                                    compartment_id=compartment_id, 
                                    instance_id=instance.id)
            
            network_client = oci.core.VirtualNetworkClient(config)
            instance_dict['vnics'] = []
            
            for vnic_attachment in vnics:
                if vnic_attachment.lifecycle_state == "ATTACHED":
                    vnic = network_client.get_vnic(vnic_attachment.vnic_id).data
                    vnic_dict = oci_object_to_dict(vnic)
                    
                    # Get public IP if any
                    if vnic.public_ip:
                        vnic_dict['public_ip_details'] = "Has public IP: " + vnic.public_ip
                    
                    # Get private IP
                    private_ips = get_all_resources(network_client.list_private_ips, 
                                                  vnic_id=vnic.id)
                    vnic_dict['private_ips'] = [oci_object_to_dict(ip) for ip in private_ips]
                    
                    instance_dict['vnics'].append(vnic_dict)
        except Exception as e:
            print(f"Could not get VNICs for instance {instance.id}: {e}")
        
        # Get console connection
        try:
            console_connections = get_all_resources(compute_client.list_instance_console_connections, 
                                                  compartment_id=compartment_id, 
                                                  instance_id=instance.id)
            instance_dict['console_connections'] = [oci_object_to_dict(conn) for conn in console_connections]
        except Exception as e:
            print(f"Could not get console connections for instance {instance.id}: {e}")
        
        # Get console history
        try:
            console_histories = get_all_resources(compute_client.list_console_histories, 
                                                compartment_id=compartment_id, 
                                                instance_id=instance.id)
            instance_dict['console_histories'] = [oci_object_to_dict(hist) for hist in console_histories]
        except Exception as e:
            print(f"Could not get console histories for instance {instance.id}: {e}")
        
        # Add to resources list
        all_resources['compute_instances'].append(instance_dict)
    
    # Get Block Storage resources
    print("Scanning Block Storage resources...")
    blockstorage_client = oci.core.BlockstorageClient(config)
    
    # Get boot volumes
    all_resources['boot_volumes'] = []
    try:
        # Get a list of availability domains first
        availability_domains = get_all_resources(identity_client.list_availability_domains, 
                                               compartment_id=compartment_id)
        
        for ad in availability_domains:
            boot_volumes = get_all_resources(blockstorage_client.list_boot_volumes, 
                                           compartment_id=compartment_id, 
                                           availability_domain=ad.name)
            
            for volume in boot_volumes:
                volume_dict = oci_object_to_dict(volume)
                
                # Get volume backups
                try:
                    backups = get_all_resources(blockstorage_client.list_boot_volume_backups, 
                                              compartment_id=compartment_id, 
                                              boot_volume_id=volume.id)
                    volume_dict['backups'] = [oci_object_to_dict(backup) for backup in backups]
                except Exception as e:
                    print(f"Could not get backups for boot volume {volume.id}: {e}")
                
                all_resources['boot_volumes'].append(volume_dict)
    except Exception as e:
        print(f"Error scanning boot volumes: {e}")
    
    # Get block volumes
    all_resources['block_volumes'] = []
    try:
        volumes = get_all_resources(blockstorage_client.list_volumes, 
                                  compartment_id=compartment_id)
        
        for volume in volumes:
            volume_dict = oci_object_to_dict(volume)
            
            # Get volume backups
            try:
                backups = get_all_resources(blockstorage_client.list_volume_backups, 
                                          compartment_id=compartment_id, 
                                          volume_id=volume.id)
                volume_dict['backups'] = [oci_object_to_dict(backup) for backup in backups]
            except Exception as e:
                print(f"Could not get backups for volume {volume.id}: {e}")
            
            all_resources['block_volumes'].append(volume_dict)
    except Exception as e:
        print(f"Error scanning block volumes: {e}")
    
    # Get Object Storage resources
    print("Scanning Object Storage resources...")
    objectstorage_client = oci.object_storage.ObjectStorageClient(config)
    
    # Get namespace
    try:
        namespace = objectstorage_client.get_namespace().data
        
        # Get buckets
        all_resources['buckets'] = []
        buckets = get_all_resources(objectstorage_client.list_buckets, 
                                  compartment_id=compartment_id, 
                                  namespace_name=namespace)
        
        for bucket in buckets:
            bucket_details = objectstorage_client.get_bucket(namespace, bucket.name).data
            bucket_dict = oci_object_to_dict(bucket_details)
            
            # Get object lifecycle policy
            try:
                lifecycle = objectstorage_client.get_object_lifecycle_policy(namespace, bucket.name).data
                bucket_dict['lifecycle_policy'] = oci_object_to_dict(lifecycle)
            except Exception as e:
                if "LifecyclePolicy not found" not in str(e):
                    print(f"Error getting lifecycle policy for bucket {bucket.name}: {e}")
            
            # Get PAR (Pre-Authenticated Requests)
            try:
                pars = get_all_resources(objectstorage_client.list_preauthenticated_requests, 
                                      namespace_name=namespace, 
                                      bucket_name=bucket.name)
                bucket_dict['preauthenticated_requests'] = [oci_object_to_dict(par) for par in pars]
            except Exception as e:
                print(f"Error getting PARs for bucket {bucket.name}: {e}")
            
            # We don't list objects as there could be too many
            all_resources['buckets'].append(bucket_dict)
    except Exception as e:
        print(f"Error scanning object storage resources: {e}")
    
    # Get Database resources
    print("Scanning Database resources...")
    database_client = oci.database.DatabaseClient(config)
    
    # Get DB Systems
    all_resources['db_systems'] = []
    try:
        db_systems = get_all_resources(database_client.list_db_systems, 
                                     compartment_id=compartment_id)
        
        for db_system in db_systems:
            db_system_dict = oci_object_to_dict(db_system)
            
            # Get databases in the DB system
            try:
                databases = get_all_resources(database_client.list_databases, 
                                            compartment_id=compartment_id, 
                                            db_home_id=db_system.db_home_id)
                db_system_dict['databases'] = [oci_object_to_dict(db) for db in databases]
            except Exception as e:
                print(f"Could not get databases for DB system {db_system.id}: {e}")
            
            # Get backups
            try:
                backups = get_all_resources(database_client.list_backups, 
                                          compartment_id=compartment_id, 
                                          db_system_id=db_system.id)
                db_system_dict['backups'] = [oci_object_to_dict(backup) for backup in backups]
            except Exception as e:
                print(f"Could not get backups for DB system {db_system.id}: {e}")
            
            all_resources['db_systems'].append(db_system_dict)
    except Exception as e:
        print(f"Error scanning DB systems: {e}")
    
    # Get Autonomous Databases
    all_resources['autonomous_databases'] = []
    try:
        autonomous_dbs = get_all_resources(database_client.list_autonomous_databases, 
                                         compartment_id=compartment_id)
        
        for adb in autonomous_dbs:
            adb_dict = oci_object_to_dict(adb)
            
            # Get backups
            try:
                backups = get_all_resources(database_client.list_autonomous_database_backups, 
                                          compartment_id=compartment_id, 
                                          autonomous_database_id=adb.id)
                adb_dict['backups'] = [oci_object_to_dict(backup) for backup in backups]
            except Exception as e:
                print(f"Could not get backups for autonomous database {adb.id}: {e}")
            
            all_resources['autonomous_databases'].append(adb_dict)
    except Exception as e:
        print(f"Error scanning autonomous databases: {e}")
    
    # Get Network resources
    print("Scanning Network resources...")
    network_client = oci.core.VirtualNetworkClient(config)
    
    # Get VCNs
    all_resources['vcns'] = []
    try:
        vcns = get_all_resources(network_client.list_vcns, 
                               compartment_id=compartment_id)
        
        for vcn in vcns:
            vcn_dict = oci_object_to_dict(vcn)
            
            # Get subnets
            try:
                subnets = get_all_resources(network_client.list_subnets, 
                                          compartment_id=compartment_id, 
                                          vcn_id=vcn.id)
                vcn_dict['subnets'] = [oci_object_to_dict(subnet) for subnet in subnets]
            except Exception as e:
                print(f"Could not get subnets for VCN {vcn.id}: {e}")
            
            # Get route tables
            try:
                route_tables = get_all_resources(network_client.list_route_tables, 
                                               compartment_id=compartment_id, 
                                               vcn_id=vcn.id)
                vcn_dict['route_tables'] = [oci_object_to_dict(rt) for rt in route_tables]
            except Exception as e:
                print(f"Could not get route tables for VCN {vcn.id}: {e}")
            
            # Get security lists
            try:
                security_lists = get_all_resources(network_client.list_security_lists, 
                                                 compartment_id=compartment_id, 
                                                 vcn_id=vcn.id)
                vcn_dict['security_lists'] = [oci_object_to_dict(sl) for sl in security_lists]
            except Exception as e:
                print(f"Could not get security lists for VCN {vcn.id}: {e}")
            
            # Get network security groups
            try:
                nsgs = get_all_resources(network_client.list_network_security_groups, 
                                       compartment_id=compartment_id, 
                                       vcn_id=vcn.id)
                vcn_dict['network_security_groups'] = []
                
                for nsg in nsgs:
                    nsg_dict = oci_object_to_dict(nsg)
                    
                    # Get NSG rules
                    try:
                        rules = get_all_resources(network_client.list_network_security_group_security_rules, 
                                                network_security_group_id=nsg.id)
                        nsg_dict['rules'] = [oci_object_to_dict(rule) for rule in rules]
                    except Exception as e:
                        print(f"Could not get rules for NSG {nsg.id}: {e}")
                    
                    vcn_dict['network_security_groups'].append(nsg_dict)
            except Exception as e:
                print(f"Could not get NSGs for VCN {vcn.id}: {e}")
            
            # Get internet gateways
            try:
                igs = get_all_resources(network_client.list_internet_gateways, 
                                      compartment_id=compartment_id, 
                                      vcn_id=vcn.id)
                vcn_dict['internet_gateways'] = [oci_object_to_dict(ig) for ig in igs]
            except Exception as e:
                print(f"Could not get internet gateways for VCN {vcn.id}: {e}")
            
            # Get NAT gateways
            try:
                nat_gateways = get_all_resources(network_client.list_nat_gateways, 
                                               compartment_id=compartment_id, 
                                               vcn_id=vcn.id)
                vcn_dict['nat_gateways'] = [oci_object_to_dict(ng) for ng in nat_gateways]
            except Exception as e:
                print(f"Could not get NAT gateways for VCN {vcn.id}: {e}")
            
            # Get service gateways
            try:
                service_gateways = get_all_resources(network_client.list_service_gateways, 
                                                   compartment_id=compartment_id, 
                                                   vcn_id=vcn.id)
                vcn_dict['service_gateways'] = [oci_object_to_dict(sg) for sg in service_gateways]
            except Exception as e:
                print(f"Could not get service gateways for VCN {vcn.id}: {e}")
            
            # Get local peering gateways
            try:
                local_peering_gateways = get_all_resources(network_client.list_local_peering_gateways, 
                                                         compartment_id=compartment_id, 
                                                         vcn_id=vcn.id)
                vcn_dict['local_peering_gateways'] = [oci_object_to_dict(lpg) for lpg in local_peering_gateways]
            except Exception as e:
                print(f"Could not get local peering gateways for VCN {vcn.id}: {e}")
            
            all_resources['vcns'].append(vcn_dict)
    except Exception as e:
        print(f"Error scanning VCNs: {e}")
    
    # Get Load Balancers
    print("Scanning Load Balancer resources...")
    loadbalancer_client = oci.load_balancer.LoadBalancerClient(config)
    
    all_resources['load_balancers'] = []
    try:
        load_balancers = get_all_resources(loadbalancer_client.list_load_balancers, 
                                         compartment_id=compartment_id)
        
        for lb in load_balancers:
            lb_dict = oci_object_to_dict(lb)
            
            # Get backends
            try:
                backends = {}
                for backend_set_name in lb.backend_sets:
                    backend_set = loadbalancer_client.get_backend_set(lb.id, backend_set_name).data
                    backends[backend_set_name] = oci_object_to_dict(backend_set)
                lb_dict['backend_details'] = backends
            except Exception as e:
                print(f"Could not get backends for load balancer {lb.id}: {e}")
            
            # Get listeners
            lb_dict['listeners_details'] = {}
            for listener_name in lb.listeners:
                lb_dict['listeners_details'][listener_name] = lb.listeners[listener_name]
            
            all_resources['load_balancers'].append(lb_dict)
    except Exception as e:
        print(f"Error scanning load balancers: {e}")
    
    # Get Vault and Key Management resources
    print("Scanning Vault and Key Management resources...")
    kms_vaults_client = oci.key_management.KmsVaultClient(config)
    
    all_resources['vaults'] = []
    try:
        vaults = get_all_resources(kms_vaults_client.list_vaults, 
                                 compartment_id=compartment_id)
        
        for vault in vaults:
            vault_dict = oci_object_to_dict(vault)
            
            # Management endpoint for this vault
            management_endpoint = vault.management_endpoint
            
            # Create a client for this specific vault's management endpoint
            kms_management_client = oci.key_management.KmsManagementClient({}, management_endpoint)
            kms_management_client.base_client.session.session_auth.signer.load_private_key_from_file(config['key_file'])
            
            # Get keys in this vault
            try:
                keys = get_all_resources(kms_management_client.list_keys, 
                                       compartment_id=compartment_id)
                vault_dict['keys'] = []
                
                for key in keys:
                    key_dict = oci_object_to_dict(key)
                    
                    # Get key versions
                    try:
                        key_versions = get_all_resources(kms_management_client.list_key_versions, 
                                                      key_id=key.id)
                        key_dict['versions'] = [oci_object_to_dict(ver) for ver in key_versions]
                    except Exception as e:
                        print(f"Could not get versions for key {key.id}: {e}")
                    
                    vault_dict['keys'].append(key_dict)
            except Exception as e:
                print(f"Could not get keys for vault {vault.id}: {e}")
            
            all_resources['vaults'].append(vault_dict)
    except Exception as e:
        print(f"Error scanning vaults: {e}")
    
    # Get secrets from Vault
    all_resources['secrets'] = []
    try:
        secrets_client = oci.secrets.SecretsClient(config)
        secrets = get_all_resources(secrets_client.list_secrets, 
                                  compartment_id=compartment_id)
        
        for secret in secrets:
            secret_dict = oci_object_to_dict(secret)
            
            # Note: We don't retrieve the actual secret contents for security reasons
            all_resources['secrets'].append(secret_dict)
    except Exception as e:
        print(f"Error scanning secrets: {e}")
    
    # Get API Gateway resources
    print("Scanning API Gateway resources...")
    try:
        api_gateway_client = oci.apigateway.ApiGatewayClient(config)
        
        # Get gateways
        all_resources['api_gateways'] = []
        gateways = get_all_resources(api_gateway_client.list_gateways, 
                                   compartment_id=compartment_id)
        
        for gateway in gateways:
            gateway_dict = oci_object_to_dict(gateway)
            
            # Get deployments
            try:
                deployments = get_all_resources(api_gateway_client.list_deployments, 
                                              compartment_id=compartment_id, 
                                              gateway_id=gateway.id)
                gateway_dict['deployments'] = [oci_object_to_dict(dep) for dep in deployments]
            except Exception as e:
                print(f"Could not get deployments for API gateway {gateway.id}: {e}")
            
            all_resources['api_gateways'].append(gateway_dict)
    except Exception as e:
        print(f"Error scanning API gateways (this may be expected if API Gateway service is not available): {e}")
    
    # Get Functions resources
    print("Scanning Functions resources...")
    try:
        functions_client = oci.functions.FunctionsManagementClient(config)
        
        # Get applications
        all_resources['function_applications'] = []
        applications = get_all_resources(functions_client.list_applications, 
                                       compartment_id=compartment_id)
        
        for app in applications:
            app_dict = oci_object_to_dict(app)
            
            # Get functions
            try:
                functions = get_all_resources(functions_client.list_functions, 
                                            application_id=app.id)
                app_dict['functions'] = [oci_object_to_dict(fn) for fn in functions]
            except Exception as e:
                print(f"Could not get functions for application {app.id}: {e}")
            
            all_resources['function_applications'].append(app_dict)
    except Exception as e:
        print(f"Error scanning functions (this may be expected if Functions service is not available): {e}")
    
    return all_resources

# Main execution
if __name__ == "__main__":
    print(f"Starting OCI resource scan for compartment {args.compartment_id}")
    resources = scan_oci_resources(args.compartment_id, args.config, args.profile)
    
    # Output the results
    with open(args.output, 'w') as f:
        json.dump(resources, f, indent=2, cls=DateTimeEncoder)
    
    print(f"Resource information saved to {args.output}")
    
    # Print a summary
    print("\nResource Summary:")
    for resource_type, resources_list in resources.items():
        if isinstance(resources_list, list):
            print(f"  {resource_type}: {len(resources_list)}")
        elif isinstance(resources_list, dict):
            print(f"  {resource_type}: 1")
    
    print("\nUse this information to identify resources that might no longer be needed.")