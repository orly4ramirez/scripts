import oci
import csv
import sys
from datetime import datetime

# Function to get compartment ID by name
def get_compartment_id_by_name(identity_client, tenancy_id, compartment_name):
    compartments = oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        compartment_id=tenancy_id,
        compartment_id_in_subtree=True
    ).data
    
    for compartment in compartments:
        if compartment.name == compartment_name and compartment.lifecycle_state == "ACTIVE":
            return compartment.id
    raise Exception(f"Compartment '{compartment_name}' not found or not active.")

# Function to search resources in a compartment
def search_resources(search_client, compartment_id):
    query = f"query all resources where compartmentId = '{compartment_id}'"
    search_details = oci.resource_search.models.StructuredSearchDetails(
        type="Structured",
        query=query
    )
    response = oci.pagination.list_call_get_all_results(
        search_client.search_resources,
        search_details=search_details,
        limit=1000
    )
    return response.data.items

# Main script
if len(sys.argv) != 2:
    print("Usage: python script.py <compartment_name>")
    sys.exit(1)

compartment_name = sys.argv[1]
output_file = f"{compartment_name}_resources_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

# Load OCI configuration
try:
    config = oci.config.from_file("~/.oci/config", "DEFAULT")
except Exception as e:
    print(f"Error loading OCI config: {e}")
    sys.exit(1)

# Initialize OCI clients
identity_client = oci.identity.IdentityClient(config)
search_client = oci.resource_search.ResourceSearchClient(config)

# Get tenancy ID from config
tenancy_id = config["tenancy"]

# Get compartment ID
try:
    compartment_id = get_compartment_id_by_name(identity_client, tenancy_id, compartment_name)
    print(f"Found compartment ID: {compartment_id}")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

# Search for all resources in the compartment
try:
    resources = search_resources(search_client, compartment_id)
    print(f"Found {len(resources)} resources in compartment '{compartment_name}'")
except Exception as e:
    print(f"Error searching resources: {e}")
    sys.exit(1)

# Define CSV headers
headers = [
    "ResourceType", "DisplayName", "Identifier", "LifecycleState", "TimeCreated",
    "AvailabilityDomain", "CompartmentId", "DefinedTags", "FreeformTags"
]

# Write to CSV
with open(output_file, mode="w", newline="", encoding="utf-8") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=headers)
    writer.writeheader()

    for resource in resources:
        row = {
            "ResourceType": resource.resource_type,
            "DisplayName": resource.display_name,
            "Identifier": resource.identifier,
            "LifecycleState": resource.lifecycle_state,
            "TimeCreated": resource.time_created,
            "AvailabilityDomain": resource.availability_domain if resource.availability_domain else "N/A",
            "CompartmentId": resource.compartment_id,
            "DefinedTags": str(resource.defined_tags) if resource.defined_tags else "",
            "FreeformTags": str(resource.freeform_tags) if resource.freeform_tags else ""
        }
        writer.writerow(row)

print(f"Resources written to {output_file}")

# Optional: Print summary of potentially unused resources
print("\nPotentially Unused Resources (based on LifecycleState):")
for resource in resources:
    if resource.lifecycle_state in ["TERMINATED", "STOPPED", "DELETED"]:
        print(f"- {resource.resource_type}: {resource.display_name} (State: {resource.lifecycle_state})")