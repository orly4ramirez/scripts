#!/bin/bash
# OCI Encryption Keys Comprehensive Listing Script
# This script lists all encryption keys in OCI, their properties, and associated resources
# It uses your current OCI CLI configuration

# Set default values
COMPARTMENT_ID=""
PROFILE=""
OUTPUT_DIR="./oci_encryption_keys_report_$(date +%Y%m%d_%H%M%S)"
OUTPUT_FILE="$OUTPUT_DIR/encryption_keys_report.json"
CSV_OUTPUT="$OUTPUT_DIR/encryption_keys_report.csv"
HTML_OUTPUT="$OUTPUT_DIR/encryption_keys_report.html"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --compartment-id)
      if [[ -z "$2" || "$2" == --* ]]; then
        echo "Error: --compartment-id requires a value"
        exit 1
      fi
      COMPARTMENT_ID="$2"
      shift 2
      ;;
    --profile)
      if [[ -z "$2" || "$2" == --* ]]; then
        echo "Error: --profile requires a value"
        exit 1
      fi
      PROFILE="--profile $2"
      shift 2
      ;;
    --output-dir)
      if [[ -z "$2" || "$2" == --* ]]; then
        echo "Error: --output-dir requires a value"
        exit 1
      fi
      OUTPUT_DIR="$2"
      OUTPUT_FILE="$OUTPUT_DIR/encryption_keys_report.json"
      CSV_OUTPUT="$OUTPUT_DIR/encryption_keys_report.csv"
      HTML_OUTPUT="$OUTPUT_DIR/encryption_keys_report.html"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--compartment-id COMPARTMENT_ID] [--profile PROFILE_NAME] [--output-dir OUTPUT_DIRECTORY]"
      echo ""
      echo "Options:"
      echo "  --compartment-id   Specify the OCID of the compartment to search (default: root compartment)"
      echo "  --profile          Specify the OCI CLI profile to use (default: DEFAULT profile)"
      echo "  --output-dir       Specify the output directory for reports (default: timestamped directory)"
      echo "  -h, --help         Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use -h or --help for usage information"
      exit 1
      ;;
  esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "Starting comprehensive OCI encryption keys report..."
echo "Results will be saved to: $OUTPUT_DIR"

# Initialize JSON file with array structure
echo "[]" > "$OUTPUT_FILE"

# Get tenancy OCID if compartment ID not specified
if [ -z "$COMPARTMENT_ID" ]; then
  echo "No compartment ID specified, using tenancy root compartment..."
  COMPARTMENT_ID=$(oci iam compartment list $PROFILE --compartment-id-in-subtree true --all --query "data[?\"compartment-id\" == null].id | [0]" --raw-output)
  
  if [ -z "$COMPARTMENT_ID" ]; then
    echo "Error: Failed to retrieve tenancy OCID. Please specify --compartment-id."
    exit 1
  fi
  
  echo "Using tenancy root compartment: $COMPARTMENT_ID"
fi

# Function to list all compartments recursively
get_all_compartments() {
  local parent_compartment_id=$1
  
  echo "Retrieving all compartments under $parent_compartment_id..."
  
  # Get all compartments, including the root one
  COMPARTMENTS=$(oci iam compartment list $PROFILE --compartment-id-in-subtree true --all --query "data[?\"lifecycle-state\" == 'ACTIVE']" --raw-output)
  
  echo "$COMPARTMENTS"
}

# Function to fetch all vaults in a compartment
get_vaults_in_compartment() {
  local compartment_id=$1
  
  echo "Retrieving vaults in compartment $compartment_id..."
  
  VAULTS=$(oci kms management vault list $PROFILE --compartment-id "$compartment_id" --all --query "data[?\"lifecycle-state\" == 'ACTIVE']" --raw-output)
  
  echo "$VAULTS"
}

# Function to fetch all keys in a vault
get_keys_in_vault() {
  local compartment_id=$1
  local vault_id=$2
  local vault_management_endpoint=$3
  
  echo "Retrieving keys in vault $vault_id..."
  
  KEYS=$(oci kms management key list $PROFILE --compartment-id "$compartment_id" --endpoint "$vault_management_endpoint" --all --query "data[?\"lifecycle-state\" != 'DELETED']" --raw-output)
  
  echo "$KEYS"
}

# Function to get key details
get_key_details() {
  local key_id=$1
  local vault_management_endpoint=$2
  
  echo "Retrieving details for key $key_id..."
  
  KEY_DETAILS=$(oci kms management key get $PROFILE --key-id "$key_id" --endpoint "$vault_management_endpoint" --raw-output)
  
  echo "$KEY_DETAILS"
}

# Function to get key versions
get_key_versions() {
  local key_id=$1
  local vault_management_endpoint=$2
  
  echo "Retrieving versions for key $key_id..."
  
  KEY_VERSIONS=$(oci kms management key-version list $PROFILE --key-id "$key_id" --endpoint "$vault_management_endpoint" --all --raw-output)
  
  echo "$KEY_VERSIONS"
}

# Function to find resources that use a particular key
find_resources_using_key() {
  local compartment_id=$1
  local key_id=$2
  
  echo "Finding resources that use key $key_id..."
  
  # Check if jq is installed
  if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Please install jq package."
    return 1
  fi
  
  # Use resource-search to find resources that reference this key
  # First, check if resource-search command exists
  if ! oci search resource --help &> /dev/null; then
    echo "Warning: 'oci search resource' command not available. Skipping resource search."
    echo "[]"
    return 0
  fi
  
  RESOURCES=$(oci search resource structured-search $PROFILE --query-text "query all resources where (definedTags.contains('*.\"EncryptionKey\".*') || freeformTags.contains('*EncryptionKey*') || (resourceType = 'VolumeBackup' && isEncrypted = 'true') || (resourceType = 'BootVolume' && isEncrypted = 'true') || (resourceType = 'Volume' && isEncrypted = 'true') || (resourceType = 'Bucket' && isEncrypted = 'true') || (resourceType = 'Database' && isEncrypted = 'true') || (resourceType = 'AutonomousDatabase' && isEncrypted = 'true') || (resourceType = 'FileSystem' && isEncrypted = 'true'))" --raw-output 2>/dev/null)
  
  # Check if command succeeded
  if [ $? -ne 0 ]; then
    echo "Warning: Error running resource search. Returning empty result."
    echo "[]"
    return 0
  fi
  
  # Filter results to find specific references to the key
  FILTERED_RESOURCES=$(echo "$RESOURCES" | jq --arg key_id "$key_id" '.data.items[] | select(.attributes | tostring | contains($key_id))' 2>/dev/null || echo "[]")
  
  echo "$FILTERED_RESOURCES"
}

# Main execution

# Check for required tools
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed. Please install jq package."; exit 1; }
command -v oci >/dev/null 2>&1 || { echo "Error: OCI CLI is required but not installed. Please install OCI CLI."; exit 1; }

# Create output directory
echo "Creating output directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR" || { echo "Error: Failed to create output directory."; exit 1; }

# Initialize empty JSON file
echo "[]" > "$OUTPUT_FILE"

# Verify OCI CLI configuration
echo "Verifying OCI CLI configuration..."
oci iam region list $PROFILE --output table >/dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "Error: OCI CLI configuration issue. Please check your configuration with 'oci setup config'."
  exit 1
fi

# Get all compartments
echo "Retrieving compartments..."
ALL_COMPARTMENTS=$(get_all_compartments "$COMPARTMENT_ID")
if [ $? -ne 0 ]; then
  echo "Error retrieving compartments. Exiting."
  exit 1
fi

# Check if any compartments were found
if [ "$(echo "$ALL_COMPARTMENTS" | jq 'length')" -eq 0 ]; then
  echo "No compartments found. Check your permissions and compartment ID."
  exit 1
fi

# Initialize results array
RESULTS="[]"
KEYS_FOUND=0

# Process each compartment
echo "$ALL_COMPARTMENTS" | jq -c '.[]' 2>/dev/null | while read -r compartment; do
  # Check if compartment is valid JSON
  if [ -z "$compartment" ]; then
    continue
  fi
  
  compartment_id=$(echo "$compartment" | jq -r '.id' 2>/dev/null)
  compartment_name=$(echo "$compartment" | jq -r '.name' 2>/dev/null || echo "Unknown")
  
  # Skip if compartment_id is empty or null
  if [ -z "$compartment_id" ] || [ "$compartment_id" = "null" ]; then
    echo "Warning: Invalid compartment data. Skipping."
    continue
  fi
  
  echo "Processing compartment: $compartment_name ($compartment_id)"
  
  # Get vaults in compartment
  VAULTS=$(get_vaults_in_compartment "$compartment_id")
  
  # Check if any vaults were found
  if [ "$(echo "$VAULTS" | jq 'length')" -eq 0 ]; then
    echo "No vaults found in compartment $compartment_name."
    continue
  fi
  
  echo "$VAULTS" | jq -c '.[]' 2>/dev/null | while read -r vault; do
    # Check if vault is valid JSON
    if [ -z "$vault" ]; then
      continue
    fi
    
    vault_id=$(echo "$vault" | jq -r '.id' 2>/dev/null)
    vault_name=$(echo "$vault" | jq -r '.["display-name"]' 2>/dev/null || echo "Unknown")
    vault_management_endpoint=$(echo "$vault" | jq -r '.["management-endpoint"]' 2>/dev/null || echo "")
    vault_crypto_endpoint=$(echo "$vault" | jq -r '.["crypto-endpoint"]' 2>/dev/null || echo "")
    
    # Skip if vault_id is empty or null
    if [ -z "$vault_id" ] || [ "$vault_id" = "null" ]; then
      echo "Warning: Invalid vault data. Skipping."
      continue
    fi
    
    echo "Processing vault: $vault_name ($vault_id)"
    
    # Get keys in vault
    KEYS=$(get_keys_in_vault "$compartment_id" "$vault_id" "$vault_management_endpoint")
    
    # Check if any keys were found
    if [ "$(echo "$KEYS" | jq 'length')" -eq 0 ]; then
      echo "No keys found in vault $vault_name."
      continue
    fi
    
    echo "$KEYS" | jq -c '.[]' 2>/dev/null | while read -r key; do
      # Check if key is valid JSON
      if [ -z "$key" ]; then
        continue
      fi
      
      key_id=$(echo "$key" | jq -r '.id' 2>/dev/null)
      key_name=$(echo "$key" | jq -r '.["display-name"]' 2>/dev/null || echo "Unknown")
      
      # Skip if key_id is empty or null
      if [ -z "$key_id" ] || [ "$key_id" = "null" ]; then
        echo "Warning: Invalid key data. Skipping."
        continue
      fi
      
      echo "Processing key: $key_name ($key_id)"
      
      # Get key details
      KEY_DETAILS=$(get_key_details "$key_id" "$vault_management_endpoint")
      
      # Get key versions
      KEY_VERSIONS=$(get_key_versions "$key_id" "$vault_management_endpoint")
      
      # Find resources using this key
      RESOURCES_USING_KEY=$(find_resources_using_key "$compartment_id" "$key_id")
      
      # Create key entry
      KEY_ENTRY=$(jq -n \
        --arg compartment_id "$compartment_id" \
        --arg compartment_name "$compartment_name" \
        --arg vault_id "$vault_id" \
        --arg vault_name "$vault_name" \
        --arg vault_management_endpoint "$vault_management_endpoint" \
        --arg vault_crypto_endpoint "$vault_crypto_endpoint" \
        --argjson key_details "$KEY_DETAILS" \
        --argjson key_versions "$KEY_VERSIONS" \
        --argjson resources_using_key "$RESOURCES_USING_KEY" \
        '{
          "compartment_id": $compartment_id,
          "compartment_name": $compartment_name,
          "vault_id": $vault_id,
          "vault_name": $vault_name,
          "vault_management_endpoint": $vault_management_endpoint,
          "vault_crypto_endpoint": $vault_crypto_endpoint,
          "key_details": $key_details,
          "key_versions": $key_versions,
          "resources_using_key": $resources_using_key
        }' 2>/dev/null)
      
      # Check if key entry is valid JSON
      if [ -z "$KEY_ENTRY" ]; then
        echo "Warning: Failed to create key entry for $key_name. Skipping."
        continue
      fi
      
      # Append to results
      TEMP_RESULTS=$(echo "$RESULTS" | jq --argjson key_entry "$KEY_ENTRY" '. += [$key_entry]' 2>/dev/null)
      if [ $? -eq 0 ]; then
        RESULTS="$TEMP_RESULTS"
        KEYS_FOUND=$((KEYS_FOUND + 1))
        # Write current results to file (in case of interruption)
        echo "$RESULTS" > "$OUTPUT_FILE"
      else
        echo "Warning: Failed to add key $key_name to results."
      fi
      
      echo "Processed $KEYS_FOUND keys so far..."
    done
  done
done

# Write final results to file
echo "$RESULTS" > "$OUTPUT_FILE"
echo "Successfully processed $KEYS_FOUND encryption keys."

# Generate CSV report
echo "Generating CSV report..."
jq -r '(["Compartment Name", "Vault Name", "Key Name", "Key ID", "Algorithm", "Protection Mode", "Current Key Version", "State", "Created Date", "Resources Using Key"] | join(",")) + 
  (map([
    (.compartment_name // "Unknown"), 
    (.vault_name // "Unknown"), 
    (.key_details.data."display-name" // "Unknown"), 
    (.key_details.data.id // "Unknown"), 
    (.key_details.data.algorithm // "Unknown"), 
    (.key_details.data."protection-mode" // "Unknown"), 
    (.key_details.data."current-key-version" // "Unknown"), 
    (.key_details.data."lifecycle-state" // "Unknown"), 
    (.key_details.data."time-created" // "Unknown"), 
    ((.resources_using_key | length | tostring) // "0")
  ] | join(",")) | join("\n"))' "$OUTPUT_FILE" > "$CSV_OUTPUT" 2>/dev/null

# Check if CSV generation succeeded
if [ $? -ne 0 ]; then
  echo "Warning: Failed to generate CSV report. Check the JSON output file."
  echo "Compartment Name,Vault Name,Key Name,Key ID,Algorithm,Protection Mode,Current Key Version,State,Created Date,Resources Using Key" > "$CSV_OUTPUT"
  echo "Error generating report,,,,,,,,,0" >> "$CSV_OUTPUT"
fi

# Generate HTML report
echo "Generating HTML report..."
cat > "$HTML_OUTPUT" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OCI Encryption Keys Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #336699; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    tr:nth-child(even) { background-color: #f9f9f9; }
    .section { margin-top: 30px; }
    .subsection { margin-left: 20px; margin-top: 20px; }
    .collapsible { cursor: pointer; background-color: #eee; padding: 10px; border: none; text-align: left; outline: none; width: 100%; }
    .active, .collapsible:hover { background-color: #ccc; }
    .content { padding: 0 18px; display: none; overflow: hidden; background-color: #f1f1f1; }
  </style>
</head>
<body>
  <h1>OCI Encryption Keys Report</h1>
  <p>Report generated on: $(date)</p>
  
  <div class="section">
    <h2>Summary</h2>
    <p>Total keys: <span id="total-keys">0</span></p>
  </div>
  
  <div class="section">
    <h2>Encryption Keys</h2>
    <table id="keys-table">
      <tr>
        <th>Compartment</th>
        <th>Vault</th>
        <th>Key Name</th>
        <th>Key ID</th>
        <th>Algorithm</th>
        <th>Protection Mode</th>
        <th>Current Version</th>
        <th>State</th>
        <th>Created Date</th>
        <th>Resources Count</th>
        <th>Details</th>
      </tr>
    </table>
  </div>

  <div id="key-details">
    <!-- Key details will be inserted here -->
  </div>

  <script>
    // Load and process JSON data
    fetch('encryption_keys_report.json')
      .then(response => response.json())
      .then(data => {
        // Update summary
        document.getElementById('total-keys').textContent = data.length;
        
        // Populate keys table
        const keysTable = document.getElementById('keys-table');
        const keyDetails = document.getElementById('key-details');
        
        data.forEach((item, index) => {
          const keyData = item.key_details.data;
          const resourcesCount = Array.isArray(item.resources_using_key) ? item.resources_using_key.length : 0;
          
          // Add row to the table
          const row = keysTable.insertRow();
          row.innerHTML = \`
            <td>\${item.compartment_name}</td>
            <td>\${item.vault_name}</td>
            <td>\${keyData["display-name"]}</td>
            <td>\${keyData.id}</td>
            <td>\${keyData.algorithm || 'N/A'}</td>
            <td>\${keyData["protection-mode"]}</td>
            <td>\${keyData["current-key-version"]}</td>
            <td>\${keyData["lifecycle-state"]}</td>
            <td>\${new Date(keyData["time-created"]).toLocaleString()}</td>
            <td>\${resourcesCount}</td>
            <td><button class="collapsible" data-index="\${index}">Details</button></td>
          \`;
          
          // Create detailed view for the key
          const detailSection = document.createElement('div');
          detailSection.id = \`key-detail-\${index}\`;
          detailSection.className = 'content';
          
          // Key versions
          let versionsHtml = '<h3>Key Versions</h3>';
          if (item.key_versions && item.key_versions.data && item.key_versions.data.length > 0) {
            versionsHtml += '<table><tr><th>Version</th><th>ID</th><th>State</th><th>Created</th></tr>';
            item.key_versions.data.forEach(version => {
              versionsHtml += \`
                <tr>
                  <td>\${version["key-version-number"]}</td>
                  <td>\${version.id}</td>
                  <td>\${version["lifecycle-state"]}</td>
                  <td>\${new Date(version["time-created"]).toLocaleString()}</td>
                </tr>
              \`;
            });
            versionsHtml += '</table>';
          } else {
            versionsHtml += '<p>No version information available</p>';
          }
          
          // Resources using key
          let resourcesHtml = '<h3>Resources Using This Key</h3>';
          if (resourcesCount > 0) {
            resourcesHtml += '<table><tr><th>Resource Type</th><th>Name</th><th>ID</th></tr>';
            item.resources_using_key.forEach(resource => {
              resourcesHtml += \`
                <tr>
                  <td>\${resource.resourceType || 'N/A'}</td>
                  <td>\${resource["display-name"] || 'N/A'}</td>
                  <td>\${resource.identifier || 'N/A'}</td>
                </tr>
              \`;
            });
            resourcesHtml += '</table>';
          } else {
            resourcesHtml += '<p>No resources found using this key</p>';
          }
          
          // Add detailed key properties
          const keyPropertiesHtml = \`
            <h3>Key Properties</h3>
            <table>
              <tr><th>Property</th><th>Value</th></tr>
              <tr><td>Compartment</td><td>\${item.compartment_name} (\${item.compartment_id})</td></tr>
              <tr><td>Vault</td><td>\${item.vault_name} (\${item.vault_id})</td></tr>
              <tr><td>Key Name</td><td>\${keyData["display-name"]}</td></tr>
              <tr><td>Key ID</td><td>\${keyData.id}</td></tr>
              <tr><td>Algorithm</td><td>\${keyData.algorithm || 'N/A'}</td></tr>
              <tr><td>Protection Mode</td><td>\${keyData["protection-mode"]}</td></tr>
              <tr><td>Current Version</td><td>\${keyData["current-key-version"]}</td></tr>
              <tr><td>State</td><td>\${keyData["lifecycle-state"]}</td></tr>
              <tr><td>Created Date</td><td>\${new Date(keyData["time-created"]).toLocaleString()}</td></tr>
              <tr><td>Crypto Endpoint</td><td>\${item.vault_crypto_endpoint}</td></tr>
              <tr><td>Management Endpoint</td><td>\${item.vault_management_endpoint}</td></tr>
            </table>
          \`;
          
          detailSection.innerHTML = keyPropertiesHtml + versionsHtml + resourcesHtml;
          keyDetails.appendChild(detailSection);
        });
        
        // Add event listeners to collapsible buttons
        document.querySelectorAll('.collapsible').forEach(button => {
          button.addEventListener('click', function() {
            this.classList.toggle('active');
            const content = document.getElementById(\`key-detail-\${this.dataset.index}\`);
            if (content.style.display === 'block') {
              content.style.display = 'none';
            } else {
              // Hide all other open sections
              document.querySelectorAll('.content').forEach(section => {
                section.style.display = 'none';
              });
              content.style.display = 'block';
            }
          });
        });
      })
      .catch(error => {
        console.error('Error loading data:', error);
        document.body.innerHTML += \`<p style="color: red">Error loading data: \${error.message}</p>\`;
      });
  </script>
</body>
</html>
EOF

echo "Report generation complete."
echo "JSON report: $OUTPUT_FILE"
echo "CSV report: $CSV_OUTPUT"
echo "HTML report: $HTML_OUTPUT"
echo ""
echo "Usage example:"
echo "  To generate a report for a specific compartment:"
echo "    $0 --compartment-id <compartment-ocid>"
echo ""
echo "  To use a specific OCI CLI profile:"
echo "    $0 --profile <profile-name>"
echo ""
echo "  To specify a custom output directory:"
echo "    $0 --output-dir /path/to/output/directory"