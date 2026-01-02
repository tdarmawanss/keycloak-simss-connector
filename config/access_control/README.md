# Access Control Configuration Guide

This directory contains tools and configurations for managing role-based access control (RBAC) in the Keycloak SIMSS Connector.

## Overview

The access control system uses two JSON files to determine user permissions:

1. **`endpoint_permissions.json`** - Maps API endpoints to required modules and permissions
2. **`role_permissions.json`** - Maps user roles to module privileges (CRUD operations)

These files work together to enforce granular access control across your CodeIgniter application.

## Directory Structure

```
access_control/
├── README.md                              # This file
├── generate_endpoint_permissions.py       # Script to generate endpoint permissions
├── generate_role_permissions.py            # Script to convert CSV to role permissions
├── validate_module_consistency.py            # Script to check modules in role and endpoint permissions match
├── access_control_simadis.csv            # Example CSV (reference implementation)
└── client_<name>/                        # Client-specific configurations
    ├── access_control.csv                # Client's access control matrix
    ├── endpoint_permissions.json         # Client's endpoint mappings
    └── role_permissions.json             # Client's role permissions
```

## Setting Up Access Control for a New Client

Follow these steps to configure access control for a new client:

### Step 1: Create Client Directory

Create a new directory for your client:

```bash
cd /path/to/keycloak-simss-connector/config/access_control
mkdir client_<client_name>
```

**Example:**
```bash
mkdir client_acme
```

### Step 2: Create Access Control CSV

Create a CSV file that defines roles and their permissions for each module.

**File:** `client_<client_name>/access_control.csv`

#### CSV Structure

The CSV has a specific format with three sections:

1. **Row 1: Module Names** - Define your application modules
2. **Row 2: CRUD Headers** - Define permissions (C, R, U, D) for each module
3. **Row 3+: Role Data** - Define which permissions each role has

#### CSV Template

```csv
⚙️ Modul,Module 1,,,Module 2,,,Module 3,,,
Role Name,C,R,U,D,C,R,U,D,C,R,U,D
Admin,y,y,y,y,y,y,y,y,y,y,y,y
Manager,,y,,,,y,,,y,y,y,
Staff,,y,,,,y,,,,y,,,
```

#### CSV Example

```csv
⚙️ Modul,Data Produk,,,Data Stock,,,Data Ekspedisi,,,Requisisi Barang,,,
user role,C,R,U,D,C,R,U,D,C,R,U,D,C,R,U,D
Branch Manager,,y,,,,y,,,,y,,,,y,,
BOC Manager,,y,,,,y,,,,y,,,,y,,
General Manager,,y,,,,y,,,,y,,,,y,,
Logistic Manager,y,y,y,,,y,,,y,y,y,,y,y,y,
Logistic Staff,y,y,y,,,y,,,y,y,y,,y,y,y,
Administrator,y,y,y,y,y,y,y,y,y,y,y,y,y,y,y,y
```

#### CSV Guidelines

- **First column** = Role name (will be normalized to lowercase with underscores)
- **Module names** = Will be converted to **snake_case** (lowercase with underscores)
  - Example: "Data Produk" → "data_produk"
  - Example: "Requisisi Barang" → "requisisi_barang"
- **Modules** = Group related permissions (each module takes 4 columns: C, R, U, D)
- **Permission markers**:
  - `y` or `Y` = Permission granted
  - `yes` = Permission granted
  - `x` or `X` = Permission granted
  - `1` = Permission granted
  - Empty = Permission denied
- **Emojis** in module headers are supported and will be stripped automatically

### Step 3: Generate Role Permissions JSON

Convert your CSV to a role permissions JSON file:

```bash
cd /path/to/keycloak-simss-connector/config/access_control

python3 generate_role_permissions.py \
  client_<client_name>/access_control.csv \
  client_<client_name>/role_permissions.json
```

**Example:**
```bash
python3 generate_role_permissions.py \
  client_acme/access_control.csv \
  client_acme/role_permissions.json
```

**Expected Output:**
```
✓ Successfully converted CSV to JSON
   Input:  client_acme/access_control.csv
   Output: client_acme/role_permissions.json

Generated 6 roles:
   - branch_manager (Branch Manager): 4 modules
   - boc_manager (BOC Manager): 4 modules
   - administrator (Administrator): 4 modules
```

#### Output Format

The generated JSON will look like this (note that module names are converted to snake_case):

```json
{
  "_meta": {
    "description": "Maps user roles to module privileges (CRUD)...",
    "generated_from": "access_control.csv",
    "generated_at": "2026-01-02 10:51:30"
  },
  "roles": {
    "administrator": {
      "display_name": "Administrator",
      "modules": {
        "data_produk": ["C", "R", "U", "D"],
        "data_stock": ["C", "R", "U", "D"]
      }
    },
    "manager": {
      "display_name": "Manager",
      "modules": {
        "data_produk": ["R"],
        "data_stock": ["R"]
      }
    }
  }
}
```

### Step 4: Generate Endpoint Permissions JSON

Generate endpoint mappings from your CodeIgniter controllers:

```bash
# First, edit the script to update the paths
# Open generate_endpoint_permissions.py and update these lines:

# ci3_app_path = "/path/to/your/ci3/application"
# output_json = "client_<client_name>/endpoint_permissions.json"
```

**Example configuration in `generate_endpoint_permissions.py`:**
```python
def main():
    # Path to your CI3 application
    ci3_app_path = "/Users/discovery-air/Documents/simadiskc/application"

    # Output path for the JSON file
    output_json = "/path/to/keycloak-simss-connector/config/access_control/client_acme/endpoint_permissions.json"
```

**Then run:**
```bash
python3 generate_endpoint_permissions.py
```

**Expected Output:**
```
Starting CI3 Endpoint Permissions Generator...

1. Parsing routes.php...
   Found 5 custom routes

2. Scanning controllers...
   Found 184 endpoints

3. Applying custom routes...
   Total endpoints after routes: 189

4. Generating JSON file...
✓ Generated endpoint permissions file: client_acme/endpoint_permissions.json
✓ Total endpoints: 189
✓ New endpoints added: 189
✓ Existing endpoints preserved: 0
```

#### Output Format

The generated JSON will have this structure:

```json
{
  "spb/add": {
    "controller": "Spb",
    "method": "add",
    "modules": [
      { "name": "module_name", "permissions": ["C", "R", "U", "D"] }
    ]
  },
  "spb/getdatabarang": {
    "controller": "Spb",
    "method": "getdatabarang",
    "modules": [
      { "name": "module_name", "permissions": ["C", "R", "U", "D"] }
    ]
  }
}
```

### Step 5: Configure Endpoint Modules

**Important:** The generated `endpoint_permissions.json` contains placeholder module data. You need to manually edit this file to map each endpoint to the correct modules.

**Example - Before (generated):**
```json
{
  "spb/getdatabarang": {
    "controller": "Spb",
    "method": "getdatabarang",
    "modules": [
      { "name": "module_name", "permissions": ["C", "R", "U", "D"] }
    ]
  }
}
```

**Example - After (manually configured):**
```json
{
  "spb/getdatabarang": {
    "controller": "Spb",
    "method": "getdatabarang",
    "modules": [
      { "name": "spb", "permissions": ["R"] },
      { "name": "data_produk", "permissions": ["R"] }
    ]
  }
}
```

#### Guidelines for Mapping Endpoints to Modules

1. **Identify the business function** - What does this endpoint do?
2. **Map to CSV modules** - Which modules from your CSV are required?
3. **Specify required permissions** - What CRUD operations are needed?
4. **Consider combinations** - An endpoint may require multiple modules

**⚠️ Important:** Module names in `endpoint_permissions.json` must match the snake_case format used in `role_permissions.json`. Since the CSV converter automatically converts module names to snake_case (e.g., "Data Produk" → "data_produk"), ensure you use the same snake_case names when configuring endpoints.

**Examples:**

```json
{
  "spb/add": {
    "controller": "Spb",
    "method": "add",
    "modules": [
      { "name": "spb", "permissions": ["C"] },
      { "name": "data_produk", "permissions": ["R"] },
      { "name": "data_stock", "permissions": ["U"] }
    ]
  },
  "spb/delete": {
    "controller": "Spb",
    "method": "delete",
    "modules": [
      { "name": "spb", "permissions": ["D"] }
    ]
  },
  "report/view": {
    "controller": "Report",
    "method": "view",
    "modules": [
      { "name": "data_produk", "permissions": ["R"] },
      { "name": "data_stock", "permissions": ["R"] }
    ]
  }
}
```

### Step 6: Update Application Configuration

Point your application to use the client-specific configuration.

**Edit `application/config/keycloak.php` and add the access_control configuration:**

```php
// application/config/keycloak.php
$config['keycloak']['access_control'] = [
    'endpoint_permissions' => APPPATH . 'third_party/keycloak-simss-connector/config/access_control/client_acme/endpoint_permissions.json',
    'role_permissions' => APPPATH . 'third_party/keycloak-simss-connector/config/access_control/client_acme/role_permissions.json'
];
```

**Important Notes:**
- Replace `client_acme` with your actual client directory name
- If this configuration is **not specified**, the connector will default to:
  - `config/access_control/[client_id]/endpoint_permissions.json`
  - `config/access_control/[client_id]/role_permissions.json`
  - Where `[client_id]` is your Keycloak client ID
- **Recommended:** Always use explicit paths for clarity and maintainability

## Updating Existing Configurations

### Adding New Roles

1. Edit your CSV file (`client_<name>/access_control.csv`)
2. Add new role rows with their permissions
3. Regenerate the role permissions JSON:
   ```bash
   python3 generate_role_permissions.py \
     client_<name>/access_control.csv \
     client_<name>/role_permissions.json
   ```

### Adding New Endpoints

When you add new controllers or methods to your CodeIgniter application:

1. Run the endpoint generator again:
   ```bash
   python3 generate_endpoint_permissions.py
   ```

2. The script will **preserve existing configurations** and only add new endpoints

3. Manually configure the new endpoints in the JSON file

**Example Output:**
```
✓ Total endpoints: 195
✓ New endpoints added: 6
✓ Existing endpoints preserved: 189
```

### Modifying Permissions

- **Role permissions**: Edit CSV and regenerate JSON
- **Endpoint mappings**: Directly edit the `endpoint_permissions.json` file

## How Access Control Works

### Authorization Flow

1. **User makes API request** → `GET /api/spb/getdatabarang`

2. **Endpoint lookup** → Check `endpoint_permissions.json`:
   ```json
   "spb/getdatabarang": {
     "modules": [
       { "name": "spb", "permissions": ["R"] },
       { "name": "data_produk", "permissions": ["R"] }
     ]
   }
   ```

3. **Role lookup** → Check user's role in `role_permissions.json`:
   ```json
   "logistic_staff": {
     "modules": {
       "spb": ["C", "R", "U"],
       "data_produk": ["R"]
     }
   }
   ```

4. **Permission check** → Verify user has required permissions:
   - ✓ User has `spb: R` permission
   - ✓ User has `data_produk: R` permission
   - **Result: Access GRANTED**

### Permission Codes

- **C** - Create (POST, add new records)
- **R** - Read (GET, view records)
- **U** - Update (PUT/PATCH, modify records)
- **D** - Delete (DELETE, remove records)

## Troubleshooting

### Common Issues

**Issue: Script not finding controllers**
- Verify the CI3 application path in `generate_endpoint_permissions.py`
- Ensure controllers directory exists

**Issue: CSV parsing errors**
- Check CSV format matches the template
- Ensure CRUD headers are in correct order (C, R, U, D)
- Verify module names span the correct number of columns

**Issue: Permissions not working**
- Verify module names match exactly between both JSON files
- Check that role names in Keycloak match the normalized keys (lowercase, underscores)
- Ensure JSON files are valid (use a JSON validator)

### Validation

**Validate JSON syntax:**
```bash
python3 -m json.tool client_<name>/endpoint_permissions.json
python3 -m json.tool client_<name>/role_permissions.json
```

**Check module consistency (Recommended - Automated):**
```bash
# Use the validation script for detailed analysis
python3 validate_module_consistency.py client_<name>

# Exit code 0 = consistent, 1 = inconsistent
```


## Support

For issues or questions:
1. Check the Keycloak SIMSS Connector documentation
2. Review example configurations in this directory
3. Validate JSON files for syntax errors
4. Verify module names are consistent across files

## Scripts Reference

### generate_endpoint_permissions.py

**Purpose:** Scans CodeIgniter controllers and generates endpoint permissions skeleton

**Features:**
- Recursively scans controller directories
- Parses routes.php for custom routes
- Generates skeleton with placeholder modules
- Preserves existing endpoint configurations on re-run

**Usage:**
```bash
python3 generate_endpoint_permissions.py
```

### generate_role_permissions.py

**Purpose:** Converts CSV access control matrix to JSON role permissions

**Features:**
- Parses multi-module CSV format
- Validates CRUD header structure
- **Normalizes role and module names to snake_case**
  - Role names: "Branch Manager" → "branch_manager"
  - Module names: "Data Produk" → "data_produk"
- Generates metadata-rich JSON output
- Strips emojis and special characters from module names

**Usage:**
```bash
python3 generate_role_permissions.py <input.csv> [output.json]
```

**Options:**
- `input.csv` - Path to access control CSV file (required)
- `output.json` - Path to output JSON file (optional, defaults to `role_permissions.json` in CSV directory)

### validate_module_consistency.py

**Purpose:** Validates module name consistency between endpoint_permissions.json and role_permissions.json

**Features:**
- Extracts all modules from both JSON files
- Compares module lists and identifies discrepancies
- Shows detailed usage statistics for each module
- Provides actionable recommendations for fixing inconsistencies
- Exit code 0 = consistent, 1 = inconsistent (useful for CI/CD)

**Usage:**
```bash
python3 validate_module_consistency.py [client_directory]

# Examples:
python3 validate_module_consistency.py client_acme
python3 validate_module_consistency.py .
```

**Example Output (Inconsistent):**
```
✗ INCONSISTENCY DETECTED!

⚠️  Modules in endpoint_permissions.json but NOT in role_permissions.json (1):
   ✗ data_ekspedisi
      Used in 3 endpoint(s), requires permissions: [C,R,U]

   → Action: Add these modules to role_permissions.json

⚠️  Modules in role_permissions.json but NOT in endpoint_permissions.json (1):
   ✗ unused_settings

   → Action: Either:
      1. Remove these unused modules from role_permissions.json, OR
      2. Add endpoints that use these modules
```

**Example Output (Consistent):**
```
✓ SUCCESS: All modules are consistent!

📌 4 modules found in both files:
   ✓ data_produk
   ✓ data_stock
   ✓ requisisi_barang
   ✓ spb
```

**When to Use:**
- After generating or updating endpoint_permissions.json
- After regenerating role_permissions.json from CSV
- Before deploying to production
- As part of CI/CD validation
