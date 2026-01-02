# User Import Format Reference

Quick reference for all supported import formats.

## 1. Hardcoded Python List

Edit `USERS_TO_CREATE` in `create_keycloak_users.py`:

```python
USERS_TO_CREATE = [
    {
        "username": "john.doe",
        "email": "john.doe@example.com",
        "firstName": "John",
        "lastName": "Doe",
        "enabled": True,
        "emailVerified": False,
        "password": "ChangeMe123!",
        "temporary_password": True,
        "groups": ["users", "managers"],
        "attributes": {
            "department": ["IT"],
            "employee_id": ["EMP001"]
        }
    }
]
```

## 2. CSV Format

**File:** `users.csv`

**Headers:**
```csv
username,email,firstName,lastName,password,enabled,emailVerified,temporary_password,groups,attributes
```

**Example Rows:**
```csv
john.doe,john@example.com,John,Doe,Pass123!,true,false,true,users,"{""department"":[""IT""],""id"":[""001""]}"
jane.smith,jane@example.com,Jane,Smith,Pass456!,true,false,true,users|managers,"{""department"":[""HR""],""id"":[""002""]}"
bob.wilson,bob@example.com,Bob,Wilson,Pass789!,true,true,false,users|admins,"{""department"":[""Engineering""],""team"":[""Backend""]}"
```

**Field Rules:**
- **username** (required): Unique identifier
- **groups**: Pipe-separated list → `users|managers|admins`
- **attributes**: JSON string with **double-escaped quotes** → `"{""key"":[""value""]}"`
- **enabled, emailVerified, temporary_password**: `true` or `false`
- Empty fields use defaults

**Excel/Google Sheets Tips:**
1. Type JSON normally in attributes column: `{"department":["IT"]}`
2. Excel auto-escapes quotes when saving as CSV
3. Use pipe `|` to separate multiple groups

## 3. JSON Format

**File:** `users.json`

```json
[
  {
    "username": "john.doe",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "enabled": true,
    "emailVerified": false,
    "password": "ChangeMe123!",
    "temporary_password": true,
    "groups": ["users", "managers"],
    "attributes": {
      "department": ["IT"],
      "employee_id": ["EMP001"],
      "location": ["NYC"],
      "clearance_level": ["L3"]
    }
  },
  {
    "username": "jane.smith",
    "email": "jane.smith@example.com",
    "firstName": "Jane",
    "lastName": "Smith",
    "enabled": true,
    "emailVerified": true,
    "password": "SecurePass456!",
    "temporary_password": true,
    "groups": ["users", "managers", "admins"],
    "attributes": {
      "department": ["HR"],
      "employee_id": ["EMP002"]
    }
  }
]
```

## Attribute Format Details

Keycloak attributes are stored as **arrays of strings**.

### Correct Format:
```json
{
  "department": ["IT"],
  "employee_id": ["EMP001"],
  "roles": ["developer", "admin"],
  "phone": ["+1-555-0123"]
}
```

### Common Mistakes:
```json
// ❌ WRONG - values must be arrays
{
  "department": "IT",
  "employee_id": "EMP001"
}

// ✅ CORRECT - values are arrays
{
  "department": ["IT"],
  "employee_id": ["EMP001"]
}
```

## Running the Script

```bash
# Auto-detect users.csv or users.json in current directory
python create_keycloak_users.py

# Specify CSV file
python create_keycloak_users.py /path/to/my_users.csv

# Specify JSON file
python create_keycloak_users.py /path/to/my_users.json
```

## Field Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `username` | string | ✅ Yes | - | Unique username |
| `email` | string | No | `""` | Email address |
| `firstName` | string | No | `""` | First name |
| `lastName` | string | No | `""` | Last name |
| `enabled` | boolean | No | `true` | Account enabled |
| `emailVerified` | boolean | No | `false` | Email verified |
| `password` | string | No | `""` | Initial password |
| `temporary_password` | boolean | No | `true` | Require password change |
| `groups` | array/string | No | `[]` | Groups to join |
| `attributes` | object | No | `{}` | Custom attributes |

## Quick Start Examples

### Minimal User (CSV)
```csv
username,email,firstName,lastName,password
john.doe,john@example.com,John,Doe,TempPass123!
```

### Full Featured User (JSON)
```json
[
  {
    "username": "admin.user",
    "email": "admin@company.com",
    "firstName": "Admin",
    "lastName": "User",
    "enabled": true,
    "emailVerified": true,
    "password": "SecureAdminPass123!",
    "temporary_password": false,
    "groups": ["admins", "users", "managers"],
    "attributes": {
      "department": ["IT"],
      "employee_id": ["ADMIN001"],
      "hire_date": ["2024-01-15"],
      "office": ["HQ"],
      "clearance": ["high"]
    }
  }
]
```

## Tips

✅ **Use JSON when:**
- You have complex nested structures
- You're working with many custom attributes
- You want better readability and version control

✅ **Use CSV when:**
- Exporting from Excel/Google Sheets/databases
- You have simple user data
- Non-technical users will edit the file

✅ **Use hardcoded list when:**
- Creating a small number of users (< 10)
- The script itself is temporary
- You want to version control the users with the script
