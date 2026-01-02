# Keycloak User Import Script

This directory contains a Python script for programmatically creating users in your Keycloak realm.

## Prerequisites

- Python 3.6 or higher
- Admin access to your Keycloak instance
- Network access to your Keycloak server

## Installation

1. **Install Required Python Packages:**

```bash
pip install requests python-dotenv
```

2. **Set Up Environment Variables:**

Copy the `.env.example` file to `.env`:

```bash
cp .env.example .env
```

Then edit `.env` and add your Keycloak admin credentials:

**Option A: Admin Username/Password**
```
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=your_password
```

**Option B: Service Account (Recommended for Production)**
```
KEYCLOAK_CLIENT_ID=your-service-account-client
KEYCLOAK_CLIENT_SECRET=your_client_secret
```

## Configuration

### Keycloak Settings

The script is pre-configured with your Keycloak server details from `keycloak.php`:

- **Server:** `https://keycloak-azure.icyriver-61c098d4.southeastasia.azurecontainerapps.io`
- **Realm:** `master`

If you need to change these, edit the following variables in `create_keycloak_users.py`:

```python
KEYCLOAK_SERVER = "https://your-keycloak-server"
REALM = "your-realm-name"
```

### User Data

Edit the `USERS_TO_CREATE` list in `create_keycloak_users.py` to define the users you want to create:

```python
USERS_TO_CREATE = [
    {
        "username": "john.doe",
        "email": "john.doe@example.com",
        "firstName": "John",
        "lastName": "Doe",
        "enabled": True,
        "emailVerified": True,
        "password": "ChangeMe123!",
        "temporary_password": True,  # User must change on first login
        "groups": ["users"],  # Optional
        "attributes": {  # Optional custom attributes
            "department": ["IT"],
            "employee_id": ["EMP001"]
        }
    }
]
```

## Usage

The script supports three ways to import users:

1. **Hardcoded list** - Edit `USERS_TO_CREATE` in the script
2. **CSV file** - Automatic if `users.csv` exists, or specify: `python create_keycloak_users.py path/to/users.csv`
3. **JSON file** - Automatic if `users.json` exists, or specify: `python create_keycloak_users.py path/to/users.json`

> Users that already exist in the system will cause the script to fail.


### Basic Usage

**Option 1: Using hardcoded list**
```bash
python create_keycloak_users.py
```

**Option 2: Using CSV file**
```bash
# Automatically detected if named users.csv
python create_keycloak_users.py

# Or specify file path
python create_keycloak_users.py my_users.csv
```

**Option 3: Using JSON file**
```bash
# Automatically detected if named users.json
python create_keycloak_users.py

# Or specify file path
python create_keycloak_users.py my_users.json
```

#### Using the User Role Access Control CSV to generate JSON file

It is recommended to use an AI agent and prompt the agent to create the JSON file. Use `PROMPT_INSTRUCTIONS.md` and modify the input file variable.  

### User Data Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes | Unique username |
| `email` | string | No | User's email address |
| `firstName` | string | No | First name |
| `lastName` | string | No | Last name |
| `enabled` | boolean | No | Enable/disable user (default: `true`) |
| `emailVerified` | boolean | No | Email verification status (default: `false`) |
| `password` | string | No | Initial password |
| `temporary_password` | boolean | No | Require password change on first login (default: `true`) |
| `groups` | array | No | List of group names to add user to |
| `attributes` | object | No | Custom user attributes (key-value pairs) |

## Setting Up Service Account (Advanced)

For production environments, it's recommended to use a service account instead of admin credentials:

1. **Create a Client in Keycloak:**
   - Go to Keycloak Admin Console → Clients → Create
   - Client ID: `user-import-service`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Service Accounts Enabled: `ON`
   - Save the client

2. **Get Client Secret:**
   - Go to Credentials tab
   - Copy the Secret value

3. **Assign Roles:**
   - Go to Service Account Roles tab
   - In Client Roles, select `realm-management`
   - Add these roles:
     - `manage-users`
     - `view-users`
     - `query-groups` (if using groups)

4. **Update .env:**
   ```
   KEYCLOAK_CLIENT_ID=user-import-service
   KEYCLOAK_CLIENT_SECRET=<your-secret>
   ```

## Bulk Import from CSV

The script now has **built-in CSV import support** with full feature parity to the JSON structure!

### CSV Format

Create a `users.csv` file with the following columns:

| Column | Required | Format | Example |
|--------|----------|--------|---------|
| `username` | Yes | String | `john.doe` |
| `email` | No | String | `john@example.com` |
| `firstName` | No | String | `John` |
| `lastName` | No | String | `Doe` |
| `password` | No | String | `ChangeMe123!` |
| `enabled` | No | Boolean | `true` or `false` |
| `emailVerified` | No | Boolean | `true` or `false` |
| `temporary_password` | No | Boolean | `true` or `false` |
| `groups` | No | Pipe-separated | `users\|managers\|admins` |
| `attributes` | No | JSON string | `{"department":["IT"],"id":["001"]}` |

### CSV Example

```csv
username,email,firstName,lastName,password,enabled,emailVerified,temporary_password,groups,attributes
john.doe,john@example.com,John,Doe,Pass123!,true,false,true,users,"{""department"":[""IT""],""employee_id"":[""001""]}"
jane.smith,jane@example.com,Jane,Smith,Pass456!,true,false,true,users|managers,"{""department"":[""HR""],""employee_id"":[""002""]}"
```

**Important CSV Notes:**
- Groups are pipe-separated: `users|managers|admins`
- Attributes must be valid JSON with **double-escaped quotes**: `"{""key"":[""value""]}"`
- Empty fields are allowed (will use defaults)
- The script automatically detects `users.csv` in the current directory

### CSV Tips for Excel/Google Sheets

When creating CSV files in Excel or Google Sheets:

1. **For groups column:** Simply type: `users|managers`
2. **For attributes column:** Type the JSON, Excel will handle the escaping:
   ```
   {"department":["IT"],"employee_id":["001"]}
   ```
3. **Save as CSV:** File → Save As → CSV (Comma delimited)

## Bulk Import from JSON

For complex imports, JSON format is easier to work with:

### JSON Format

Create a `users.json` file:

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
      "location": ["NYC"]
    }
  }
]
```

**JSON Advantages:**
- Easier to write complex nested structures
- No quote escaping needed
- Better for version control and code review
- Supports comments (in some editors)

## Example Files

The repository includes example files you can copy and modify:

- `users.csv.example` - CSV format with all fields
- `users.json.example` - JSON format with all fields

Copy and rename to use:
```bash
cp users.csv.example users.csv
# Edit users.csv with your data
python create_keycloak_users.py
```

## Troubleshooting

### Authentication Failed

**Problem:** `✗ Authentication failed`

**Solution:**
- Verify credentials in `.env` file
- Ensure admin user has proper permissions
- Check network connectivity to Keycloak server

### User Already Exists

**Problem:** `✗ Failed to create user: 409 Conflict`

**Solution:**
- User with that username already exists
- Either delete the existing user or use a different username

### Permission Denied

**Problem:** `✗ Failed to create user: 403 Forbidden`

**Solution:**
- Admin user lacks necessary permissions
- For service account: ensure it has `manage-users` role

### Group Not Found

**Problem:** `! Group 'group-name' not found`

**Solution:**
- Create the group in Keycloak first, or
- Remove the group from user's `groups` array

## Security Best Practices

1. **Never commit `.env` file** - Add it to `.gitignore`
2. **Use strong passwords** for initial user passwords
3. **Use temporary passwords** to force password change on first login
4. **Use service accounts** instead of admin credentials in production
5. **Rotate credentials regularly**
6. **Use HTTPS** for Keycloak server (already configured)
7. **Audit logs** after bulk imports

## Example Output

```
============================================================
Keycloak User Import Script
============================================================

Authenticating with username/password...
✓ Successfully authenticated as admin

============================================================
Starting import of 2 users...
============================================================

Processing user: john.doe
✓ Created user: john.doe (ID: 8b4d7c9a-1234-5678-90ab-cdef12345678)
  ✓ Set temporary password for user ID: 8b4d7c9a-1234-5678-90ab-cdef12345678
  ✓ Added user to group (Group ID: f3a2b1c0-9876-5432-10ab-cdef87654321)

Processing user: jane.smith
✓ Created user: jane.smith (ID: 7c3b2a1d-4321-8765-09ba-fedc21098765)
  ✓ Set temporary password for user ID: 7c3b2a1d-4321-8765-09ba-fedc21098765

============================================================
Import Summary
============================================================
Total users processed: 2
Successfully created:  2
Failed:               0
============================================================
```

## Support

For issues related to:
- **Keycloak configuration:** Check your Keycloak admin console
- **Script errors:** Review error messages and ensure all prerequisites are met
- **Integration with your application:** Refer to the main connector documentation

## Related Files

- `/config/keycloak.php` - Main Keycloak configuration for the application
- `/config/keycloak.example.php` - Example configuration template
