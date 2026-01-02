#!/usr/bin/env python3
"""
Keycloak User Import Script

This script programmatically creates users in a Keycloak realm using the Keycloak Admin REST API.

HOW TO USE THIS SCRIPT:
-----------------------

1. Install required dependencies:
   pip install requests python-dotenv

2. Create a .env file in the same directory with your admin credentials:
   KEYCLOAK_ADMIN_USERNAME=admin
   KEYCLOAK_ADMIN_PASSWORD=your_admin_password

   OR if using a service account with client credentials:
   KEYCLOAK_CLIENT_ID=admin-cli
   KEYCLOAK_CLIENT_SECRET=your_client_secret

3. Prepare your users data (choose ONE method):

   METHOD A - Hardcoded list:
   - Edit the USERS_TO_CREATE list in this script

   METHOD B - CSV file (supports groups, roles, and attributes):
   - Create users.csv in the same directory (auto-detected), OR
   - Create a CSV file anywhere and pass as argument
   - Format: username,email,firstName,lastName,password,enabled,emailVerified,
            temporary_password,groups,role,attributes
   - Groups: pipe-separated (e.g., "users|managers")
   - Role: single role name (e.g., "admin")
   - Attributes: JSON string (e.g., '{"department":["IT"],"id":["001"]}')

   METHOD C - JSON file (easiest for complex data):
   - Create users.json in the same directory (auto-detected), OR
   - Create a JSON file anywhere and pass as argument
   - Format: Array of user objects matching USERS_TO_CREATE structure

4. Run the script:

   # Auto-detect users.csv or users.json in current directory
   python create_keycloak_users.py

   # Or specify a file
   python create_keycloak_users.py path/to/users.csv
   python create_keycloak_users.py path/to/users.json

IMPORTANT NOTES:
----------------
- This script requires admin privileges or a service account with user management permissions
- The client credentials in your keycloak.php config (simadis-app) are for application authentication,
  NOT for admin API access. You need separate admin credentials.
- Users will be created in the 'master' realm by default (change REALM variable if needed)
- Passwords are set as temporary by default, requiring users to change on first login
- Make sure to keep credentials secure and never commit them to version control

"""

import requests
import json
import sys
import csv
from typing import Dict, List, Optional
from os import getenv
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ============================================================================
# CONFIGURATION - Update these values based on your Keycloak setup
# ============================================================================

# Keycloak server URL (from your keycloak.php config)

KEYCLOAK_SERVER = getenv("KEYCLOAK_SERVER")

# Realm name (extracted from issuer URL in keycloak.php)
REALM = "master"

# Admin credentials (loaded from environment variables for security)
ADMIN_USERNAME = getenv("KEYCLOAK_ADMIN_USERNAME")
ADMIN_PASSWORD = getenv("KEYCLOAK_ADMIN_PASSWORD")

# Alternative: Service Account Client Credentials
# If you have a service account client configured in Keycloak, you can use these instead
SERVICE_ACCOUNT_CLIENT_ID = getenv("KEYCLOAK_CLIENT_ID", "admin-cli")
SERVICE_ACCOUNT_CLIENT_SECRET = getenv("KEYCLOAK_CLIENT_SECRET")

# ============================================================================
# USER DATA - Define users to be created
# ============================================================================

# Example users to create - Customize this list with your actual user data
USERS_TO_CREATE = [
    {
        "username": "john.doe",
        "email": "john.doe@example.com",
        "firstName": "John",
        "lastName": "Doe",
        "enabled": True,
        "emailVerified": True,
        "password": "ChangeMe123!",  # This will be set as temporary password
        "temporary_password": True,  # User must change password on first login
        "groups": [],  # Optional: list of group names to add user to
        "role": None,  # Optional: realm role name to assign to user
        "attributes": {  # Optional: custom attributes
            "department": ["IT"],
            "employee_id": ["EMP001"]
        }
    },
    {
        "username": "jane.smith",
        "email": "jane.smith@example.com",
        "firstName": "Jane",
        "lastName": "Smith",
        "enabled": True,
        "emailVerified": False,
        "password": "SecurePass456!",
        "temporary_password": True,
        "groups": ["users", "managers"],
        "role": "manager",  # Optional: realm role name
        "attributes": {
            "department": ["HR"],
            "employee_id": ["EMP002"]
        }
    }
]


# ============================================================================
# CSV/JSON IMPORT FUNCTIONS
# ============================================================================

def load_users_from_csv(filename: str) -> List[Dict]:
    """
    Load users from a CSV file with support for complex fields

    CSV Format:
    - Basic fields: username, email, firstName, lastName, password, enabled,
                   emailVerified, temporary_password
    - groups: Pipe-separated list (e.g., "users|managers|admins")
    - role: Single role name (e.g., "admin")
    - attributes: JSON string (e.g., '{"department":["IT"],"id":["001"]}')

    Args:
        filename: Path to CSV file

    Returns:
        List of user dictionaries

    Example CSV row:
        john.doe,john@example.com,John,Doe,Pass123!,true,false,true,
        users|managers,"{""department"":[""IT""],""employee_id"":[""001""]}"
    """
    users = []

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row_num, row in enumerate(reader, start=2):
                try:
                    # Parse boolean fields
                    enabled = row.get('enabled', 'true').lower() == 'true'
                    email_verified = row.get(
                        'emailVerified', 'false'
                    ).lower() == 'true'
                    temp_password = row.get(
                        'temporary_password', 'true'
                    ).lower() == 'true'

                    # Parse groups (pipe-separated)
                    groups = []
                    if row.get('groups'):
                        groups = [
                            g.strip() for g in row['groups'].split('|')
                            if g.strip()
                        ]

                    # Parse role (single role name)
                    role = row.get('role', '').strip() or None

                    # Parse attributes (JSON string)
                    attributes = {}
                    if row.get('attributes'):
                        try:
                            attributes = json.loads(row['attributes'])
                        except json.JSONDecodeError as e:
                            print(
                                f"Warning: Invalid JSON in attributes "
                                f"for row {row_num}: {e}"
                            )

                    # Build user object
                    user = {
                        "username": row['username'],
                        "email": row.get('email', ''),
                        "firstName": row.get('firstName', ''),
                        "lastName": row.get('lastName', ''),
                        "enabled": enabled,
                        "emailVerified": email_verified,
                        "password": row.get('password', ''),
                        "temporary_password": temp_password,
                        "groups": groups,
                        "role": role,
                        "attributes": attributes
                    }

                    users.append(user)

                except KeyError as e:
                    print(
                        f"Error: Missing required field {e} in row {row_num}"
                    )
                    continue

        print(f"Loaded {len(users)} users from {filename}")
        return users

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return []
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return []


def load_users_from_json(filename: str) -> List[Dict]:
    """
    Load users from a JSON file

    JSON should be an array of user objects matching the USERS_TO_CREATE
    structure.

    Args:
        filename: Path to JSON file

    Returns:
        List of user dictionaries

    Example JSON:
        [
            {
                "username": "john.doe",
                "email": "john@example.com",
                "firstName": "John",
                "lastName": "Doe",
                "enabled": true,
                "emailVerified": false,
                "password": "ChangeMe123!",
                "temporary_password": true,
                "groups": ["users"],
                "role": "user",
                "attributes": {
                    "department": ["IT"],
                    "employee_id": ["EMP001"]
                }
            }
        ]
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            users = json.load(f)

        print(f"Loaded {len(users)} users from {filename}")
        return users

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return []
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {filename}: {e}")
        return []
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        return []


# ============================================================================
# KEYCLOAK API CLIENT CLASS
# ============================================================================


class KeycloakAdmin:
    """Client for interacting with Keycloak Admin REST API"""

    def __init__(self, server_url: str, realm: str):
        """
        Initialize Keycloak Admin client

        Args:
            server_url: Base URL of Keycloak server
            realm: Realm name to operate on
        """
        self.server_url = server_url.rstrip('/')
        self.realm = realm
        self.access_token = None
        self.session = requests.Session()

    def authenticate_with_password(self, username: str, password: str) -> bool:
        """
        Authenticate using admin username and password

        Args:
            username: Admin username
            password: Admin password

        Returns:
            True if authentication successful, False otherwise
        """
        token_url = f"{self.server_url}/realms/master/protocol/openid-connect/token"

        payload = {
            "client_id": "admin-cli",
            "username": username,
            "password": password,
            "grant_type": "password"
        }

        try:
            response = self.session.post(token_url, data=payload)
            response.raise_for_status()

            token_data = response.json()
            self.access_token = token_data.get("access_token")

            print(f"✓ Successfully authenticated as {username}")
            return True

        except requests.exceptions.RequestException as e:
            print(f"✗ Authentication failed: {e}")
            if hasattr(e.response, 'text'):
                print(f"  Error details: {e.response.text}")
            return False

    def authenticate_with_client_credentials(self, client_id: str, client_secret: str) -> bool:
        """
        Authenticate using service account client credentials

        Args:
            client_id: Service account client ID
            client_secret: Service account client secret

        Returns:
            True if authentication successful, False otherwise
        """
        token_url = f"{self.server_url}/realms/master/protocol/openid-connect/token"

        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }

        try:
            response = self.session.post(token_url, data=payload)
            response.raise_for_status()

            token_data = response.json()
            self.access_token = token_data.get("access_token")

            print(
                f"✓ Successfully authenticated with service account: {client_id}")
            return True

        except requests.exceptions.RequestException as e:
            print(f"✗ Authentication failed: {e}")
            if hasattr(e.response, 'text'):
                print(f"  Error details: {e.response.text}")
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers with authorization token"""
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    def create_user(self, user_data: Dict) -> Optional[str]:
        """
        Create a new user in Keycloak

        Args:
            user_data: Dictionary containing user information

        Returns:
            User ID if successful, None otherwise
        """
        url = f"{self.server_url}/admin/realms/{self.realm}/users"

        # Prepare user payload (exclude password and custom fields)
        payload = {
            "username": user_data["username"],
            "email": user_data.get("email"),
            "firstName": user_data.get("firstName"),
            "lastName": user_data.get("lastName"),
            "enabled": user_data.get("enabled", True),
            "emailVerified": user_data.get("emailVerified", False),
            "attributes": user_data.get("attributes", {})
        }

        try:
            # Create the user
            response = self.session.post(
                url, headers=self._get_headers(), json=payload)
            response.raise_for_status()

            # Extract user ID from Location header
            location = response.headers.get("Location")
            user_id = location.split("/")[-1] if location else None

            print(f"✓ Created user: {user_data['username']} (ID: {user_id})")
            return user_id

        except requests.exceptions.RequestException as e:
            print(f"✗ Failed to create user {user_data['username']}: {e}")
            if hasattr(e.response, 'text'):
                print(f"  Error details: {e.response.text}")
            return None

    def set_user_password(self, user_id: str, password: str, temporary: bool = True) -> bool:
        """
        Set password for a user

        Args:
            user_id: User ID
            password: Password to set
            temporary: If True, user must change password on first login

        Returns:
            True if successful, False otherwise
        """
        url = f"{self.server_url}/admin/realms/{self.realm}/users/{user_id}/reset-password"

        payload = {
            "type": "password",
            "value": password,
            "temporary": temporary
        }

        try:
            response = self.session.put(
                url, headers=self._get_headers(), json=payload)
            response.raise_for_status()

            temp_status = "temporary" if temporary else "permanent"
            print(f"  ✓ Set {temp_status} password for user ID: {user_id}")
            return True

        except requests.exceptions.RequestException as e:
            print(f"  ✗ Failed to set password for user ID {user_id}: {e}")
            if hasattr(e.response, 'text'):
                print(f"    Error details: {e.response.text}")
            return False

    def get_group_id(self, group_name: str) -> Optional[str]:
        """
        Get group ID by group name or path

        Supports both simple group names and hierarchical paths:
        - Simple: "users"
        - Path: "parent/child" or "parent/child/grandchild"
        - Alternative separator: "parent|child" (for backward compatibility)

        Args:
            group_name: Name of the group or path (e.g., "parent/child")

        Returns:
            Group ID if found, None otherwise
        """
        # Check if it's a path notation (supports both / and | separators)
        if '/' in group_name or '|' in group_name:
            separator = '/' if '/' in group_name else '|'
            path_parts = [p.strip()
                          for p in group_name.split(separator) if p.strip()]
            return self._get_group_id_by_path(path_parts)

        # Simple group name - search recursively
        return self._get_group_id_recursive(group_name)

    def _get_group_children(self, group_id: str) -> List[Dict]:
        """
        Get child groups using the /children endpoint

        Args:
            group_id: ID of the parent group

        Returns:
            List of child groups
        """
        url = f"{self.server_url}/admin/realms/{self.realm}/groups/{group_id}/children"
        try:
            response = self.session.get(url, headers=self._get_headers())
            response.raise_for_status()
            children = response.json()
            return children
        except requests.exceptions.RequestException as e:
            print(f"  ✗ Failed to fetch children for group {group_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"    Response: {e.response.text}")
            return []

    def _get_group_id_recursive(self, group_name: str, groups: Optional[List] = None) -> Optional[str]:
        """
        Recursively search for a group by name in the group hierarchy

        Args:
            group_name: Name of the group to find
            groups: List of groups to search (if None, fetches all groups)

        Returns:
            Group ID if found, None otherwise
        """
        if groups is None:
            url = f"{self.server_url}/admin/realms/{self.realm}/groups"
            try:
                response = self.session.get(url, headers=self._get_headers())
                response.raise_for_status()
                groups = response.json()
            except requests.exceptions.RequestException as e:
                print(f"  ✗ Failed to fetch groups: {e}")
                return None

        for group in groups:
            if group.get("name") == group_name:
                return group.get("id")

            # Get children using the /children endpoint
            group_id = group.get("id")
            if group_id:
                children = self._get_group_children(group_id)
                if children:
                    found_id = self._get_group_id_recursive(
                        group_name, children)
                    if found_id:
                        return found_id

        return None

    def _get_group_id_by_path(self, path_parts: List[str]) -> Optional[str]:
        """
        Get group ID by navigating the group hierarchy using a path

        Args:
            path_parts: List of group names representing the path (e.g., ["parent", "child"])

        Returns:
            Group ID if found, None otherwise
        """
        if not path_parts:
            return None

        url = f"{self.server_url}/admin/realms/{self.realm}/groups"

        try:
            response = self.session.get(url, headers=self._get_headers())
            response.raise_for_status()
            groups = response.json()

            # Navigate through the path
            current_groups = groups
            target_name = path_parts[-1]  # The last part is the target group

            # Navigate to parent groups first
            for i, part in enumerate(path_parts[:-1]):
                found = False
                for group in current_groups:
                    if group.get("name") == part:
                        group_id = group.get("id")
                        # Get children using the /children endpoint
                        children = self._get_group_children(group_id)
                        if children:
                            current_groups = children
                            found = True
                            break
                        else:
                            print(
                                f"  ! Group '{part}' found but has no children")
                            return None

                if not found:
                    print(f"  ! Group '{part}' not found in path")
                    return None

            # Now search for the target group in the current level
            for group in current_groups:
                if group.get("name") == target_name:
                    return group.get("id")

            print(
                f"  ! Group '{target_name}' not found at path '/{'/'.join(path_parts)}'")
            return None

        except requests.exceptions.RequestException as e:
            print(f"  ✗ Failed to search for group path: {e}")
            return None

    def add_user_to_group(self, user_id: str, group_id: str) -> bool:
        """
        Add user to a group

        Args:
            user_id: User ID
            group_id: Group ID

        Returns:
            True if successful, False otherwise
        """
        url = f"{self.server_url}/admin/realms/{self.realm}/users/{user_id}/groups/{group_id}"

        try:
            response = self.session.put(url, headers=self._get_headers())
            response.raise_for_status()

            print(f"  ✓ Added user to group (Group ID: {group_id})")
            return True

        except requests.exceptions.RequestException as e:
            print(f"  ✗ Failed to add user to group: {e}")
            return False

    def get_role_id(self, role_name: str) -> Optional[Dict]:
        """
        Get realm role by name

        Args:
            role_name: Name of the realm role

        Returns:
            Role dictionary with id and name if found, None otherwise
        """
        url = f"{self.server_url}/admin/realms/{self.realm}/roles/{role_name}"

        try:
            response = self.session.get(url, headers=self._get_headers())
            response.raise_for_status()
            role = response.json()
            return role

        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 404:
                    print(f"  ! Role '{role_name}' not found")
                else:
                    print(f"  ✗ Failed to fetch role '{role_name}': {e}")
            else:
                print(f"  ✗ Failed to fetch role '{role_name}': {e}")
            return None

    def add_user_role(self, user_id: str, role: Dict) -> bool:
        """
        Assign a realm role to a user

        Args:
            user_id: User ID
            role: Role dictionary (must contain 'id' and 'name')

        Returns:
            True if successful, False otherwise
        """
        url = f"{self.server_url}/admin/realms/{self.realm}/users/{user_id}/role-mappings/realm"

        payload = [role]

        try:
            response = self.session.post(
                url, headers=self._get_headers(), json=payload)
            response.raise_for_status()

            print(f"  ✓ Assigned role '{role.get('name')}' to user")
            return True

        except requests.exceptions.RequestException as e:
            print(
                f"  ✗ Failed to assign role '{role.get('name')}' to user: {e}")
            if hasattr(e.response, 'text'):
                print(f"    Error details: {e.response.text}")
            return False

# ============================================================================
# MAIN EXECUTION FUNCTIONS
# ============================================================================


def import_users(keycloak_admin: KeycloakAdmin, users: List[Dict]) -> Dict[str, int]:
    """
    Import multiple users into Keycloak

    Args:
        keycloak_admin: Authenticated KeycloakAdmin instance
        users: List of user data dictionaries

    Returns:
        Dictionary with import statistics (success, failed counts)
    """
    stats = {"success": 0, "failed": 0, "total": len(users)}

    print(f"\n{'='*60}")
    print(f"Starting import of {stats['total']} users...")
    print(f"{'='*60}\n")

    for user_data in users:
        print(f"Processing user: {user_data['username']}")

        # Create the user
        user_id = keycloak_admin.create_user(user_data)

        if user_id:
            # Set password if provided
            if user_data.get("password"):
                temporary = user_data.get("temporary_password", True)
                keycloak_admin.set_user_password(
                    user_id, user_data["password"], temporary)

            # Add user to groups if specified
            groups = user_data.get("groups", [])
            for group_name in groups:
                group_id = keycloak_admin.get_group_id(group_name)
                if group_id:
                    keycloak_admin.add_user_to_group(user_id, group_id)

            # Assign role if specified
            role_name = user_data.get("role")
            if role_name:
                role = keycloak_admin.get_role_id(role_name)
                if role:
                    keycloak_admin.add_user_role(user_id, role)

            stats["success"] += 1
        else:
            stats["failed"] += 1

        print()  # Blank line between users

    return stats


def main():
    """Main execution function"""
    import os

    print("="*60)
    print("Keycloak User Import Script")
    print("="*60)

    # Determine user source (CSV, JSON, or hardcoded list)
    users_to_import = []
    import_source = "hardcoded list"

    # Check for command-line argument
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if file_path.endswith('.csv'):
            users_to_import = load_users_from_csv(file_path)
            import_source = file_path
        elif file_path.endswith('.json'):
            users_to_import = load_users_from_json(file_path)
            import_source = file_path
        else:
            print(f"\n✗ ERROR: Unsupported file format: {file_path}")
            print("Supported formats: .csv, .json")
            sys.exit(1)
    # Check for users.csv in current directory
    elif os.path.exists('users.csv'):
        print("\nFound users.csv file, loading users from CSV...")
        users_to_import = load_users_from_csv('users.csv')
        import_source = "users.csv"
    # Check for users.json in current directory
    elif os.path.exists('users.json'):
        print("\nFound users.json file, loading users from JSON...")
        users_to_import = load_users_from_json('users.json')
        import_source = "users.json"
    # Use hardcoded list
    else:
        print("\nNo external file found, using USERS_TO_CREATE list...")
        users_to_import = USERS_TO_CREATE

    # Validate we have users to import
    if not users_to_import:
        print("\n✗ ERROR: No users to import!")
        print("Please either:")
        print("  1. Add users to the USERS_TO_CREATE list in the script")
        print("  2. Create a users.csv file")
        print("  3. Create a users.json file")
        print("  4. Provide a file path as argument: "
              "python create_keycloak_users.py users.csv")
        sys.exit(1)

    print(f"Import source: {import_source}")
    print(f"Users to import: {len(users_to_import)}")

    # Initialize Keycloak Admin client
    keycloak_admin = KeycloakAdmin(KEYCLOAK_SERVER, REALM)

    # Authenticate - Try password authentication first,
    # then client credentials
    authenticated = False

    if ADMIN_USERNAME and ADMIN_PASSWORD:
        print("\nAuthenticating with username/password...")
        authenticated = keycloak_admin.authenticate_with_password(
            ADMIN_USERNAME, ADMIN_PASSWORD
        )

    if not authenticated and SERVICE_ACCOUNT_CLIENT_SECRET:
        print("\nAuthenticating with service account...")
        authenticated = keycloak_admin.authenticate_with_client_credentials(
            SERVICE_ACCOUNT_CLIENT_ID,
            SERVICE_ACCOUNT_CLIENT_SECRET
        )

    if not authenticated:
        print("\n✗ ERROR: Authentication failed!")
        print("\nPlease ensure you have set one of the following "
              "in your .env file:")
        print("  1. KEYCLOAK_ADMIN_USERNAME and KEYCLOAK_ADMIN_PASSWORD")
        print("  2. KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET "
              "(for service account)")
        sys.exit(1)

    # Import users
    stats = import_users(keycloak_admin, users_to_import)

    # Print summary
    print("="*60)
    print("Import Summary")
    print("="*60)
    print(f"Total users processed: {stats['total']}")
    print(f"Successfully created:  {stats['success']}")
    print(f"Failed:               {stats['failed']}")
    print("="*60)

    if stats['failed'] > 0:
        sys.exit(1)


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
