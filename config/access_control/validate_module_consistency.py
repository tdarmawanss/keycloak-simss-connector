#!/usr/bin/env python3
"""
Access Control Module Consistency Validator

Validates that module names are consistent between:
- endpoint_permissions.json (modules required by endpoints)
- role_permissions.json (modules available to roles)

Usage:
    python validate_module_consistency.py [client_directory]
    python validate_module_consistency.py client_acme
    python validate_module_consistency.py  # Uses current directory
"""

import json
import sys
from pathlib import Path
from typing import Set, Tuple, Dict


class ModuleConsistencyValidator:
    """Validates module name consistency across access control JSON files."""

    def __init__(self, base_path: Path):
        """
        Initialize the validator.

        Args:
            base_path: Path to the directory containing the JSON files
        """
        self.base_path = Path(base_path)
        self.endpoint_file = self.base_path / 'endpoint_permissions.json'
        self.role_file = self.base_path / 'role_permissions.json'

    def extract_endpoint_modules(self) -> Set[str]:
        """
        Extract all module names from endpoint_permissions.json.

        Returns:
            Set of module names used in endpoint permissions
        """
        if not self.endpoint_file.exists():
            print(f"⚠️  Warning: {self.endpoint_file} not found")
            return set()

        try:
            with open(self.endpoint_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            modules = set()
            for endpoint_key, endpoint_data in data.items():
                if isinstance(endpoint_data, dict) and 'modules' in endpoint_data:
                    for module in endpoint_data['modules']:
                        if isinstance(module, dict) and 'name' in module:
                            modules.add(module['name'])

            return modules

        except json.JSONDecodeError as e:
            print(f"✗ Error parsing {self.endpoint_file}: {e}")
            return set()
        except Exception as e:
            print(f"✗ Error reading {self.endpoint_file}: {e}")
            return set()

    def extract_role_modules(self) -> Set[str]:
        """
        Extract all module names from role_permissions.json.

        Returns:
            Set of module names defined in role permissions
        """
        if not self.role_file.exists():
            print(f"⚠️  Warning: {self.role_file} not found")
            return set()

        try:
            with open(self.role_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            modules = set()
            roles = data.get('roles', {})

            for role_key, role_data in roles.items():
                if isinstance(role_data, dict) and 'modules' in role_data:
                    role_modules = role_data['modules']
                    if isinstance(role_modules, dict):
                        modules.update(role_modules.keys())

            return modules

        except json.JSONDecodeError as e:
            print(f"✗ Error parsing {self.role_file}: {e}")
            return set()
        except Exception as e:
            print(f"✗ Error reading {self.role_file}: {e}")
            return set()

    def get_module_usage_stats(self) -> Dict[str, Dict]:
        """
        Get detailed usage statistics for each module in endpoints.

        Returns:
            Dictionary mapping module names to usage statistics
        """
        if not self.endpoint_file.exists():
            return {}

        try:
            with open(self.endpoint_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            stats = {}
            for endpoint_key, endpoint_data in data.items():
                if isinstance(endpoint_data, dict) and 'modules' in endpoint_data:
                    for module in endpoint_data['modules']:
                        if isinstance(module, dict) and 'name' in module:
                            module_name = module['name']
                            if module_name not in stats:
                                stats[module_name] = {
                                    'endpoints': [],
                                    'permissions': set()
                                }
                            stats[module_name]['endpoints'].append(endpoint_key)
                            if 'permissions' in module:
                                stats[module_name]['permissions'].update(module['permissions'])

            # Convert sets to sorted lists for display
            for module_name in stats:
                stats[module_name]['permissions'] = sorted(stats[module_name]['permissions'])
                stats[module_name]['count'] = len(stats[module_name]['endpoints'])

            return stats

        except Exception as e:
            print(f"✗ Error getting module stats: {e}")
            return {}

    def validate(self) -> bool:
        """
        Validate module consistency and print detailed report.

        Returns:
            True if modules are consistent, False otherwise
        """
        print("=" * 70)
        print("Access Control Module Consistency Validation")
        print("=" * 70)
        print()

        # Extract modules
        print("📁 Extracting modules from JSON files...")
        endpoint_modules = self.extract_endpoint_modules()
        role_modules = self.extract_role_modules()

        print(f"   Endpoint permissions: {self.endpoint_file.name}")
        print(f"   Role permissions: {self.role_file.name}")
        print()

        # Check if files exist and have data
        if not endpoint_modules and not role_modules:
            print("✗ No modules found in either file. Check file paths and formats.")
            return False

        # Summary statistics
        print("📊 Summary:")
        print(f"   Modules in endpoint_permissions.json: {len(endpoint_modules)}")
        print(f"   Modules in role_permissions.json: {len(role_modules)}")
        print()

        # Find differences
        only_in_endpoints = endpoint_modules - role_modules
        only_in_roles = role_modules - endpoint_modules
        common_modules = endpoint_modules & role_modules

        # Determine if consistent
        is_consistent = len(only_in_endpoints) == 0 and len(only_in_roles) == 0

        # Print results
        if is_consistent:
            print("✓ SUCCESS: All modules are consistent!")
            print()
            print(f"📌 {len(common_modules)} modules found in both files:")
            for module in sorted(common_modules):
                print(f"   ✓ {module}")
            print()
        else:
            print("✗ INCONSISTENCY DETECTED!")
            print()

            if only_in_endpoints:
                print(f"⚠️  Modules in endpoint_permissions.json but NOT in role_permissions.json ({len(only_in_endpoints)}):")
                stats = self.get_module_usage_stats()
                for module in sorted(only_in_endpoints):
                    if module in stats:
                        count = stats[module]['count']
                        perms = ','.join(stats[module]['permissions'])
                        print(f"   ✗ {module}")
                        print(f"      Used in {count} endpoint(s), requires permissions: [{perms}]")
                    else:
                        print(f"   ✗ {module}")
                print()
                print("   → Action: Add these modules to role_permissions.json")
                print()

            if only_in_roles:
                print(f"⚠️  Modules in role_permissions.json but NOT in endpoint_permissions.json ({len(only_in_roles)}):")
                for module in sorted(only_in_roles):
                    print(f"   ✗ {module}")
                print()
                print("   → Action: Either:")
                print("      1. Remove these unused modules from role_permissions.json, OR")
                print("      2. Add endpoints that use these modules")
                print()

            if common_modules:
                print(f"✓ Modules present in both files ({len(common_modules)}):")
                for module in sorted(common_modules):
                    print(f"   ✓ {module}")
                print()

        # Additional recommendations
        if not is_consistent:
            print("💡 Recommendations:")
            print()
            if only_in_endpoints:
                print("   1. Update role_permissions.json (CSV) with missing modules:")
                print("      - Edit your CSV file to add columns for missing modules")
                print("      - Run: python generate_role_permissions.py <csv_file>")
                print()
            if only_in_roles:
                print("   2. Review unused modules in role_permissions.json:")
                print("      - Verify these modules are not needed")
                print("      - Remove from CSV if truly unused")
                print()

        print("=" * 70)
        return is_consistent


def main():
    """Main entry point for CLI execution."""
    script_name = Path(__file__).name

    # Determine which directory to check
    if len(sys.argv) > 1:
        client_dir = sys.argv[1]
    else:
        # Use current directory
        client_dir = '.'

    client_path = Path(client_dir)

    if not client_path.exists():
        print(f"✗ Error: Directory not found: {client_path}")
        print()
        print(f"Usage: python {script_name} [client_directory]")
        print()
        print("Examples:")
        print(f"  python {script_name} client_acme")
        print(f"  python {script_name} .")
        sys.exit(1)

    # Check if directory contains the required JSON files
    endpoint_file = client_path / 'endpoint_permissions.json'
    role_file = client_path / 'role_permissions.json'

    if not endpoint_file.exists() and not role_file.exists():
        print(f"✗ Error: No access control JSON files found in {client_path}")
        print()
        print("Expected files:")
        print(f"  - {endpoint_file}")
        print(f"  - {role_file}")
        sys.exit(1)

    # Run validation
    validator = ModuleConsistencyValidator(client_path)
    is_consistent = validator.validate()

    # Exit with appropriate code
    sys.exit(0 if is_consistent else 1)


if __name__ == "__main__":
    main()
