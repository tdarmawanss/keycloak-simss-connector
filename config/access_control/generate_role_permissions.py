#!/usr/bin/env python3
"""
CSV to Role Permissions JSON Converter

Converts access control CSV (with modules as headers and CRUD as subheaders)
to role_permissions.json format for Keycloak SIMSS Connector

Usage: python generate_role_permissions.py [input.csv] [output.json]
"""

import csv
import json
import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple


class CsvToRolePermissionsConverter:
    """Converts CSV access control matrix to JSON role permissions."""

    def __init__(self, csv_path: str, output_path: str = None):
        """
        Initialize the converter.

        Args:
            csv_path: Path to the input CSV file
            output_path: Path to the output JSON file (optional)
        """
        self.csv_path = Path(csv_path)
        self.output_path = Path(
            output_path) if output_path else self.csv_path.parent / 'role_permissions.json'
        self.modules = []
        self.roles = {}

    def convert(self) -> Dict:
        """
        Parse the CSV and convert to JSON structure.

        Returns:
            Dictionary containing the role permissions data

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid
        """
        if not self.csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")

        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = list(reader)

        if len(rows) < 3:
            raise ValueError(
                "CSV must have at least 3 rows (module headers, CRUD headers, and data)")

        # Parse headers
        module_positions = self.parse_module_headers(rows[0])
        self.validate_crud_headers(rows[1])

        # Parse role data rows
        for row in rows[2:]:
            self.parse_role_row(row, module_positions)

        return self.generate_json()

    def parse_module_headers(self, row: List[str]) -> Dict[int, Dict[str, any]]:
        """
        Parse the first row to extract module names and their column positions.

        Handles CSV format where:
        - Module names are in consecutive columns (1, 2, 3, 4, ...)
        - Each module maps to 4 CRUD columns in the data rows
        - Row 2 contains C, R, U, D pattern repeated for each module

        Args:
            row: First row from CSV

        Returns:
            Dictionary mapping column indices to module and CRUD info
        """
        module_positions = {}

        # Collect all non-empty module names from row 1
        module_list = []
        for i in range(1, len(row)):
            cell = row[i].strip()
            if cell:
                module_list.append(self.normalize_module_name(cell))

        self.modules = module_list

        # Map each module to its 4 CRUD columns
        # Module 0 -> columns 1-4, Module 1 -> columns 5-8, etc.
        for module_index, module_name in enumerate(module_list):
            start_col = (module_index * 4) + 1  # 1-based column index

            for crud_index in range(4):
                col_index = start_col + crud_index
                module_positions[col_index] = {
                    'module': module_name,
                    'crud_index': crud_index
                }

        return module_positions

    def validate_crud_headers(self, row: List[str]) -> None:
        """
        Validate that the second row contains C, R, U, D pattern.

        Args:
            row: Second row from CSV
        """
        crud_pattern = ['C', 'R', 'U', 'D']
        pattern_index = 0

        for i in range(1, len(row)):
            cell = row[i].strip().upper()

            if cell:
                expected = crud_pattern[pattern_index % 4]
                if cell != expected:
                    print(
                        f"Warning: Expected '{expected}' at column {i}, found '{cell}'")
                pattern_index += 1

    def parse_role_row(self, row: List[str], module_positions: Dict[int, Dict[str, any]]) -> None:
        """
        Parse a role row and extract permissions.

        Args:
            row: Data row containing role name and permissions
            module_positions: Mapping of column indices to modules
        """
        if not row or len(row) == 0:
            return

        role_name = row[0].strip()
        if not role_name:
            return

        role_key = self.normalize_role_key(role_name)
        module_permissions = {}
        crud_ops = ['C', 'R', 'U', 'D']

        for col_index, mapping in module_positions.items():
            module = mapping['module']
            crud_index = mapping['crud_index']

            if col_index >= len(row):
                continue

            value = row[col_index].strip().lower()
            has_permission = value in ['y', 'yes', '1', 'x']

            if has_permission:
                if module not in module_permissions:
                    module_permissions[module] = []
                module_permissions[module].append(crud_ops[crud_index])

        # Only add role if it has any permissions
        if module_permissions:
            self.roles[role_key] = {
                'display_name': role_name,
                'modules': module_permissions
            }

    def normalize_module_name(self, name: str) -> str:
        """
        Normalize module name to snake_case for consistent JSON keys.

        Example: "Data Produk" -> "data_produk"

        Args:
            name: Raw module name from CSV

        Returns:
            Normalized module name in snake_case
        """
        # Remove emoji and special characters
        name = re.sub(r'[^\w\s-]', '', name, flags=re.UNICODE)
        # Convert to lowercase and replace spaces with underscores
        name = name.strip().lower()
        name = re.sub(r'\s+', '_', name)
        # Remove any remaining non-alphanumeric characters except underscores
        name = re.sub(r'[^a-z0-9_]', '', name)
        return name

    def normalize_role_key(self, name: str) -> str:
        """
        Convert role display name to a key-friendly format.

        Args:
            name: Raw role name from CSV

        Returns:
            Normalized role key (lowercase with underscores)
        """
        # Convert to lowercase, replace spaces with underscores
        key = name.strip().lower()
        key = re.sub(r'\s+', '_', key)
        key = re.sub(r'[^a-z0-9_]', '', key)
        return key

    def generate_json(self) -> Dict:
        """
        Generate the final JSON structure.

        Returns:
            Dictionary containing metadata and role permissions
        """
        output = {
            '_meta': {
                'description': 'Maps user roles to module privileges (CRUD). Used with endpoint_permissions.json to determine access.',
                'generated_from': self.csv_path.name,
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            },
            'roles': {}
        }

        for role_key, role_data in self.roles.items():
            output['roles'][role_key] = {
                'display_name': role_data['display_name'],
                'modules': role_data['modules']
            }

        return output

    def save_json(self, data: Dict) -> Path:
        """
        Save the JSON to file.

        Args:
            data: Dictionary to save as JSON

        Returns:
            Path to the saved file

        Raises:
            IOError: If unable to write file
        """
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return self.output_path

    def get_output_path(self) -> Path:
        """Get the output file path."""
        return self.output_path


def main():
    """Main entry point for CLI execution."""
    script_name = Path(__file__).name

    if len(sys.argv) < 2:
        print(f"Usage: python {script_name} <input.csv> [output.json]")
        print("\nExample:")
        print(
            f"  python {script_name} access_control_simadis.csv role_permissions.json")
        sys.exit(1)

    csv_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        converter = CsvToRolePermissionsConverter(csv_path, output_path)
        data = converter.convert()
        saved_path = converter.save_json(data)

        print("✓ Successfully converted CSV to JSON")
        print(f"   Input:  {csv_path}")
        print(f"   Output: {saved_path}")
        print(f"\nGenerated {len(data['roles'])} roles:")

        for key, role in data['roles'].items():
            module_count = len(role['modules'])
            print(
                f"   - {key} ({role['display_name']}): {module_count} modules")

    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"✗ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
