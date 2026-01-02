#!/usr/bin/env python3
"""
CodeIgniter 3 Endpoint Permissions Generator

This script parses CI3 controllers and routes to generate an endpoint
permissions JSON file for Keycloak integration.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple


class CI3EndpointParser:
    def __init__(self, app_path: str):
        """
        Initialize the parser with the CI3 application path.

        Args:
            app_path: Path to the CI3 application root directory
        """
        self.app_path = Path(app_path)
        self.controllers_path = self.app_path / 'controllers'
        self.routes_path = self.app_path / 'config' / 'routes.php'
        self.routes = {}
        self.endpoints = {}

    def parse_controller_file(self, file_path: Path) -> Tuple[str, List[str]]:
        """
        Parse a single controller file to extract class name and public methods.

        Args:
            file_path: Path to the controller PHP file

        Returns:
            Tuple of (controller_name, list_of_methods)
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return None, []

        # Extract class name
        class_match = re.search(r'class\s+(\w+)\s+extends\s+', content)
        if not class_match:
            return None, []

        controller_name = class_match.group(1)

        # Extract public methods (excluding constructors and private/protected)
        methods = []
        method_pattern = r'public\s+function\s+(\w+)\s*\('

        for match in re.finditer(method_pattern, content):
            method_name = match.group(1)
            # Skip constructors and methods starting with underscore
            if method_name not in ['__construct', 'index'] and not method_name.startswith('_'):
                methods.append(method_name)
            elif method_name == 'index':
                methods.append(method_name)

        return controller_name, methods

    def scan_controllers(self, directory: Path = None, prefix: str = '') -> None:
        """
        Recursively scan controllers directory for PHP files.

        Args:
            directory: Directory to scan (defaults to controllers_path)
            prefix: Prefix for nested controllers (e.g., 'admin/')
        """
        if directory is None:
            directory = self.controllers_path

        if not directory.exists():
            print(f"Controllers directory not found: {directory}")
            return

        for item in sorted(directory.iterdir()):
            if item.is_file() and item.suffix == '.php':
                controller_name, methods = self.parse_controller_file(item)

                if controller_name:
                    # Determine the URL prefix (subfolder path)
                    url_prefix = prefix.lower()
                    controller_lower = controller_name.lower()

                    for method in methods:
                        # Create endpoint path
                        if method == 'index':
                            # index method can be accessed without method name
                            endpoint = f"{url_prefix}{controller_lower}"
                            if endpoint:
                                self.add_endpoint(
                                    endpoint, controller_name, method)

                        # All methods including index can be accessed with method name
                        endpoint = f"{url_prefix}{controller_lower}/{method.lower()}"
                        self.add_endpoint(endpoint, controller_name, method)

            elif item.is_dir() and not item.name.startswith('.'):
                # Recursively scan subdirectories
                new_prefix = f"{prefix}{item.name.lower()}/"
                self.scan_controllers(item, new_prefix)

    def parse_routes(self) -> None:
        """
        Parse the routes.php file to extract custom route mappings.
        """
        if not self.routes_path.exists():
            print(f"Routes file not found: {self.routes_path}")
            return

        try:
            with open(self.routes_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading routes file: {e}")
            return

        # Match route definitions: $route['pattern'] = 'controller/method';
        route_pattern = r'\$route\[([\'"])(.+?)\1\]\s*=\s*([\'"])(.+?)\3'

        for match in re.finditer(route_pattern, content):
            route_key = match.group(2)
            route_value = match.group(4)

            # Skip default_controller and 404_override
            if route_key in ['default_controller', '404_override', 'translate_uri_dashes']:
                continue

            self.routes[route_key] = route_value

    def add_endpoint(self, endpoint: str, controller: str, method: str) -> None:
        """
        Add an endpoint to the endpoints dictionary.

        Args:
            endpoint: The URL endpoint path
            controller: The controller class name
            method: The method name
        """
        self.endpoints[endpoint] = {
            "controller": controller,
            "method": method,
            # Empty modules array - to be filled manually
            "modules": [{'name': 'module_name', 'permissions': ['C', 'R', 'U', 'D']}]
        }

    def apply_custom_routes(self) -> None:
        """
        Apply custom routes from routes.php to the endpoints dictionary.
        """
        for route_pattern, route_target in self.routes.items():
            # Simple routes without regex
            if '(' not in route_pattern:
                # Parse the target controller/method
                target_parts = route_target.split('/')
                if len(target_parts) >= 1:
                    controller = target_parts[0]
                    method = target_parts[1] if len(
                        target_parts) > 1 else 'index'

                    # Add this custom route
                    self.add_endpoint(route_pattern, controller, method)

    def generate_permissions_json(self, output_path: str) -> None:
        """
        Generate the endpoint permissions JSON file.
        If the file exists, merge with existing data (preserving existing configurations).

        Args:
            output_path: Path where the JSON file should be saved
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing JSON if it exists
        existing_endpoints = {}
        if output_file.exists():
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    existing_endpoints = json.load(f)
                print(
                    f"   Loaded {len(existing_endpoints)} existing endpoints")
            except Exception as e:
                print(f"   Warning: Could not load existing file: {e}")
                existing_endpoints = {}

        # Count new endpoints
        new_count = 0
        for endpoint, data in self.endpoints.items():
            if endpoint not in existing_endpoints:
                existing_endpoints[endpoint] = data
                new_count += 1

        # Sort endpoints alphabetically
        sorted_endpoints = dict(sorted(existing_endpoints.items()))

        # Write merged data
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sorted_endpoints, f, indent=2, ensure_ascii=False)

        print(f"✓ Generated endpoint permissions file: {output_file}")
        print(f"✓ Total endpoints: {len(sorted_endpoints)}")
        print(f"✓ New endpoints added: {new_count}")
        print(
            f"✓ Existing endpoints preserved: {len(sorted_endpoints) - new_count}")

    def run(self, output_path: str) -> None:
        """
        Run the full parsing and generation process.

        Args:
            output_path: Path where the JSON file should be saved
        """
        print("Starting CI3 Endpoint Permissions Generator...")
        print(f"Application path: {self.app_path}")
        print(f"Controllers path: {self.controllers_path}")

        # Parse routes first
        print("\n1. Parsing routes.php...")
        self.parse_routes()
        print(f"   Found {len(self.routes)} custom routes")

        # Scan controllers
        print("\n2. Scanning controllers...")
        self.scan_controllers()
        print(f"   Found {len(self.endpoints)} endpoints")

        # Apply custom routes
        print("\n3. Applying custom routes...")
        self.apply_custom_routes()
        print(f"   Total endpoints after routes: {len(self.endpoints)}")

        # Generate JSON
        print("\n4. Generating JSON file...")
        self.generate_permissions_json(output_path)

        print("\n✓ Done! Please review and update the permissions as needed.")


def main():
    """Main entry point for the script."""
    # Path to your CI3 application
    ci3_app_path = "/Users/discovery-air/Documents/simadiskc/application"

    # Output path for the JSON file
    client_id = "client_simadis"
    filename = "endpoint_permissions.json"
    output_json = f"/Users/discovery-air/Documents/simadiskc/application/third_party/keycloak-simss-connector/config/access_control/{client_id}/{filename}"

    # Create parser and run
    parser = CI3EndpointParser(ci3_app_path)
    parser.run(output_json)


if __name__ == "__main__":
    main()
