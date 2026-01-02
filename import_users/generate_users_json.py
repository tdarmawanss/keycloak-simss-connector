#!/usr/bin/env python3
"""
Generate users.json from CSV file containing role-based user counts per station.
"""

import csv
import json
import random


# Station mapping: CSV name -> (Station Name, Initial, Cabang)
STATION_MAPPING = {
    "pusat": ("Pusat", "GDG", "PUSAT"),
    "Medan": ("Medan", "MDN", "MEDAN"),
    "Pematang Siantar": ("P.Siantar", "PSR", "MEDAN"),
    "Banda Aceh": ("B.Aceh", "BAC", "MEDAN"),  # Added from CSV
    "Pekanbaru": ("Pekanbaru", "PKB", "MEDAN"),
    "Padang": ("Padang", "PDG", "MEDAN"),
    "Palembang": ("Palembang", "PLG", "PALEMBANG"),
    "Jambi": ("Jambi", "JMB", "PALEMBANG"),
    "Bandar Lampung": ("B.Lampung", "BDL", "PALEMBANG"),
    "Jakarta": ("Jak.Sel & Tim", "JKT", "JAKARTA"),
    "Bogor": ("Bogor", "BGR", "JAKARTA"),  # Not in controller, placeholder
    "Bandung": ("Bandung", "BDG", "BANDUNG"),
    "Cirebon": ("Cirebon", "CRB", "BANDUNG"),  # Not in controller, placeholder
    "Semarang": ("Semarang", "SMG", "SEMARANG"),
    "Yogya": ("Yogyakarta", "YGY", "YOGYAKARTA"),
    "Surabaya": ("Surabaya", "SBY", "SURABAYA"),
    "Malang": ("Malang", "MLG", "SURABAYA"),  # Not in controller, placeholder
    "Balikpapan": ("Balikpapan", "BLP", "BALIKPAPAN"),
    "Banjarmasin": ("Banjarmasin", "BJM", "BALIKPAPAN"),
    "Denpasar": ("Denpasar", "DPS", "DENPASAR"),
    "Mataram": ("Mataram", "MTR", "DENPASAR"),
    "Kupang": ("Kupang", "KPG", "KUPANG"),
    "Makassar": ("Makasar", "MKS", "MAKASAR"),
    "Palu": ("Palu", "PLU", "MAKASAR"),
    "Kendari": ("Kendari", "KDR", "MAKASAR"),
    "Manado": ("Manado", "MND", "MAKASAR"),
    "Sorong": ("Sorong", "SRG", "SORONG"),
    "Ambon": ("Ambon", "AMB", "SORONG"),
    "Jayapura": ("Jayapura", "JPR", "SORONG")
}


def generate_password():
    """Generate a simple random password."""
    return f"Pass{random.randint(1000, 9999)}!"


def parse_applications(apps_string):
    """Parse comma-separated applications and return list with APP_ prefix."""
    if not apps_string or apps_string.strip() == "":
        return []

    apps = [app.strip() for app in apps_string.split(",")]
    return [f"APP_{app}" for app in apps if app]


def create_user(username, password, groups, role_code=None):
    """Create a user object with the required fields."""
    user = {
        "username": username,
        "firstName": "",
        "lastName": "",
        "enabled": True,
        "emailVerified": False,
        "password": password,
        "temporary_password": True,
        "groups": groups
    }
    # Add role field only if role_code is provided
    if role_code:
        user["role"] = role_code
    return user


def generate_groups(division, subdivision, station_name, station_initial, cabang, applications):
    """Generate the list of groups for a user."""
    groups = []

    # Add cabang and station groups
    cabang_group = f"CABANG_{cabang.upper()}"
    groups.append(cabang_group)

    # Add station subgroup
    station_subgroup = f"{cabang_group}|STO_{station_name.upper().replace('.', '').replace(' ', '_').replace('&', 'AND')}"
    groups.append(station_subgroup)

    # Add division group
    if division and division.strip() and division.upper() != "NA":
        division_group = f"DIVISI_{division.upper()}"
        groups.append(division_group)

        # Add subdivision if not "NA"
        if subdivision and subdivision.strip().upper() != "NA":
            subdivision_group = f"{division_group}|{subdivision.upper().replace(',', '').replace(' ', '_')}"
            groups.append(subdivision_group)

    # Add application groups
    groups.extend(applications)

    return groups


def main():
    csv_file = "Access control SIMSS dec 25 - Roles.csv"
    output_file = "users.json"

    users = []

    print(f"Reading CSV file: {csv_file}")

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            role_code = row['Role Code']
            division = row['Division']
            subdivision = row['Subdivision']

            # Skip empty rows (like summary rows at the end)
            if not role_code or role_code.strip() == '':
                continue

            print(f"\nProcessing role: {role_code}")

            # Process each station column
            for csv_station, (station_name, station_initial, cabang) in STATION_MAPPING.items():
                user_count_str = row.get(csv_station, '').strip()

                # Skip if empty or not a number
                if not user_count_str or user_count_str == '':
                    continue

                try:
                    user_count = int(user_count_str)
                except ValueError:
                    continue

                if user_count <= 0:
                    continue

                # Generate groups for this station (no applications in this CSV)
                groups = generate_groups(
                    division,
                    subdivision,
                    station_name,
                    station_initial,
                    cabang,
                    []  # No applications column in CSV
                )

                # Create users for this station
                for i in range(user_count):
                    # Generate username
                    if user_count == 1:
                        username = f"{role_code}_{station_initial.lower()}"
                    else:
                        username = f"{role_code}_{station_initial.lower()}_{i+1}"

                    # Generate password
                    password = generate_password()

                    # Create user object with role
                    user = create_user(username, password, groups, role_code)
                    users.append(user)

                    print(
                        f"  Created: {username} at {station_name} ({cabang})")

    # Write to JSON file
    print(f"\nWriting {len(users)} users to {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

    print(f"\n✓ Successfully generated {output_file} with {len(users)} users!")

    # Print summary
    print("\n" + "="*60)
    print("Summary:")
    print("="*60)
    print(f"Total users created: {len(users)}")
    print(f"\nSample users:")
    for user in users[:5]:
        print(f"  - {user['username']} (password: {user['password']})")
        print(f"    Groups: {len(user['groups'])} groups")
    if len(users) > 5:
        print(f"  ... and {len(users) - 5} more users")


if __name__ == "__main__":
    main()
