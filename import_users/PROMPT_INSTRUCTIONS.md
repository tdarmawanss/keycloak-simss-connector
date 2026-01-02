# Instructions for Generating users.json from User Access Control CSV

## Objective
Create a `users.json` file based on `users.json.example` format, using a CSV file that contains user role information and the number of users to create per station location.

## CSV Structure

### Information Columns (First 3 columns):
2. **Role Code** - Short code for username generation (e.g., "branch_mgr", "sales")
3. **Division** - Corporate division (e.g., "FNA", "SNM", "Manajemen")
4. **Subdivision** - A comma separated list of Sub-division within division (e.g., "Finance, Accounting", "Marketing", "NA")

### Station Columns (Remaining columns):
- Each column represents a station location (using full station names like "Medan", "Jakarta", "Denpasar")
- The cell value is a number indicating how many users of that role to create at that station
- Empty or 0 = no users to create

## Station-Cabang Relationship

Station names in CSV map to Keycloak groups as follows:

### Station Mapping (CSV Name → Station Name, Initial, Cabang):
- pusat → no station
- Medan → Medan (MDN) under MEDAN
- Pematang Siantar → P.Siantar (PSR) under MEDAN
- Pekanbaru → Pekanbaru (PKB) under MEDAN
- Padang → Padang (PDG) under MEDAN
- Palembang → Palembang (PLG) under PALEMBANG
- Jambi → Jambi (JMB) under PALEMBANG
- Bandar Lampung → B.Lampung (BDL) under PALEMBANG
- Jakarta → Jakarta (JKT) under JAKARTA
- **Bogor → Bogor (BGR) under JAKARTA** *(not in controller, use placeholder)*
- Bandung → Bandung (BDG) under BANDUNG
- **Cirebon → Cirebon (CRB) under BANDUNG** *(not in controller, use placeholder)*
- Semarang → Semarang (SMG) under SEMARANG
- Yogya → Yogyakarta (YGY) under YOGYAKARTA
- Surabaya → Surabaya (SBY) under SURABAYA
- **Malang → Malang (MLG) under SURABAYA** *(not in controller, use placeholder)*
- Balikpapan → Balikpapan (BLP) under BALIKPAPAN
- Banjarmasin → Banjarmasin (BJM) under BALIKPAPAN
- Denpasar → Denpasar (DPS) under DENPASAR
- Mataram → Mataram (MTR) under DENPASAR
- Kupang → Kupang (KPG) under KUPANG
- Makassar → Makasar (MKS) under MAKASAR *(note spelling difference)*
- Palu → Palu (PLU) under MAKASAR
- Kendari → Kendari (KDR) under MAKASAR
- Manado → Manado (MND) under MAKASAR
- Sorong → Sorong (SRG) under SORONG
- Ambon → Ambon (AMB) under SORONG
- Jayapura → Jayapura (JPR) under SORONG

## User JSON Structure

Each user should have:

```json
{
  "username": "branch_mgr_dps",
  "firstName": "",
  "lastName": "",
  "enabled": true,
  "emailVerified": false,
  "password": "Pass1234!",
  "temporary_password": true,
  "groups": [
    "CABANG_DENPASAR",
    "CABANG_DENPASAR|STO_DENPASAR",
    "DIVISI_MANAJEMEN"
  ],
  "role": "branch_manager"
}
```

### Field Requirements:

1. **username** (string, required):
   - Format: `{role_code}_{station_initial_lowercase}`
   - If multiple users of same role at same station: `{role_code}_{station_initial_lowercase}_{number}`
   - Examples: `branch_mgr_dps`, `sales_sby_1`, `sales_sby_2`, `technician_mdn_3`

2. **firstName** (string): Always empty string `""`

3. **lastName** (string): Always empty string `""`

4. **email**: **OMIT THIS FIELD** (do not include in JSON)

5. **enabled** (boolean): Always `true`

6. **emailVerified** (boolean): Always `false`

7. **password** (string): Random easy password in format `Pass####!` where #### is a random 4-digit number
   - Examples: `Pass1234!`, `Pass5678!`, `Pass9012!`

8. **temporary_password** (boolean): Always `true`

9. **groups** (array of strings): See Groups section below

10. **role** (string, optional): Keycloak realm role name to assign to the user
    - If provided, the user will be assigned to a Keycloak realm role with the same name
    - The role must exist in Keycloak before import (script will log a warning if role not found)
    - Examples: `"branch_manager"`, `"sales_rep"`, `"admin"`
    - If not provided, omit the field entirely (do not include empty string or null)

## Groups Assignment

Each user should be assigned to the following groups:

### 1. Cabang Group
- Format: `CABANG_{CABANG_NAME_UPPERCASE}`
- Example: `CABANG_DENPASAR`, `CABANG_MEDAN`, `CABANG_JAKARTA`

### 2. Station Subgroup
- Format: `CABANG_{CABANG_NAME}|STO_{STATION_NAME_UPPERCASE}`
- Station name must be sanitized: remove dots, replace spaces with underscores, replace & with AND
- Examples:
  - `CABANG_DENPASAR|STO_DENPASAR`
  - `CABANG_DENPASAR|STO_MATARAM`
  - `CABANG_JAKARTA|STO_JAKARTA`
  - `CABANG_MEDAN|STO_PSIANTAR`

### 3. Division Group
- Format: `DIVISI_{DIVISION_NAME_UPPERCASE}`
- Examples: `DIVISI_FNA`, `DIVISI_SNM`, `DIVISI_MANAJEMEN`
- Only add if Division is not empty and not "NA"

### 4. Subdivision Group (CONDITIONAL)
- Format: `DIVISI_{DIVISION_NAME}|{SUBDIVISION_NAME_UPPERCASE}`
- **IMPORTANT:** Only add if Subdivision is NOT "NA" (skip if "NA")
- Separately add subidivisions when given a comma separated list. 
- For Finance, Accounting, add both Finance and Accounting as subidivisions.
- Examples:
  - `DIVISI_FNA|FINANCE` (from "Finance")
  - `DIVISI_SNM|MARKETING`
- Do NOT create: `DIVISI_MANAJEMEN|NA` (skip subdivision if "NA")


## Processing Logic

For each row in the CSV:
1. Read role information (Role Code, Division, Subdivision, Aplikasi)
2. Parse and prepare application groups (trim spaces)
3. For each station column:
   - If value is a number > 0:
     - Get station mapping (name, initial, cabang)
     - Generate groups list for this station
     - Create N users (where N = the number in the cell)
     - Generate unique usernames (append number if N > 1)
     - Generate random password for each user
     - Create user JSON object

## Important Rules

1. **All group names must be UPPERCASE**
2. **Skip subdivision group if Subdivision column = "NA"**
3. **Trim whitespace from application names before creating groups**
4. **Omit email field entirely (do not include empty string)**
5. **firstName and lastName are empty strings**
6. **Use placeholder initials (BGR, CRB, MLG) for stations not in controller**
7. **Sanitize station names in groups:** remove dots, spaces → underscores, & → AND
8. **Role field is optional:** If a role is specified, it must exist in Keycloak as a realm role. Omit the field if no role should be assigned.

## Example Output

```json
[
  {
    "username": "branch_mgr_dps",
    "firstName": "",
    "lastName": "",
    "enabled": true,
    "emailVerified": false,
    "password": "Pass5598!",
    "temporary_password": true,
    "groups": [
      "CABANG_DENPASAR",
      "CABANG_DENPASAR|STO_DENPASAR",
      "DIVISI_MANAJEMEN",
      "APP_SIMAPEN",
      "APP_SIMADIS",
      "APP_MT",
      "APP_GL",
      "APP_PERSONALIA",
      "APP_PKH_ONLINE"
    ],
    "role": "branch_mgr"
  },
  {
    "username": "sales_dps_1",
    "firstName": "",
    "lastName": "",
    "enabled": true,
    "emailVerified": false,
    "password": "Pass2341!",
    "temporary_password": true,
    "groups": [
      "CABANG_DENPASAR",
      "CABANG_DENPASAR|STO_DENPASAR",
      "DIVISI_SNM",
      "DIVISI_SNM|MARKETING",
      "APP_SIMAPEN",
      "APP_SIMADIS"
    ],
    "role": "sales"
  }
]
```

## Reference Files

- **Example format:** `users.json.example`
- **Station-Cabang mapping:** `cabang_station_list.txt`
- **CSV input:** `Access control SIMSS dec 25 - Roles.csv`
- **Generation script:** `generate_users_json.py`
