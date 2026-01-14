# SIMADIS Integration Guide

> **Note**: This document was updated by AI assistant on December 24, 2025.

This guide walks through integrating the Keycloak SIMSS Connector into the SIMADIS application.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step-by-Step Integration](#step-by-step-integration)
  - [Step 1: Add as Git Submodule](#step-1-add-as-git-submodule)
  - [Step 2: Install Composer Dependencies](#step-2-install-composer-dependencies)
  - [Step 3: Configure Composer Autoloading](#step-3-configure-composer-autoloading)
  - [Step 4: Create Keycloak Configuration](#step-4-create-keycloak-configuration)
  - [Step 5: Create Authentication Controller](#step-5-create-authentication-controller)
  - [Step 6: Update Routes](#step-6-update-routes)
  - [Step 7: Handle Old Auth Controller](#step-7-handle-old-auth-controller)
  - [Step 8: Protect Routes with Authentication](#step-8-protect-routes-with-authentication)
  - [Step 9: (Optional) Endpoint Permission Control](#step-9-optional-endpoint-permission-control)
  - [Step 10: (Optional) Role/Group-Based Access](#step-10-optional-rolegroup-based-access)
  - [Step 11: (Optional) Attribute-Based Access Control](#step-11-optional-attribute-based-access-control)
  - [Step 12: (Optional) Rate Limiting](#step-12-optional-rate-limiting)
  - [Step 13: Update Views to Use New Session Data](#step-13-update-views-to-use-new-session-data)
  - [Step 14: Access User Information](#step-14-access-user-information)
  - [Step 15: Update Existing Session Checks](#step-15-update-existing-session-checks)
- [Keycloak Server Configuration](#keycloak-server-configuration)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Rollback Plan](#rollback-plan)
- [Support](#support)

## Prerequisites

- SIMADIS application is a CodeIgniter 3 application
- Keycloak server is set up and accessible
- Git is installed
- Composer is installed

## Step-by-Step Integration

### Step 1: Add as Git Submodule

From the SIMADIS root directory:

```bash
cd /path/to/SIMADIS
git submodule add <repository-url> application/third_party/keycloak-simss-connector
git submodule update --init --recursive
```

### Step 2: Install Composer Dependencies

```bash
cd application/third_party/keycloak-simss-connector
composer install
```

### Step 3: Configure Composer Autoloading

Edit `application/config/config.php` and set:

```php
$config['composer_autoload'] = APPPATH . 'third_party/keycloak-simss-connector/vendor/autoload.php';
```

### Step 4: Create Keycloak Configuration

Create `application/config/keycloak.php`:

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

return [
    // Keycloak server URL
    'issuer' => 'https://your-keycloak-server.com/realms/simss',

    // Client credentials from Keycloak
    'client_id' => 'simadis',
    'client_secret' => 'your-client-secret-from-keycloak',

    // Callback URL (must match Keycloak client config)
    'redirect_uri' => 'https://your-simadis-url.com/auth/callback',

    // Scopes to request
    'scopes' => ['openid', 'profile', 'email'],

    // SSL verification (set to true in production!)
    'verify_peer' => true,
    'verify_host' => true,
];
```

**Important**: Add `keycloak.php` to `.gitignore` to avoid committing secrets:

```bash
echo "application/config/keycloak.php" >> .gitignore
```

Create `application/config/keycloak.example.php` as a template for other developers.

### Step 5: Create Authentication Controller

Create `application/controllers/AuthKeycloak.php`:

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

require_once APPPATH . 'third_party/keycloak-simss-connector/vendor/autoload.php';

use Simss\KeycloakAuth\Controllers\AuthController;
use Simss\KeycloakAuth\Config\KeycloakConfig;

class AuthKeycloak extends CI_Controller
{
    protected $authController;

    public function __construct()
    {
        parent::__construct();

        // Reset singleton to ensure fresh config is loaded
        KeycloakConfig::reset();

        // Load keycloak config via CI and pass to KeycloakConfig
        $this->config->load('keycloak');
        $keycloakConfig = $this->config->item('keycloak');
        KeycloakConfig::getInstance($keycloakConfig);

        // Load role-based home URL configuration (if exists)
        $homeUrlConfig = null;
        if (file_exists(APPPATH . 'config/keycloak_home_urls.php')) {
            $this->config->load('keycloak_home_urls');
            $homeUrlConfig = $this->config->item('keycloak_home_urls');
        }

        // Create AuthController with home URL configuration
        $this->authController = new AuthController($homeUrlConfig);
    }

    public function index()
    {
        $this->authController->index();
    }

    public function login()
    {
        $this->authController->login();
    }

    public function callback()
    {
        $this->authController->callback();
    }

    public function logout()
    {
        $this->authController->logout();
    }

    public function check()
    {
        $this->authController->check();
    }
}
```

#### Step 5a: (Optional) Configure Role-Based Home URLs

To redirect users to different home pages based on their roles after login, create a home URL configuration file.

**Create `application/config/keycloak_home_urls.php`:**

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * Role-Based Home URL Configuration
 * 
 * Maps user roles to their respective home URLs.
 * When a user logs in, they will be redirected to the URL associated
 * with their role. If a user has multiple roles, the first matching
 * role (in order) will be used.
 */

$config['keycloak_home_urls'] = [
    // Role-based home URLs (in priority order)
    'supervisor' => 'supervisor',
    'admin' => 'admin/dashboard',
    'staff' => 'home',
    
    // Default home URL if no role matches
    'default' => 'home',
];
```

**How it works:**

1. After successful authentication, `AuthController` checks the user's roles from the session
2. It matches roles against the configuration in order (first match wins)
3. If a match is found, the user is redirected to that URL
4. If no role matches, the `default` URL is used
5. Role matching is case-insensitive

**URL Format:**

- **Relative URLs** (recommended): Use paths relative to `base_url()`
  - Example: `'supervisor' => 'supervisor'` → redirects to `/supervisor`
  - Example: `'admin' => 'admin/dashboard'` → redirects to `/admin/dashboard`
  
- **Absolute URLs**: Use full URLs for external redirects
  - Example: `'external' => 'https://external-app.com/dashboard'`

**Example Configuration:**

```php
$config['keycloak_home_urls'] = [
    // High priority roles first
    'super_admin' => 'admin/dashboard',
    'administrator' => 'admin',
    'supervisor' => 'supervisor',
    'manager' => 'manager/home',
    'staff' => 'staff/dashboard',
    'viewer' => 'home',
    
    // Default fallback
    'default' => 'home',
];
```

**Note:** If you don't create this configuration file, users will be redirected to the default `/home` URL after login.

### Step 6: Update Routes

Edit `application/config/routes.php` and add:

```php
// Set default controller (loads when visiting root URL)
$route['default_controller'] = 'auth';

// Keycloak authentication routes
// These remap 'auth/*' URLs to AuthKeycloak controller
$route['auth'] = 'AuthKeycloak/index';
$route['auth/login'] = 'AuthKeycloak/login';
$route['auth/callback'] = 'AuthKeycloak/callback';
$route['auth/logout'] = 'AuthKeycloak/logout';
$route['auth/check'] = 'AuthKeycloak/check';
```

#### How CodeIgniter 3 Routing Works

CodeIgniter 3 uses segment-based URL routing. By default, URLs follow this pattern:

```
example.com/controller/method/parameter
```

When custom routes are defined, CI processes them in order:

1. **User visits `/`** → CI looks for `default_controller` = `auth`
2. **Route `$route['auth']` intercepts** → remaps to `AuthKeycloak/index`
3. **`AuthKeycloak::index()` is executed** — not `Auth::index()`

The same applies for all `auth/*` URLs:

| URL | Routed To |
|-----|-----------|
| `/auth` | `AuthKeycloak::index()` |
| `/auth/login` | `AuthKeycloak::login()` |
| `/auth/callback` | `AuthKeycloak::callback()` |
| `/auth/logout` | `AuthKeycloak::logout()` |
| `/auth/check` | `AuthKeycloak::check()` |

**Important**: Because all `auth/*` routes are explicitly remapped to `AuthKeycloak`, the original `Auth.php` controller is never called. You do **not** need to create a redirect wrapper in `Auth.php`.

### Step 7: Handle Old Auth Controller

Since the routes handle all remapping, you have two options:

#### Option A: Delete Auth.php (Recommended)

Simply remove or rename the old controller:

```bash
mv application/controllers/Auth.php application/controllers/Auth.php.backup
```

The routes ensure all `auth/*` requests go to `AuthKeycloak`. No redirect wrapper is needed.

#### Option B: Keep Auth.php as Safety Net (Optional)

If you prefer a fallback in case someone bypasses routing (e.g., direct class instantiation in tests), you can keep a minimal `Auth.php`:

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

// This controller is not used in normal operation.
// Routes in config/routes.php redirect all auth/* URLs to AuthKeycloak.
// This file exists only as a safety net.
class Auth extends CI_Controller
{
    public function index()
    {
        redirect('auth/login');
    }

    public function login()
    {
        redirect('auth/login');
    }

    public function logout()
    {
        redirect('auth/logout');
    }
}
```

**Note**: This is purely optional. Under normal circumstances, CI's routing will always direct traffic to `AuthKeycloak`, making this file redundant.

### Step 8: Protect Routes with Authentication

#### Option A: Protect Individual Controllers

In any controller that requires authentication:

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Home extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();

        // Require authentication
        $middleware = new \Simss\KeycloakAuth\Middleware\AuthMiddleware();
        $middleware->requireAuth();
    }

    public function index()
    {
        // Your controller logic
        $this->load->view('home');
    }
}
```

#### Option B: Protect All Routes Globally

Edit `application/config/config.php`:

```php
$config['enable_hooks'] = TRUE;
```

Add in `application/config/hooks.php`:


```php
// Use the provided hook function
$hook['post_controller_constructor'][] = [
    'function' => 'keycloak_auth_check',
    'filename' => 'keycloak_auth_hook.php',
    'filepath' => 'hooks',
];
```
Copy and paste into `application/hooks/keycloak_auth_hook.php` the following:

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * Keycloak Authentication Hook Function
 * 
 * This function is called after the controller constructor.
 * It checks if the user is authenticated via Keycloak.
 */
function keycloak_auth_check()
{
    // Create middleware instance with any additional excluded paths
    $middleware = new \Simss\KeycloakAuth\Middleware\AuthMiddleware([
        // Add any additional paths to exclude from authentication here
        // '/api/public',
    ]);
    
    // Check authentication
    $middleware->check();
}

```

This will enforce authentication globally, preserve the intended URL for redirect after login, and surface a gentle "session expired" notice on the login page when a session times out.

### Step 9: (Optional) Endpoint Permission Control

For fine-grained access control based on endpoint-module-CRUD mappings, use the `PermissionMiddleware`. This implements a comprehensive Role-Based Access Control (RBAC) system that validates user permissions at the endpoint level.

#### Overview

The PermissionMiddleware provides **client-specific, role-based access control** that allows you to:
- Define which endpoints require which module permissions
- Map user roles to specific module/CRUD permissions
- Automatically validate access on every request
- Maintain separate configurations for different CI3 applications using the same connector

#### How Access Control Works

The RBAC system uses a two-tier mapping approach with client-specific configuration:

```
┌─────────────────────────────────────────────────────────────────┐
│                      ACCESS CONTROL FLOW                        │
└─────────────────────────────────────────────────────────────────┘

1. User Request → /ekspedisi/add
   ↓
2. Extract Client ID from Config → "simadiskc"
   ↓
3. Load Client-Specific Configs from:
   config/access_control/simadiskc/endpoint_permissions.json
   config/access_control/simadiskc/role_permissions.json
   ↓
4. Extract User Role from Session → "logistic_staff"
   ↓
5. Load Endpoint Requirements (endpoint_permissions.json)
   → ekspedisi/add requires: data ekspedisi[C]
   ↓
6. Load User Role Permissions (role_permissions.json)
   → logistic_staff has: data ekspedisi[C, R, U]
   ↓
7. Compare: Does user have ALL required permissions?
   → Check: data ekspedisi has C? ✓ YES
   ↓
8. Result: ✓ AUTHORIZE REQUEST


If ANY permission is missing → ✗ REJECT REQUEST (redirect with error)
```

**Key Components:**

1. **Endpoint permissions** (`endpoint_permissions.json`) - Maps each endpoint to required modules and CRUD permissions
2. **Role permissions** (`role_permissions.json`) - Maps each user role to their allowed modules and CRUD permissions
3. **Client ID** - Determines which configuration directory to use (from `application/config/keycloak.php`)
4. **Middleware validation** - Automatically checks permissions on every request

#### CRUD Permission Mapping

- **C** = Create (add new records)
- **R** = Read (view/retrieve data)
- **U** = Update (modify existing records)
- **D** = Delete (remove records)

#### Configuration Directory Structure

The PermissionMiddleware uses **client-specific configuration directories** based on your Keycloak `client_id`. This allows multiple CI3 applications to use the same connector with different permission configurations.

**Directory Structure:**
```
application/third_party/keycloak-simss-connector/
└── config/
    └── access_control/
        ├── simadiskc/                    ← Client ID from keycloak.php
        │   ├── endpoint_permissions.json
        │   └── role_permissions.json
        ├── simadispo/                    ← Another CI3 app
        │   ├── endpoint_permissions.json
        │   └── role_permissions.json
        └── my-other-app/                 ← Yet another CI3 app
            ├── endpoint_permissions.json
            └── role_permissions.json
```

**How Client ID is Determined:**

The middleware automatically reads your `client_id` from `application/config/keycloak.php`:

```php
// application/config/keycloak.php
return [
    'client_id' => 'simadiskc',  // ← This determines config directory
    // ... other config
];
```

The middleware then loads configs from:
```
config/access_control/{client_id}/endpoint_permissions.json
config/access_control/{client_id}/role_permissions.json
```

For example:
- If `client_id` = `simadiskc`, configs are loaded from `config/access_control/simadiskc/`
- If `client_id` = `simadispo`, configs are loaded from `config/access_control/simadispo/`

**Implementation Detail:**

The config path is constructed in `PermissionMiddleware::getConfigPath()` (line 226-235):
```php
protected function getConfigPath()
{
    // Default: config/access_control/[client_id] relative to connector root
    self::$configPath = dirname(__DIR__, 2) . '/config/access_control/' . $keycloakClientId;
    return self::$configPath;
}
```

#### Setting Up Access Control for a New CI3 Application

Follow these steps to set up access control for your CodeIgniter 3 application:

##### Step 1: Identify Your Client ID

Check your `application/config/keycloak.php` file:

```php
return [
    'client_id' => 'simadiskc',  // ← Your client ID
    // ...
];
```

##### Step 2: Create Client-Specific Config Directory

Navigate to the connector's config directory and create a folder matching your client ID:

```bash
cd application/third_party/keycloak-simss-connector/config/access_control
mkdir simadiskc  # Replace with your actual client_id
cd simadiskc
```

The full path should be:
```
application/third_party/keycloak-simss-connector/config/access_control/[YOUR_CLIENT_ID]/
```

##### Step 3: Create Configuration Files

Create two JSON files in your client-specific directory:

1. **`endpoint_permissions.json`** - Maps endpoints to required permissions
2. **`role_permissions.json`** - Maps roles to granted permissions

##### Step 4: Configure Endpoint Permissions

Create `endpoint_permissions.json` to define which modules and CRUD permissions each endpoint requires:

**File:** `application/third_party/keycloak-simss-connector/config/access_control/[YOUR_CLIENT_ID]/endpoint_permissions.json`

**Purpose:** Maps each endpoint (controller/method) to the functional modules and CRUD permissions it requires.

**Format Guidelines:**
- Endpoint keys must be **lowercase** (e.g., `"ekspedisi/add"`, not `"Ekspedisi/Add"`)
- Endpoint key format: `"controller/method"` (without leading slash)
- Each endpoint specifies an array of `modules` it needs access to
- Each module specifies which CRUD `permissions` are required
- The `controller` field is optional (for documentation purposes)

**Configuration Schema:**

```json
{
  "_meta": {
    "description": "Endpoint to module-permission mapping: for each endpoint, define the required functional modules and the permissions (CRUD) for each."
  },
  "endpoints": {
    "datastock/index": {
      "controller": "DataStock",
      "modules": [
        { "name": "data stock", "permissions": ["R"] }
      ]
    },
    "ekspedisi/add": {
      "controller": "Ekspedisi",
      "modules": [
        { "name": "data ekspedisi", "permissions": ["C"] }
      ]
    },
    "ekspedisi/edit": {
      "controller": "Ekspedisi",
      "modules": [
        { "name": "data ekspedisi", "permissions": ["R", "U"] }
      ]
    },
    "btb/add": {
      "controller": "Btb",
      "modules": [
        { "name": "btb", "permissions": ["C"] },
        { "name": "data produk", "permissions": ["R"] }
      ]
    },
    "btb/save": {
      "controller": "Btb",
      "modules": [
        { "name": "btb", "permissions": ["C"] },
        { "name": "data stock", "permissions": ["U"] }
      ]
    },
    "requisisi/findbarang": {
      "controller": "Requisisi",
      "modules": [
        { "name": "requisisi barang", "permissions": ["R"] },
        { "name": "data produk", "permissions": ["R"] }
      ]
    },
    "requisisi/delete": {
      "controller": "Requisisi",
      "modules": [
        { "name": "requisisi barang", "permissions": ["D"] }
      ]
    }
  }
}
```

**Understanding Endpoint Configuration:**

1. **Single Module Requirement:**
   ```json
   "datastock/index": {
     "controller": "DataStock",
     "modules": [
       { "name": "data stock", "permissions": ["R"] }
     ]
   }
   ```
   - Accessing `/datastock/index` requires Read permission on "data stock" module

2. **Multiple Permissions on One Module:**
   ```json
   "ekspedisi/edit": {
     "modules": [
       { "name": "data ekspedisi", "permissions": ["R", "U"] }
     ]
   }
   ```
   - Requires both Read AND Update permissions on "data ekspedisi"
   - User must have all listed permissions (R and U)

3. **Multiple Module Requirements:**
   ```json
   "btb/add": {
     "modules": [
       { "name": "btb", "permissions": ["C"] },
       { "name": "data produk", "permissions": ["R"] }
     ]
   }
   ```
   - Requires Create on "btb" AND Read on "data produk"
   - User must have permissions on ALL listed modules

4. **Endpoints Not Listed:**
   - If an endpoint is NOT in this config, access is **allowed by default**
   - Only explicitly configured endpoints are restricted
   - Use this for gradual rollout of access control

**Mapping Your Application's Endpoints:**

To build your `endpoint_permissions.json`, follow this process:

1. **List all controllers and their public methods** in your application
   ```bash
   # Find all controllers
   find application/controllers -name "*.php"
   ```

2. **For each endpoint, determine:**
   - What functional module does it belong to? (e.g., "inventory management", "sales order")
   - What operation does it perform? (Create, Read, Update, or Delete)
   - Does it access multiple modules? (e.g., creating a sales order might read inventory)

3. **Group by functional modules** (match your business logic):
   - Data Stock (inventory)
   - Data Produk (products)
   - Data Ekspedisi (shipping)
   - BTB (goods transfer)
   - Requisisi Barang (requisitions)

4. **Start with critical endpoints first:**
   - Deletion endpoints (highest risk)
   - Creation endpoints (data integrity)
   - Modification endpoints
   - View endpoints last (lowest risk)

##### Step 5: Configure Role Permissions

Create `role_permissions.json` to define what modules each role can access:

**File:** `application/third_party/keycloak-simss-connector/config/access_control/[YOUR_CLIENT_ID]/role_permissions.json`

**Purpose:** Maps user roles to their granted modules and CRUD permissions.

**Format Guidelines:**
- Role keys must be **lowercase** (e.g., `"administrator"`, not `"Administrator"`)
- Role keys should match exactly what Keycloak sends in the ID token
- Each role defines a `modules` object mapping module names to permission arrays
- Module names must match those used in `endpoint_permissions.json`
- The `display_name` field is optional (for UI display)

**Configuration Schema:**

This file maps user roles to the modules they can access and what CRUD permissions they have on each module.

```json
{
  "_meta": {
    "description": "Maps user roles to module privileges (CRUD). Used with endpoint_permissions.json to determine access.",
    "generated_from": "Manual configuration or CSV export"
  },
  "roles": {
    "administrator": {
      "display_name": "Administrator",
      "modules": {
        "data stock": ["C", "R", "U", "D"],
        "data produk": ["C", "R", "U", "D"],
        "data ekspedisi": ["C", "R", "U", "D"],
        "btb": ["C", "R", "U", "D"],
        "bkb": ["C", "R", "U", "D"],
        "requisisi barang": ["C", "R", "U", "D"]
      }
    },
    "logistic_manager": {
      "display_name": "Logistic Manager",
      "modules": {
        "data produk": ["C", "R", "U"],
        "data stock": ["R"],
        "data ekspedisi": ["C", "R", "U"],
        "requisisi barang": ["C", "R", "U"]
      }
    },
    "logistic_staff": {
      "display_name": "Logistic Staff",
      "modules": {
        "data produk": ["C", "R", "U"],
        "data stock": ["R"],
        "data ekspedisi": ["C", "R", "U"],
        "requisisi barang": ["C", "R", "U"]
      }
    },
    "branch_manager": {
      "display_name": "Branch Manager",
      "modules": {
        "data produk": ["R"],
        "data stock": ["R"],
        "data ekspedisi": ["R"],
        "requisisi barang": ["R"]
      }
    }
  }
}
```

**Understanding Role Configuration:**

1. **Administrator Role (Full Access):**
   ```json
   "administrator": {
     "display_name": "Administrator",
     "modules": {
       "data stock": ["C", "R", "U", "D"],
       "data produk": ["C", "R", "U", "D"]
     }
   }
   ```
   - Has full CRUD access to all modules
   - Can perform any operation

2. **Manager Role (Limited Delete):**
   ```json
   "logistic_manager": {
     "modules": {
       "data produk": ["C", "R", "U"],    // No Delete
       "data stock": ["R"],                // Read-only
       "data ekspedisi": ["C", "R", "U"]
     }
   }
   ```
   - Can create, read, update (but not delete) most modules
   - Read-only access to stock data

3. **Staff Role (Operational):**
   ```json
   "logistic_staff": {
     "modules": {
       "data ekspedisi": ["C", "R", "U"],
       "requisisi barang": ["C", "R", "U"]
     }
   }
   ```
   - Limited to specific modules relevant to their job
   - No delete permissions

4. **Viewer Role (Read-Only):**
   ```json
   "branch_manager": {
     "modules": {
       "data produk": ["R"],
       "data stock": ["R"],
       "data ekspedisi": ["R"]
     }
   }
   ```
   - Can only view data, no modifications allowed

**Designing Your Role Hierarchy:**

1. **Identify organizational roles** in your company:
   - What job positions exist? (Admin, Manager, Staff, Viewer)
   - What are their responsibilities?
   - What data do they need access to?

2. **Map roles to functional modules:**
   - Create a matrix of Role × Module × CRUD
   - Example:
     ```
     | Role              | Inventory | Products | Shipping | Requisitions |
     |-------------------|-----------|----------|----------|--------------|
     | Administrator     | CRUD      | CRUD     | CRUD     | CRUD         |
     | Logistics Manager | R         | CRU      | CRU      | CRU          |
     | Logistics Staff   | R         | CRU      | CRU      | CRU          |
     | Branch Manager    | R         | R        | R        | R            |
     ```

3. **Apply least privilege principle:**
   - Give users the **minimum** permissions needed to do their job
   - Start restrictive, expand as needed
   - Regularly review and audit permissions

4. **Role naming conventions:**
   - Use lowercase with underscores (e.g., `logistic_staff`)
   - Keep names consistent with Keycloak role names
   - Use descriptive names that reflect job function

##### Step 6: Configure Keycloak Roles

Your Keycloak roles must match the role names in `role_permissions.json`:

1. **Login to Keycloak Admin Console**

2. **Navigate to your realm** (e.g., `simss`)

3. **Create roles:**
   - Go to **Realm Roles** or **Client Roles**
   - Click **Create Role**
   - Enter role name (e.g., `logistic_staff`) - **must be lowercase**
   - Save

4. **Assign roles to users:**
   - Go to **Users** → Select user → **Role Mappings**
   - Assign appropriate roles

5. **Ensure roles are included in tokens:**
   - For **Realm Roles**: Automatically included
   - For **Client Roles**: May need to add a protocol mapper

   **Add Client Role Mapper (if needed):**
   - Go to **Clients** → Your client → **Client Scopes** → **[client]-dedicated**
   - Click **Add mapper** → **By configuration** → **User Client Role**
   - Name: `client-roles`
   - Client ID: `[your-client-id]`
   - Token Claim Name: `roles`
   - Add to ID token: **ON**
   - Add to access token: **ON**

##### Step 7: Verify Configuration Files

Before enabling the middleware, verify your JSON files are valid:

```bash
# Navigate to your config directory
cd application/third_party/keycloak-simss-connector/config/access_control/[YOUR_CLIENT_ID]

# Validate JSON syntax
php -r "json_decode(file_get_contents('endpoint_permissions.json')); echo (json_last_error() === JSON_ERROR_NONE) ? 'Valid' : 'Invalid';"
php -r "json_decode(file_get_contents('role_permissions.json')); echo (json_last_error() === JSON_ERROR_NONE) ? 'Valid' : 'Invalid';"
```

**Checklist:**
- [ ] Config directory exists: `config/access_control/[YOUR_CLIENT_ID]/`
- [ ] `endpoint_permissions.json` exists and is valid JSON
- [ ] `role_permissions.json` exists and is valid JSON
- [ ] All endpoint keys are lowercase
- [ ] All role keys are lowercase
- [ ] Module names match between both files
- [ ] Roles exist in Keycloak
- [ ] Roles are assigned to test users

##### Reference Files

Complete examples are available at:
- `config/access_control/endpoint_permissions.example.json`
- `config/access_control/role_permissions.example.json`

You can copy these as starting templates for your application.

#### Enable Permission Middleware

You have two options for enabling the permission middleware:

##### Option A: Global Hook (Recommended)

Enable permission checking for all requests by updating your authentication hook.

Edit `application/hooks/keycloak_auth_hook.php`:

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

function keycloak_auth_check()
{
    // Initialize authentication middleware
    $authMiddleware = new \Simss\KeycloakAuth\Middleware\AuthMiddleware([
        // Add any additional paths to exclude from authentication here
        // '/api/public',
    ]);

    // Check authentication first
    if (!$authMiddleware->check()) {
        return; // Not authenticated, auth middleware handles redirect
    }

    // Only check permissions if user is authenticated
    $permMiddleware = new \Simss\KeycloakAuth\Middleware\PermissionMiddleware([
        // Add any additional paths to exclude from permission checks
        // '/dashboard',
        // '/profile',
    ]);
    $permMiddleware->check();
}
```

**How it works:**
1. Hook executes after controller constructor (`post_controller_constructor`)
2. Authentication middleware checks if user is logged in
3. If not authenticated, redirects to login (permission check is skipped)
4. If authenticated, permission middleware validates endpoint access
5. If access denied, redirects back with error message

**Excluded paths** (no permission check):
- `/auth/*` - Authentication endpoints (always excluded)
- `/home` - Home page (always excluded)
- Any paths you add to the constructor array

##### Option B: Per-Controller (Selective)

Apply permission checking only to specific controllers:

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Btb extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();

        // Require authentication
        $authMiddleware = new \Simss\KeycloakAuth\Middleware\AuthMiddleware();
        $authMiddleware->requireAuth();

        // Check endpoint permissions
        $permMiddleware = new \Simss\KeycloakAuth\Middleware\PermissionMiddleware();
        $permMiddleware->check();
    }

    public function add()
    {
        // This method is protected by permission middleware
        // User must have required permissions from endpoint_permissions.json
    }
}
```
#### Behavior and Configuration Notes

##### Default Behaviors
- **Unregistered endpoints**: If an endpoint is not in `endpoint_permissions.json`, access is **allowed by default** (only explicitly configured endpoints are restricted)
- **Empty modules array**: An endpoint with empty `modules: []` allows all authenticated users
- **Missing roles**: If a user's role is not in `role_permissions.json`, that role is skipped (other roles are checked)
- **No roles**: If user has no roles assigned, access is denied

##### Multiple Roles Support
- If a user has multiple roles, access is granted if **ANY ONE** of their roles satisfies all requirements
- Roles are checked in the order they appear in the session
- The first role that satisfies all requirements grants access
- Detailed logging shows which role granted access

##### Performance Optimizations
- **Static caching**: Config files are loaded once per PHP process and cached in memory
- **Minimal overhead**: Typically adds < 5ms to request processing time
- **No database queries**: All validation done in-memory using JSON configs

##### Access Denial Handling
- **Redirect behavior**: Redirects to previous page (via HTTP_REFERER header)
- **Fallback**: If no valid referer, redirects to `/home`
- **Flash message**: Sets session flash message in Indonesian: "Anda tidak memiliki izin untuk mengakses halaman tersebut."
- **Security**: Validates referer is from same host (prevents open redirect)

##### Logging and Debugging

The middleware provides comprehensive logging for debugging:

**Access Granted** (log level: `info`):
```
[PermissionMiddleware] Access granted to ekspedisi/add for role: logistic_staff
```

**Access Denied** (log level: `warning`):
```
[PermissionMiddleware] Access denied to endpoint: ekspedisi/add.
User roles: [branch_manager].
Required: data ekspedisi[C].
Reason: [branch_manager: Module 'data ekspedisi': has [R], missing [C]]
```

**Unregistered Endpoint** (log level: `debug`):
```
[PermissionMiddleware] Endpoint not in config (allowing access): some/endpoint
```

To view these logs, enable CodeIgniter logging in `application/config/config.php`:
```php
$config['log_threshold'] = 2; // 0=off, 1=error, 2=debug, 3=info, 4=all
```

##### Debugging Tips

1. **Check log files**: Look at `application/logs/log-YYYY-MM-DD.php` for detailed access denial reasons
2. **Verify endpoint key**: Ensure endpoint key in config matches actual URL (lowercase, format: `controller/method`)
3. **Verify role names**: Role keys in `role_permissions.json` must be lowercase
4. **Check user session**: Verify user's roles are correctly stored in session via SessionManager
5. **Use public methods**: For debugging/testing, use:
   ```php
   $perms = \Simss\KeycloakAuth\Middleware\PermissionMiddleware::getEndpointPermissions();
   $roles = \Simss\KeycloakAuth\Middleware\PermissionMiddleware::getRolePermissions();
   var_dump($perms, $roles);
   ```

##### Excluded Paths

By default, these paths are excluded from permission checks:
- `/auth`, `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/check`
- `/home`

Add custom excluded paths:
```php
$permMiddleware = new \Simss\KeycloakAuth\Middleware\PermissionMiddleware([
    '/public',
    '/api/health',
    '/welcome'
]);
```

#### Testing Access Control Configuration

After setting up your configuration files, thoroughly test the access control system:

##### Test Plan

**1. Test with Administrator Role**

Create a test user with `administrator` role:

```bash
# Login as administrator
# Expected: Should have access to ALL endpoints
```

Test endpoints:
- [ ] Can view data (e.g., `/datastock/index`)
- [ ] Can create records (e.g., `/ekspedisi/add`)
- [ ] Can update records (e.g., `/ekspedisi/edit`)
- [ ] Can delete records (e.g., `/ekspedisi/delete`)

**2. Test with Restricted Role**

Create a test user with `logistic_staff` role:

```bash
# Login as logistic_staff
# Expected: Limited access based on role_permissions.json
```

Test scenarios:
- [ ] **Allowed endpoint**: Access `/ekspedisi/add` → Should succeed (has Create permission)
- [ ] **Denied endpoint**: Access `/ekspedisi/delete` → Should redirect with error message
- [ ] **Read-only module**: Access `/datastock/index` → Should succeed (has Read)
- [ ] **Forbidden module**: Access endpoint requiring unassigned module → Should deny

**3. Test with Multiple Roles**

Create a test user with both `branch_manager` and `logistic_staff` roles:

```bash
# Expected: Access granted if ANY role satisfies requirements
```

- [ ] Endpoint requiring only branch_manager permissions → Should succeed
- [ ] Endpoint requiring only logistic_staff permissions → Should succeed
- [ ] Endpoint requiring permissions neither role has → Should deny

**4. Test with No Roles**

Create a test user with NO roles assigned:

```bash
# Expected: All protected endpoints deny access
```

- [ ] Access any protected endpoint → Should redirect with error
- [ ] Check log for "User has no roles assigned"

**5. Test Unregistered Endpoints**

Access an endpoint NOT listed in `endpoint_permissions.json`:

```bash
# Expected: Access allowed (only explicitly configured endpoints are restricted)
```

- [ ] Access unlisted endpoint → Should allow access
- [ ] Check log for "Endpoint not in config (allowing access)"

##### Manual Testing Steps

1. **Enable CodeIgniter logging** (`application/config/config.php`):
   ```php
   $config['log_threshold'] = 2; // Debug level
   ```

2. **Create test script** (`test_permissions.php` in application root):
   ```php
   <?php
   require_once 'vendor/autoload.php';

   // Load configs
   $endpoint = \Simss\KeycloakAuth\Middleware\PermissionMiddleware::getEndpointPermissions();
   $roles = \Simss\KeycloakAuth\Middleware\PermissionMiddleware::getRolePermissions();

   echo "=== Endpoint Permissions ===\n";
   print_r($endpoint);

   echo "\n=== Role Permissions ===\n";
   print_r($roles);

   // Test specific endpoint
   $testEndpoint = 'ekspedisi/add';
   echo "\n=== Testing endpoint: $testEndpoint ===\n";

   if (isset($endpoint[$testEndpoint])) {
       echo "Required modules:\n";
       print_r($endpoint[$testEndpoint]['modules']);
   } else {
       echo "Endpoint not configured (access allowed by default)\n";
   }

   // Test specific role
   $testRole = 'logistic_staff';
   echo "\n=== Testing role: $testRole ===\n";

   if (isset($roles[$testRole])) {
       echo "Granted modules:\n";
       print_r($roles[$testRole]['modules']);
   } else {
       echo "Role not configured\n";
   }
   ```

3. **Run test**:
   ```bash
   php test_permissions.php
   ```

4. **Check output** for configuration errors

##### Automated Testing

Create PHPUnit tests for permission logic:

```php
<?php
class PermissionMiddlewareTest extends \PHPUnit\Framework\TestCase
{
    public function testAdministratorHasFullAccess()
    {
        // Set up test user with administrator role
        // Test access to all endpoints
        // Assert all access granted
    }

    public function testStaffDeniedDeleteAccess()
    {
        // Set up test user with logistic_staff role
        // Test access to delete endpoint
        // Assert access denied
    }

    public function testMultipleRolesFirstMatchWins()
    {
        // Set up user with multiple roles
        // Test endpoint accessible by second role
        // Assert access granted
    }
}
```

##### Common Test Failures and Solutions

| Test Failure | Possible Cause | Solution |
|--------------|----------------|----------|
| "Role not found in configuration" | Role name mismatch | Ensure role names are lowercase in both Keycloak and `role_permissions.json` |
| "Module 'X' missing" | Module not assigned to role | Add module to role in `role_permissions.json` |
| "Missing permission [C]" | Role lacks specific CRUD permission | Add permission letter to module's array |
| "Endpoint not in config" log but access denied | Wrong endpoint key format | Check endpoint key is lowercase `controller/method` |
| Config not loading | Wrong client_id directory | Verify directory name matches `client_id` in `keycloak.php` |
| Always allowed regardless of config | Endpoint excluded from checks | Check if endpoint in excluded paths list |

#### Troubleshooting Access Control

##### Issue: "Permission denied" but user should have access

**Diagnosis steps:**

1. **Check user's roles in session:**
   ```php
   // Add to controller temporarily
   $sessionManager = new \Simss\KeycloakAuth\Auth\SessionManager();
   var_dump($sessionManager->getRoles());
   exit;
   ```

2. **Verify role name matches config:**
   - Keycloak role: `Logistic_Staff` (incorrect - has capital letters)
   - Config role: `logistic_staff` (correct - all lowercase)
   - Solution: Make Keycloak role lowercase OR update config to match

3. **Check endpoint key in log:**
   ```
   [PermissionMiddleware] Access denied to endpoint: ekspedisi/add
   ```
   - Ensure this matches your `endpoint_permissions.json` exactly

4. **Verify module names match:**
   - `endpoint_permissions.json`: `"data ekspedisi"`
   - `role_permissions.json`: `"data-ekspedisi"` ← Mismatch!
   - Solution: Use exact same module name in both files

5. **Check required vs granted permissions:**
   ```
   Required: data ekspedisi[C, R]
   Role has: data ekspedisi[R]
   ```
   - Missing Create permission
   - Solution: Add "C" to role's module permissions

##### Issue: Config files not loading

**Symptoms:**
- All endpoints allow access regardless of config
- Log shows: "Endpoint permissions file not found"

**Diagnosis:**

1. **Verify directory structure:**
   ```bash
   ls -la application/third_party/keycloak-simss-connector/config/access_control/
   ```
   - Should show your `[client_id]` directory

2. **Check client_id:**
   ```php
   // Add to controller temporarily
   $config = \Simss\KeycloakAuth\Config\KeycloakConfig::getInstance();
   echo "Client ID: " . $config->getClientId();
   exit;
   ```
   - Verify this matches your directory name

3. **Verify file paths:**
   ```bash
   # Expected path pattern
   config/access_control/[client_id]/endpoint_permissions.json
   config/access_control/[client_id]/role_permissions.json
   ```

4. **Check file permissions:**
   ```bash
   chmod 644 config/access_control/[client_id]/*.json
   ```

##### Issue: JSON parse errors

**Symptoms:**
- Config partially loading
- Unexpected behavior
- PHP warnings about JSON

**Diagnosis:**

1. **Validate JSON syntax:**
   ```bash
   # Use online validator or command line
   python -m json.tool endpoint_permissions.json
   # OR
   jq . endpoint_permissions.json
   # OR
   php -r "json_decode(file_get_contents('endpoint_permissions.json')); echo json_last_error_msg();"
   ```

2. **Common JSON errors:**
   - Trailing commas: `"permissions": ["C", "R",]` ← Remove last comma
   - Missing quotes: `{name: "btb"}` ← Should be `{"name": "btb"}`
   - Comments: `// This is a comment` ← JSON doesn't support comments
   - Single quotes: `'data stock'` ← Use double quotes: `"data stock"`

##### Issue: Access always allowed

**Possible causes:**

1. **Endpoint not in `endpoint_permissions.json`:**
   - By design, unregistered endpoints allow access
   - Solution: Add endpoint to config

2. **Empty modules array:**
   ```json
   "someendpoint/method": {
     "modules": []  ← Allows all authenticated users
   }
   ```
   - Solution: Add required modules

3. **Endpoint in excluded paths:**
   - Check `PermissionMiddleware` constructor for excluded paths
   - Solution: Remove from excluded paths if it should be protected

4. **Middleware not enabled:**
   - Check hook is configured in `config/hooks.php`
   - Check `$config['enable_hooks'] = TRUE` in `config/config.php`
   - Solution: Enable hooks and add middleware call

#### Quick Reference: Setting Up Access Control for New CI3 App

Follow this checklist for a new CodeIgniter 3 application:

**Step-by-Step Setup:**

```bash
# 1. Check your client_id
grep 'client_id' application/config/keycloak.php
# Output example: 'client_id' => 'simadiskc',

# 2. Create config directory
cd application/third_party/keycloak-simss-connector/config/access_control
mkdir simadiskc  # Use your actual client_id
cd simadiskc

# 3. Create config files
touch endpoint_permissions.json
touch role_permissions.json

# 4. Copy example templates (optional)
cp ../endpoint_permissions.example.json endpoint_permissions.json
cp ../role_permissions.example.json role_permissions.json

# 5. Edit configs with your endpoints and roles
# Use your text editor to customize the JSON files

# 6. Validate JSON syntax
php -r "json_decode(file_get_contents('endpoint_permissions.json')); echo (json_last_error() === JSON_ERROR_NONE) ? 'Valid' : json_last_error_msg();"
php -r "json_decode(file_get_contents('role_permissions.json')); echo (json_last_error() === JSON_ERROR_NONE) ? 'Valid' : json_last_error_msg();"

# 7. Set file permissions
chmod 644 *.json
```

**Required Files:**
- `application/config/keycloak.php` → Contains `client_id`
- `config/access_control/[client_id]/endpoint_permissions.json` → Endpoint requirements
- `config/access_control/[client_id]/role_permissions.json` → Role grants

**Configuration Summary:**

| Configuration File | Purpose | Key Format | Example |
|--------------------|---------|------------|---------|
| `endpoint_permissions.json` | Maps endpoints to required modules/CRUD | `"controller/method"` (lowercase) | `"ekspedisi/add": {"modules": [{"name": "data ekspedisi", "permissions": ["C"]}]}` |
| `role_permissions.json` | Maps roles to granted modules/CRUD | `"role_name"` (lowercase) | `"logistic_staff": {"modules": {"data ekspedisi": ["C", "R", "U"]}}` |

**Access Control Logic:**

```
For each request:
  1. Extract endpoint (e.g., "ekspedisi/add")
  2. Load required modules from endpoint_permissions.json
  3. Extract user roles from session
  4. For each role, load granted modules from role_permissions.json
  5. Check: Does user have ALL required modules + permissions?
     - YES → Allow access
     - NO → Redirect with error message
```

**Key Principles:**

- **Endpoint not in config** → Access allowed by default
- **User has multiple roles** → Access granted if ANY role satisfies requirements
- **Module names** → Must match exactly in both files
- **Role names** → Must be lowercase
- **Endpoint keys** → Must be lowercase `controller/method` format
- **CRUD letters** → Must be uppercase: `["C", "R", "U", "D"]`

**Common Pitfalls:**

❌ **Don't:**
- Use uppercase in endpoint keys: `"Ekspedisi/Add"`
- Use uppercase in role names: `"Logistic_Staff"`
- Mismatch module names between files
- Forget to assign roles to users in Keycloak
- Use different client_id in directory vs config

✅ **Do:**
- Use lowercase for all keys: `"ekspedisi/add"`, `"logistic_staff"`
- Keep module names consistent
- Test with different user roles
- Enable logging for debugging
- Validate JSON syntax before deploying

### Step 10: (Optional) Role/Group-Based Access

Roles and groups from Keycloak are stored in the session (`roles`, `groups`) with `lvl` kept for backward compatibility. To protect a controller:

```php
require_once APPPATH . 'third_party/keycloak-simss-connector/vendor/autoload.php';

class DataStock extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();
        $middleware = new \Simss\KeycloakAuth\Middleware\AuthMiddleware();

        // Require any of these roles or groups
        $middleware->requireAnyRole(['admin', 'inventory']);
        // Or a single role: $middleware->requireRole('admin');
    }
}
```

You can also create a base controller that calls `requireAnyRole()` in its constructor and extend it across protected controllers.

### Step 11: (Optional) Attribute-Based Access Control

For more granular access control based on user attributes (e.g., branch code, store code), use `SessionManager` directly:

#### Check Single Attribute

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class BranchReport extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();
        
        $middleware = new \Simss\KeycloakAuth\Middleware\AuthMiddleware();
        $middleware->requireAuth();
        
        // Restrict to specific branch
        $sessionManager = new \Simss\KeycloakAuth\Auth\SessionManager();
        $userBranch = $sessionManager->getUserAttribute('kdcab');
        
        if ($userBranch !== 'CAB001') {
            redirect('home'); // Deny access
        }
    }
}
```

#### Restrict by Multiple Allowed Values

```php
$sessionManager = new \Simss\KeycloakAuth\Auth\SessionManager();
$userBranch = $sessionManager->getUserAttribute('kdcab');

$allowedBranches = ['CAB001', 'CAB002', 'CAB003'];
if (!in_array($userBranch, $allowedBranches)) {
    redirect('home');
}
```

#### Combine Role and Attribute Checks

```php
$middleware = new \Simss\KeycloakAuth\Middleware\AuthMiddleware();
$sessionManager = new \Simss\KeycloakAuth\Auth\SessionManager();

// Must be authenticated
$middleware->requireAuth();

// Admin can access all branches, others restricted to their own
if (!$middleware->hasRole('admin')) {
    $userBranch = $sessionManager->getUserAttribute('kdcab');
    $requestedBranch = $this->input->get('branch');
    
    if ($requestedBranch && $requestedBranch !== $userBranch) {
        show_error('You can only access data for your own branch.', 403);
    }
}
```

#### Available User Attributes

The following attributes are stored in session after login:

| Attribute | Description | Example |
|-----------|-------------|---------|
| `username` | Keycloak username | `john.doe` |
| `nama` | Full name | `John Doe` |
| `email` | Email address | `john@example.com` |
| `kdcab` | Branch code | `CAB001` |
| `inicab` | Store code | `STO001` |
| `lvl` | User level (first role/group) | `admin` |
| `roles` | Array of all roles | `['admin', 'manager']` |
| `groups` | Array of all groups | `['/branch-managers']` |

Access any attribute via:
```php
$sessionManager = new \Simss\KeycloakAuth\Auth\SessionManager();
$value = $sessionManager->getUserAttribute('kdcab', 'default_value');
```

### Step 12: (Optional) Rate Limiting

`AuthController` applies a lightweight IP-based rate limit on `auth/login` (30 attempts / 60s) and `auth/callback` (60 attempts / 5m). It uses the CI cache driver if available, falling back to PHP session storage. No extra setup is required, but you can tune these limits in code if needed.

### Step 13: Update Views to Use New Session Data

The session structure remains the same, so existing code should work. However, update login views:

Edit `application/views/pages/auth-login.php`:

```php
<!DOCTYPE html>
<html>
<head>
    <title>Login - SIMADIS</title>
</head>
<body>
    <div class="login-container">
        <h1>SIMADIS Login</h1>
        <a href="<?php echo base_url('auth/login'); ?>" class="btn btn-primary">
            Login with Keycloak
        </a>
    </div>
</body>
</html>
```

### Step 14: Access User Information

Throughout your application, access user data as before:

```php
// Old way (still works with CodeIgniter session)
$username = $this->session->userdata('keycloak_auth')['username'];

// Or use SessionManager directly
$sessionManager = new \Simss\KeycloakAuth\Auth\SessionManager();

if ($sessionManager->isAuthenticated()) {
    $userData = $sessionManager->getSessionData();
    echo "Welcome, " . $userData['nama'];
}
```

### Step 15: Update Existing Session Checks

Find and update any session checks in your codebase:

Old code:
```php
if($this->session->userdata('logged_in') != true) {
    redirect(base_url('auth'));
}
```

New code:
```php
$sessionManager = new \Simss\KeycloakAuth\Auth\SessionManager();
if (!$sessionManager->isAuthenticated()) {
    redirect(base_url('auth/login'));
}
```

Or use the middleware approach instead (recommended).

### Step 16: (Optional) UI Integration - User Profile Header and Modal

To provide a consistent user experience across your CodeIgniter 3 applications, you can integrate a user profile dropdown and detailed profile modal in your views. This section provides ready-to-use UI snippets.

#### Overview

The UI integration consists of two main components:

1. **User Profile Dropdown** (Header Navigation) - Shows user name, avatar, and quick access menu
2. **User Profile Modal** (Full Details) - Displays comprehensive user information including roles, session details, and Keycloak data

#### Component 1: User Profile Dropdown (Header)

Add this snippet to your header/navigation view (typically `application/views/layout/header.php` or similar):

**Location in your template:** Inside the main navigation bar, usually in a `<ul class="nav-right">` or similar container.

```php
<li class="user-profile header-notification">
    <div class="dropdown-primary dropdown">
        <div class="dropdown-toggle" data-toggle="dropdown">
            <img src="<?php echo base_url(); ?>assets/images/avatar.png" class="img-radius" alt="User-Profile-Image">
            <span><?php
                $keycloakAuth = $this->session->userdata('keycloak_auth');
                $displayName = !empty($keycloakAuth['name']) ? $keycloakAuth['name'] :
                              (!empty($keycloakAuth['username']) ? $keycloakAuth['username'] :
                              $this->session->userdata('nama'));
                echo $displayName;
            ?></span>
            <i class="feather icon-chevron-down"></i>
        </div>
        <ul class="show-notification profile-notification dropdown-menu" data-dropdown-in="fadeIn" data-dropdown-out="fadeOut" style="width: 380px; max-height: 500px; overflow-y: auto;">
            <?php
            $keycloakAuth = $this->session->userdata('keycloak_auth');
            $keycloakTokens = $this->session->userdata('keycloak_tokens');
            $simssData = isset($keycloakAuth['simss']) ? $keycloakAuth['simss'] : [];

            if (ENVIRONMENT === 'development'):
                // Development: Show all user details including SIMSS data
            ?>
            <li style="padding: 10px 15px; border-bottom: 1px solid #f1f1f1; background: #f8f9fa;">
                <strong style="color: #333;">User Details (Dev)</strong>
            </li>
            <?php if (!empty($keycloakAuth)): ?>
            <li style="padding: 8px 15px; font-size: 12px; border-bottom: 1px solid #f1f1f1;">
                <div style="margin-bottom: 5px;"><strong>Username:</strong> <?php echo htmlspecialchars($keycloakAuth['username'] ?? 'N/A'); ?></div>
                <div style="margin-bottom: 5px;"><strong>Email:</strong> <?php echo htmlspecialchars($keycloakAuth['email'] ?? 'N/A'); ?></div>
                <div style="margin-bottom: 5px;"><strong>Name:</strong> <?php echo htmlspecialchars($keycloakAuth['nama'] ?? $keycloakAuth['name'] ?? 'N/A'); ?></div>

                <?php if (!empty($simssData)): ?>
                <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #e0e0e0;">
                    <strong style="color: #0066cc;">User Info</strong>

                    <?php if (!empty($simssData['cabang'])): ?>
                    <div style="margin: 5px 0;">
                        <strong style="font-size: 10px; color: #666;">Cabang:</strong><br>
                        <?php foreach ($simssData['cabang'] as $cabang): ?>
                        <span style="display: inline-block; background: #17a2b8; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin: 2px;"><?php echo htmlspecialchars($cabang); ?></span>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>

                    <?php if (!empty($simssData['divisi'])): ?>
                    <div style="margin: 5px 0;">
                        <strong style="font-size: 10px; color: #666;">Divisi:</strong><br>
                        <?php foreach ($simssData['divisi'] as $divisi): ?>
                        <span style="display: inline-block; background: #6610f2; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin: 2px;"><?php echo htmlspecialchars($divisi); ?></span>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>

                    <?php if (!empty($simssData['station'])): ?>
                    <div style="margin: 5px 0;">
                        <strong style="font-size: 10px; color: #666;">Station:</strong><br>
                        <?php foreach ($simssData['station'] as $station): ?>
                        <span style="display: inline-block; background: #fd7e14; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin: 2px;"><?php echo htmlspecialchars($station); ?></span>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>

                    <?php if (!empty($simssData['subdivisi'])): ?>
                    <div style="margin: 5px 0;">
                        <strong style="font-size: 10px; color: #666;">Subdivisi:</strong><br>
                        <?php foreach ($simssData['subdivisi'] as $subdivisi): ?>
                        <span style="display: inline-block; background: #e83e8c; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin: 2px;"><?php echo htmlspecialchars($subdivisi); ?></span>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>

                    <?php if (!empty($simssData['role'])): ?>
                    <div style="margin: 5px 0;">
                        <strong style="font-size: 10px; color: #666;">Jabatan</strong><br>
                        <?php foreach ($simssData['role'] as $role): ?>
                        <span style="display: inline-block; background: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin: 2px;"><?php echo htmlspecialchars($role); ?></span>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #e0e0e0;">
                    <strong>Token Info:</strong>
                    <div style="font-size: 10px; color: #666;">
                        Issued: <?php echo !empty($keycloakAuth['iat']) ? date('Y-m-d H:i:s', $keycloakAuth['iat']) : 'N/A'; ?><br>
                        Expires: <?php echo !empty($keycloakAuth['exp']) ? date('Y-m-d H:i:s', $keycloakAuth['exp']) : 'N/A'; ?>
                    </div>
                </div>
            </li>
            <?php else: ?>
            <li style="padding: 8px 15px; font-size: 12px; color: #999;">
                No Keycloak auth data available
            </li>
            <?php endif; ?>
            <?php else:
                // Production: Show SIMSS organizational info and roles
                $keycloakConfig = $this->config->item('keycloak');
                $keycloakAdminUrl = !empty($keycloakConfig['issuer']) ?
                                   str_replace('/realms/', '/admin/', $keycloakConfig['issuer']) . '/console' :
                                   '#';
            ?>
            <!-- SIMSS Organization Info -->
            <?php if (!empty($simssData)): ?>
            <li style="padding: 10px 15px; border-bottom: 1px solid #f1f1f1; background: #f8f9fa;">
                <strong style="color: #0066cc; font-size: 12px;">Organization</strong>
            </li>
            <li style="padding: 8px 15px; font-size: 11px; border-bottom: 1px solid #f1f1f1;">
                <?php if (!empty($simssData['cabang'])): ?>
                <div style="margin-bottom: 6px;">
                    <i class="feather icon-home" style="color: #17a2b8; margin-right: 5px;"></i>
                    <strong>Cabang:</strong>
                    <?php echo htmlspecialchars(implode(', ', $simssData['cabang'])); ?>
                </div>
                <?php endif; ?>

                <?php if (!empty($simssData['divisi'])): ?>
                <div style="margin-bottom: 6px;">
                    <i class="feather icon-briefcase" style="color: #6610f2; margin-right: 5px;"></i>
                    <strong>Divisi:</strong>
                    <?php echo htmlspecialchars(implode(', ', $simssData['divisi'])); ?>
                </div>
                <?php endif; ?>

                <?php if (!empty($simssData['station'])): ?>
                <div style="margin-bottom: 6px;">
                    <i class="feather icon-map-pin" style="color: #fd7e14; margin-right: 5px;"></i>
                    <strong>Station:</strong>
                    <?php echo htmlspecialchars(implode(', ', $simssData['station'])); ?>
                </div>
                <?php endif; ?>

                <?php if (!empty($simssData['subdivisi'])): ?>
                <div style="margin-bottom: 6px;">
                    <i class="feather icon-folder" style="color: #e83e8c; margin-right: 5px;"></i>
                    <strong>Subdivisi:</strong>
                    <?php echo htmlspecialchars(implode(', ', $simssData['subdivisi'])); ?>
                </div>
                <?php endif; ?>
            </li>
            <?php endif; ?>

            <!-- Roles -->
            <li style="padding: 10px 15px; border-bottom: 1px solid #f1f1f1;">
                <div style="margin-bottom: 5px;"><strong>Roles:</strong></div>
                <?php if (!empty($simssData['role'])): ?>
                    <?php foreach ($simssData['role'] as $role): ?>
                    <span style="display: inline-block; background: #28a745; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; margin: 2px;"><?php echo htmlspecialchars($role); ?></span>
                    <?php endforeach; ?>
                <?php elseif (!empty($keycloakAuth['roles'])): ?>
                    <?php foreach ($keycloakAuth['roles'] as $role): ?>
                    <span style="display: inline-block; background: #28a745; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; margin: 2px;"><?php echo htmlspecialchars($role); ?></span>
                    <?php endforeach; ?>
                <?php else: ?>
                    <span style="color: #999;">No roles assigned</span>
                <?php endif; ?>
            </li>
            <li>
                <a href="<?php echo $keycloakAdminUrl; ?>" target="_blank">
                    <i class="feather icon-shield"></i> Keycloak Admin
                </a>
            </li>
            <?php endif; ?>
            <li>
                <a href="#" onclick="event.preventDefault(); document.getElementById('user-details-modal').style.display='block';">
                    <i class="feather icon-user"></i> View Full Profile
                </a>
            </li>
            <li>
                <a href="<?php echo base_url('auth/logout'); ?>">
                    <i class="feather icon-log-out"></i> Logout
                </a>
            </li>
        </ul>
    </div>
</li>
```

**What it does:**
- Displays user avatar and name in the navigation bar
- Shows a dropdown with user organizational info (SIMSS data: cabang, divisi, station, subdivisi)
- Displays assigned roles as badges
- Provides links to:
  - View full profile (opens modal)
  - Keycloak Admin Console
  - Logout
- **Development mode**: Shows additional debug information including token timestamps
- **Production mode**: Shows cleaner organizational view

#### Component 2: User Profile Modal (Full Details)

Add this snippet to your footer view (typically `application/views/layout/footer.php` or before `</body>`):

**Location in your template:** Before your closing `</body>` tag or in a footer partial.

```php
<!-- User Profile Modal -->
<div id="user-details-modal" style="display:none; position: fixed; z-index: 9999; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4);">
    <div style="background-color: #fefefe; margin: 5% auto; padding: 0; border: 1px solid #888; width: 600px; max-width: 90%; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
        <div style="padding: 20px; border-bottom: 1px solid #e0e0e0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px 8px 0 0;">
            <h4 style="margin: 0; font-weight: 600;">User Profile Details</h4>
            <span onclick="document.getElementById('user-details-modal').style.display='none'" style="float: right; margin-top: -30px; font-size: 28px; font-weight: bold; cursor: pointer; color: white;">&times;</span>
        </div>
        <div style="padding: 20px; max-height: 500px; overflow-y: auto;">
            <?php
            // Helper function to decode JWT tokens
            function decodeJWT($token) {
                if (!$token || !is_string($token)) return null;
                $parts = explode('.', $token);
                if (count($parts) === 3) {
                    $payload = base64_decode(strtr($parts[1], '-_', '+/'));
                    return json_decode($payload, true);
                }
                return null;
            }

            // Get session data
            $sessionData = $this->session->userdata();
            $keycloakAuth = $this->session->userdata('keycloak_auth');
            $keycloakTokens = $this->session->userdata('keycloak_tokens');
            $keycloakConfig = $this->config->item('keycloak');

            // Extract and decode ID token to get real-time exp/iat
            $idToken = null;
            if (isset($sessionData['id_token'])) {
                $idToken = $sessionData['id_token'];
            } elseif (isset($sessionData['keycloak_id_token'])) {
                $idToken = $sessionData['keycloak_id_token'];
            }

            // Extract and decode access token
            $accessToken = null;
            if (isset($sessionData['keycloak_tokens'])) {
                $tokens = $sessionData['keycloak_tokens'];
                if (is_array($tokens) && isset($tokens['access_token'])) {
                    $accessToken = $tokens['access_token'];
                } elseif (is_object($tokens) && isset($tokens->access_token)) {
                    $accessToken = $tokens->access_token;
                }
            }
            if (!$accessToken && isset($sessionData['access_token'])) {
                $accessToken = $sessionData['access_token'];
            } elseif (!$accessToken && isset($sessionData['keycloak_access_token'])) {
                $accessToken = $sessionData['keycloak_access_token'];
            }

            // Decode tokens to get fresh timestamps
            $idTokenPayload = decodeJWT($idToken);
            $accessTokenPayload = decodeJWT($accessToken);

            // Use decoded token data if available, fallback to keycloak_auth
            if ($idTokenPayload) {
                $keycloakAuth['iat'] = $idTokenPayload['iat'] ?? $keycloakAuth['iat'] ?? null;
                $keycloakAuth['exp'] = $idTokenPayload['exp'] ?? $keycloakAuth['exp'] ?? null;
            }

            if (!empty($keycloakAuth)):
                // Prepare Keycloak admin console URL
                $issuerUrl = $keycloakConfig['issuer'] ?? null;
                $adminConsoleUrl = null;
                if (!empty($issuerUrl)) {
                    // Convert issuer URL to admin console URL
                    // From: https://[server]/realms/master
                    // To:   https://[server]/admin/master/console
                    $adminConsoleUrl = str_replace('/realms/', '/admin/', $issuerUrl) . '/console';
                }
            ?>

            <!-- Edit User Section -->
            <?php if (!empty($adminConsoleUrl)): ?>
            <div style="margin-bottom: 20px; background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%); padding: 15px; border-radius: 8px; border: 1px solid #667eea30;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h5 style="color: #667eea; margin: 0 0 5px 0; font-weight: 600;">
                            <i class="feather icon-edit" style="font-size: 16px;"></i> Edit User
                        </h5>
                        <p style="margin: 0; font-size: 12px; color: #666;">
                            Manage user settings in Keycloak Admin Console
                        </p>
                    </div>
                    <div>
                        <a href="<?php echo htmlspecialchars($adminConsoleUrl); ?>"
                           target="_blank"
                           style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 13px; box-shadow: 0 2px 4px rgba(102,126,234,0.3); transition: transform 0.2s;"
                           onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 8px rgba(102,126,234,0.4)';"
                           onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 4px rgba(102,126,234,0.3)';">
                            <i class="feather icon-external-link" style="font-size: 12px;"></i>
                            Open Admin Console
                        </a>
                    </div>
                </div>
            </div>
            <?php endif; ?>

            <div style="margin-bottom: 20px;">
                <h5 style="color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 5px; margin-bottom: 15px;">Basic Information</h5>
                <table style="width: 100%; font-size: 14px;">
                    <tr style="border-bottom: 1px solid #f0f0f0;">
                        <td style="padding: 10px; width: 40%; color: #666;"><strong>Username:</strong></td>
                        <td style="padding: 10px;"><?php echo htmlspecialchars($keycloakAuth['username'] ?? 'N/A'); ?></td>
                    </tr>
                    <tr style="border-bottom: 1px solid #f0f0f0;">
                        <td style="padding: 10px; color: #666;"><strong>Full Name:</strong></td>
                        <td style="padding: 10px;"><?php echo htmlspecialchars($keycloakAuth['name'] ?? 'N/A'); ?></td>
                    </tr>
                    <tr style="border-bottom: 1px solid #f0f0f0;">
                        <td style="padding: 10px; color: #666;"><strong>Email:</strong></td>
                        <td style="padding: 10px;"><?php echo htmlspecialchars($keycloakAuth['email'] ?? 'N/A'); ?></td>
                    </tr>
                    <tr style="border-bottom: 1px solid #f0f0f0;">
                        <td style="padding: 10px; color: #666;"><strong>Email Verified:</strong></td>
                        <td style="padding: 10px;">
                            <?php if (!empty($keycloakAuth['email_verified'])): ?>
                                <span style="color: #28a745; font-weight: bold;">✓ Verified</span>
                            <?php else: ?>
                                <span style="color: #dc3545;">✗ Not Verified</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
            </div>

            <?php if (!empty($keycloakAuth['roles'])): ?>
            <div style="margin-bottom: 20px;">
                <h5 style="color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 5px; margin-bottom: 15px;">Roles & Permissions</h5>
                <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                    <?php foreach ($keycloakAuth['roles'] as $role): ?>
                    <span style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 500;">
                        <?php echo htmlspecialchars($role); ?>
                    </span>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>

            <div style="margin-bottom: 20px;">
                <h5 style="color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 5px; margin-bottom: 15px;">Session Information</h5>
                <table style="width: 100%; font-size: 14px;">
                    <tr style="border-bottom: 1px solid #f0f0f0;">
                        <td style="padding: 10px; width: 40%; color: #666;"><strong>Session Issued:</strong></td>
                        <td style="padding: 10px;"><?php echo !empty($keycloakAuth['iat']) ? date('Y-m-d H:i:s', $keycloakAuth['iat']) : 'N/A'; ?></td>
                    </tr>
                    <tr style="border-bottom: 1px solid #f0f0f0;">
                        <td style="padding: 10px; color: #666;"><strong>Session Expires:</strong></td>
                        <td style="padding: 10px;"><?php echo !empty($keycloakAuth['exp']) ? date('Y-m-d H:i:s', $keycloakAuth['exp']) : 'N/A'; ?></td>
                    </tr>
                    <tr style="border-bottom: 1px solid #f0f0f0;">
                        <td style="padding: 10px; color: #666;"><strong>Client ID:</strong></td>
                        <td style="padding: 10px;"><?php echo htmlspecialchars($keycloakAuth['azp'] ?? $keycloakConfig['client_id'] ?? 'N/A'); ?></td>
                    </tr>
                </table>
            </div>

            <?php if (ENVIRONMENT === 'development' && !empty($keycloakTokens)): ?>
            <div style="margin-bottom: 20px;">
                <h5 style="color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 5px; margin-bottom: 15px;">Token Info (Development Only)</h5>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #667eea;">
                    <p style="margin: 5px 0; font-size: 12px;">
                        <strong>Access Token:</strong>
                        <code style="word-break: break-all; background: #fff; padding: 2px 4px; border-radius: 3px; display: block; margin-top: 5px;">
                            <?php echo substr($keycloakTokens['access_token'] ?? '', 0, 80) . '...'; ?>
                        </code>
                    </p>
                    <p style="margin: 5px 0; font-size: 12px;">
                        <strong>Token Type:</strong>
                        <span style="background: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">
                            <?php echo htmlspecialchars($keycloakTokens['token_type'] ?? 'Bearer'); ?>
                        </span>
                    </p>
                    <?php if (!empty($keycloakAuth['iat'])): ?>
                    <p style="margin: 5px 0; font-size: 12px;">
                        <strong>Issued At:</strong>
                        <?php echo date('Y-m-d H:i:s', $keycloakAuth['iat']); ?>
                        <span style="color: #666; font-size: 10px;" id="modal-session-age" data-iat="<?php echo $keycloakAuth['iat']; ?>"></span>
                    </p>
                    <?php endif; ?>
                    <?php if (!empty($keycloakAuth['exp'])): ?>
                    <p style="margin: 5px 0; font-size: 12px;">
                        <strong>Expires At:</strong>
                        <?php echo date('Y-m-d H:i:s', $keycloakAuth['exp']); ?>
                        <span id="modal-token-countdown" data-exp="<?php echo $keycloakAuth['exp']; ?>"></span>
                    </p>
                    <?php elseif (isset($keycloakTokens['expires_in'])): ?>
                    <p style="margin: 5px 0; font-size: 12px;">
                        <strong>Expires In:</strong>
                        <span id="modal-token-countdown-relative" data-expires-in="<?php echo (int)$keycloakTokens['expires_in']; ?>"></span>
                    </p>
                    <?php endif; ?>
                    <?php if (!empty($keycloakTokens['refresh_token'])): ?>
                    <p style="margin: 5px 0; font-size: 12px;">
                        <strong>Refresh Token:</strong>
                        <span style="background: #17a2b8; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">Available</span>
                    </p>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

            <?php else: ?>
            <div style="padding: 20px; text-align: center; color: #999;">
                <p>No Keycloak authentication data available.</p>
            </div>
            <?php endif; ?>
        </div>
        <div style="padding: 15px 20px; border-top: 1px solid #e0e0e0; text-align: right; background: #f8f9fa; border-radius: 0 0 8px 8px;">
            <?php if (ENVIRONMENT === 'production'): ?>
            <a href="<?php echo !empty($keycloakConfig['issuer']) ? str_replace('/realms/', '/admin/', $keycloakConfig['issuer']) . '/console' : '#'; ?>" target="_blank" style="display: inline-block; background: #667eea; color: white; padding: 8px 20px; border-radius: 5px; text-decoration: none; margin-right: 10px;">
                <i class="feather icon-shield"></i> Open Keycloak Admin
            </a>
            <?php endif; ?>
            <button onclick="document.getElementById('user-details-modal').style.display='none'" style="background: #6c757d; color: white; border: none; padding: 8px 20px; border-radius: 5px; cursor: pointer;">Close</button>
        </div>
    </div>
</div>

<!-- Live Token Countdown Script -->
<script>
function updateModalCountdowns() {
    const now = Math.floor(Date.now() / 1000);

    // Update session age
    const sessionAge = document.getElementById('modal-session-age');
    if (sessionAge) {
        const iat = parseInt(sessionAge.getAttribute('data-iat'));
        const ageSeconds = now - iat;
        const hours = Math.floor(ageSeconds / 3600);
        const minutes = Math.floor((ageSeconds % 3600) / 60);
        const seconds = ageSeconds % 60;
        sessionAge.textContent = '(' + hours + 'h ' + minutes + 'm ' + seconds + 's ago)';
    }

    // Update token countdown
    const tokenCountdown = document.getElementById('modal-token-countdown');
    if (tokenCountdown) {
        const exp = parseInt(tokenCountdown.getAttribute('data-exp'));
        updateModalCountdownDisplay(tokenCountdown, exp, now);
    }

    // Update relative countdown (expires_in)
    const relativeCountdown = document.getElementById('modal-token-countdown-relative');
    if (relativeCountdown) {
        const expiresIn = parseInt(relativeCountdown.getAttribute('data-expires-in'));
        const diff = expiresIn;

        if (diff <= 0) {
            relativeCountdown.innerHTML = '<span style="color: #e74c3c; font-weight: bold;">EXPIRED</span>';
        } else {
            const hours = Math.floor(diff / 3600);
            const minutes = Math.floor((diff % 3600) / 60);
            const seconds = diff % 60;

            const parts = [];
            if (hours > 0) parts.push(hours + 'h');
            if (minutes > 0) parts.push(minutes + 'm');
            if (seconds > 0) parts.push(seconds + 's');

            relativeCountdown.innerHTML = diff + ' seconds <span style="color: #666; font-size: 10px;">(' + parts.join(' ') + ')</span>';
        }
    }
}

function updateModalCountdownDisplay(element, exp, now) {
    const diff = exp - now;

    if (diff <= 0) {
        element.innerHTML = ' <span style="color: #dc3545; font-size: 10px; font-weight: bold;">(EXPIRED)</span>';
        return;
    }

    const hours = Math.floor(diff / 3600);
    const minutes = Math.floor((diff % 3600) / 60);
    const seconds = diff % 60;

    const parts = [];
    if (hours > 0) parts.push(hours + 'h');
    if (minutes > 0) parts.push(minutes + 'm');
    if (seconds > 0) parts.push(seconds + 's');

    element.innerHTML = ' <span style="color: #28a745; font-size: 10px;">(expires in ' + parts.join(' ') + ')</span>';
}

// Update immediately when page loads
updateModalCountdowns();

// Update every second
setInterval(updateModalCountdowns, 1000);
</script>
```

**What it does:**
- Provides a detailed modal popup with comprehensive user information
- Displays:
  - Basic user information (username, full name, email, verification status)
  - Assigned roles and permissions (as styled badges)
  - Session information (issue time, expiry time, client ID)
  - **Development mode only**: Token details for debugging (access token snippet, token type, issue/expiry timestamps with **live countdown timers**)
- **Live token countdown**: JavaScript automatically updates the token expiry countdown every second, showing real-time remaining time
- **Session age tracking**: Displays how long ago the session was issued, updating in real-time
- **Token refresh compatibility**: Decodes JWT tokens directly to get fresh expiration times (instead of relying on cached session data), ensuring accuracy even after background token refreshes
- Provides link to Keycloak Admin Console
- Uses inline styles for portability (no external CSS dependencies)
- Responsive design with max-width for mobile compatibility

**Important Implementation Note:**

The modal **decodes JWT tokens directly** using the `decodeJWT()` helper function to extract real-time `iat` (issued at) and `exp` (expiration) timestamps. This is critical because:

1. **Token Refresh**: When tokens are refreshed (either manually or automatically), the actual JWT tokens in `keycloak_tokens` are updated, but the cached `keycloak_auth` session data may not be
2. **Accuracy**: Decoding the JWT ensures you always display the correct expiration time from the token itself, not stale cached data
3. **Consistency**: This matches the implementation in `home_simple.php`, ensuring consistent behavior across all views

Without this JWT decoding, the modal would show outdated expiration times that don't reflect token refreshes.

#### Customization Notes

**1. Styling:** The snippets use inline styles for portability. To customize:
- Replace inline styles with your CSS classes
- Adjust colors by changing hex values (e.g., `#667eea` to your brand color)
- Use your existing icon library (examples use Feather icons)

**2. Avatar Image:** Replace the avatar image path:
```php
<img src="<?php echo base_url(); ?>assets/images/avatar.png" class="img-radius" alt="User-Profile-Image">
```

**3. SIMSS Custom Data:** The snippets include support for custom SIMSS organizational data (`cabang`, `divisi`, `station`, `subdivisi`, `role`). If your application doesn't use these:
- Remove the `$simssData` references
- Keep only the standard Keycloak fields (`username`, `email`, `name`, `roles`)

**4. Environment-Specific Display:**
- Development mode shows all debug info (tokens, timestamps)
- Production mode shows cleaner, user-focused information
- Toggle using `ENVIRONMENT` constant

**5. Icon Libraries:** Examples use Feather Icons. Replace with your preferred icon library:
```php
<!-- Font Awesome example -->
<i class="fas fa-user"></i>

<!-- Bootstrap Icons example -->
<i class="bi bi-person"></i>
```

#### Integration Example for Different CI3 Templates

**For Bootstrap-based templates:**
```php
<!-- Add to navbar-nav -->
<ul class="navbar-nav ml-auto">
    <!-- User profile dropdown snippet goes here -->
</ul>
```

**For AdminLTE templates:**
```php
<!-- Add to navbar-custom-menu -->
<ul class="nav navbar-nav">
    <!-- User profile dropdown snippet goes here -->
</ul>
```

**For custom templates:**
Find your navigation/header partial and insert the dropdown snippet in the appropriate location.

#### Browser Compatibility

The UI components are compatible with:
- Modern browsers (Chrome, Firefox, Safari, Edge)
- Internet Explorer 11+ (with polyfills for flexbox)
- Mobile browsers (responsive design)

#### Dependencies

**Required:**
- Bootstrap 3/4 (for dropdown functionality)
- jQuery (for dropdown toggle)

**Optional:**
- Feather Icons or Font Awesome (for icons)

If you don't use Bootstrap dropdowns, you can implement the dropdown with vanilla JavaScript:
```javascript
<script>
document.querySelector('.dropdown-toggle').addEventListener('click', function() {
    this.nextElementSibling.classList.toggle('show');
});
</script>
```

## Keycloak Server Configuration

### 1. Create Realm

1. Login to Keycloak Admin Console
2. Create new realm: `simss`

### 2. Configure Client

1. Go to Clients > Create Client
2. Client ID: `simadis`
3. Client Protocol: `openid-connect`
4. Access Type: `confidential`
5. Standard Flow Enabled: `ON`
6. Valid Redirect URIs: `https://your-simadis-url.com/auth/callback`
7. Web Origins: `https://your-simadis-url.com`
8. Save and go to Credentials tab
9. Copy the Client Secret to your `keycloak.php` config

### 3. Configure User Attributes

For each user in Keycloak:

1. Go to Users > Select User > Attributes
2. Add custom attributes:
   - `kdcab`: Branch code (e.g., `CAB001`)
   - `inicab`: Store code (e.g., `STO001`)
   - `lvl`: User level (e.g., `admin`, `user`)

### 4. Create Protocol Mappers

For the `simadis` client:

1. Go to Clients > `simadis` > Client Scopes > `simadis-dedicated` > Add mapper

**For `kdcab`:**
- Mapper Type: `User Attribute`
- Name: `kdcab`
- User Attribute: `kdcab`
- Token Claim Name: `kdcab`
- Claim JSON Type: `String`
- Add to ID token: `ON`
- Add to access token: `ON`
- Add to userinfo: `ON`

**Repeat for `inicab` and `lvl`**

### 5. Migrate Existing Users

You can migrate users from the old `tss_msuser` table to Keycloak:

#### Option A: Manual Export/Import

1. Export users from database
2. Create users in Keycloak with matching attributes
3. Reset passwords (or use temporary passwords)

#### Option B: Scripted Migration

Create a migration script (`migrate_users.php`):

```php
<?php
require 'vendor/autoload.php';

// Connect to database
$db = new mysqli('localhost', 'user', 'pass', 'database');

// Fetch users
$result = $db->query("SELECT * FROM tss_msuser");

// Initialize Keycloak Admin Client
// (Use Keycloak Admin API to create users)

while ($user = $result->fetch_assoc()) {
    // Create user in Keycloak via API
    // Set attributes: kdcab, inicab, lvl
}
```

## Testing

### Test with Local Keycloak

1. Start test environment:
   ```bash
   cd application/third_party/keycloak-simss-connector/docker
   docker-compose up -d
   ```

2. Update config to point to local Keycloak:
   ```php
   'issuer' => 'http://localhost:8080/realms/simss',
   'verify_peer' => false,
   'verify_host' => false,
   ```

3. Test login with test users:
   - Username: `testuser` / Password: `password123`

### Test Authentication Flow

1. Visit `http://your-simadis/auth/login`
2. Should redirect to Keycloak
3. Login with credentials
4. Should redirect back to `auth/callback`
5. Then redirect to home page with session created

## Troubleshooting

### Issue: "Configuration error"

**Solution**: Ensure `application/config/keycloak.php` exists and has all required fields.

### Issue: Redirect loop

**Solution**: Check that the middleware is not applied to auth routes. The middleware should exclude `/auth/*` paths.

### Issue: "Invalid redirect URI"

**Solution**: Ensure the `redirect_uri` in config exactly matches one configured in Keycloak client settings (including trailing slashes).

### Issue: User attributes not appearing

**Solution**:
1. Verify attributes are set on the user in Keycloak
2. Verify protocol mappers are configured correctly
3. Check that mappers are added to ID token and userinfo

## Rollback Plan

If you need to rollback to the old authentication:

1. Restore old Auth controller:
   ```bash
   mv application/controllers/Auth.php.backup application/controllers/Auth.php
   ```

2. Update routes to use old controller

3. Remove middleware from controllers or hooks


## Support

For issues specific to this integration, check:
- Main README: `../README.md`
- Configuration Reference: `CONFIGURATION.md`
- Testing Guide: `TESTING.md`
