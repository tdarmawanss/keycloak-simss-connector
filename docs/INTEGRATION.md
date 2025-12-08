# SIMADIS Integration Guide

This guide walks through integrating the Keycloak SIMSS Connector into the SIMADIS application.

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

class AuthKeycloak extends AuthController
{
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Override to customize home redirect
     */
    protected function getHomeUrl()
    {
        return base_url('home');
    }
}
```

### Step 6: Update Routes

Edit `application/config/routes.php` and add:

```php
// Keycloak authentication routes
$route['auth'] = 'AuthKeycloak/index';
$route['auth/login'] = 'AuthKeycloak/login';
$route['auth/callback'] = 'AuthKeycloak/callback';
$route['auth/logout'] = 'AuthKeycloak/logout';
$route['auth/check'] = 'AuthKeycloak/check';
```

### Step 7: Replace Old Auth Controller (Optional)

You can keep the old `Auth.php` as a backup and gradually migrate:

```bash
mv application/controllers/Auth.php application/controllers/Auth.php.backup
```

Then create a new `application/controllers/Auth.php` that redirects to Keycloak:

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

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

This will enforce authentication globally, preserve the intended URL for redirect after login, and surface a gentle “session expired” notice on the login page when a session times out.

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

### Step 11: (Optional) Rate Limiting

`AuthController` applies a lightweight IP-based rate limit on `auth/login` (30 attempts / 60s) and `auth/callback` (60 attempts / 5m). It uses the CI cache driver if available, falling back to PHP session storage. No extra setup is required, but you can tune these limits in code if needed.

### Step 9: Update Views to Use New Session Data

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

### Step 10: Access User Information

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

### Step 11: Update Existing Session Checks

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

## Next Steps

1. Set up SSL certificates for production
2. Configure proper Keycloak realm for production
3. Migrate all users to Keycloak
4. Remove old password hash logic from database
5. Set up monitoring and logging
6. Configure token lifespans appropriately

## Support

For issues specific to this integration, check:
- Main README: `../README.md`
- Configuration Reference: `CONFIGURATION.md`
- Testing Guide: `TESTING.md`
