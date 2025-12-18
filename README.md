# Keycloak SIMSS Connector

A shared authentication module for SIMSS applications using Keycloak and OpenID Connect (OIDC).

## Features

- Complete OIDC authentication flow
- Ready-to-use authentication controller
- Session management compatible with CodeIgniter
- Automatic token refresh with silent SSO re-authentication
- Route protection middleware
- Comprehensive test suite
- Docker-based test environment

## Token Management & Session Lifecycle

This connector implements proper OAuth2/OIDC token management to ensure your app session lifetime never exceeds Keycloak's token lifetimes.

### How Sessions Work

When a user logs in, three things are created:

1. **Access Token** (5 minutes) - Used to fetch user info from Keycloak
2. **Refresh Token** (30 minutes) - Used to get new access tokens without re-login
3. **SSO Session** (10 hours) - Keycloak's single sign-on session

Your app session is automatically managed based on these token lifetimes.

### Automatic Token Refresh

When the access token expires (every 5 minutes), the middleware automatically refreshes it using the refresh token. This happens silently in the background - users never notice.

**User Experience**: User keeps working normally, no interruption.

### Silent SSO Re-Authentication

When the refresh token expires (after 30 minutes), the app can't refresh anymore. But if the user's Keycloak SSO session is still valid (10-hour lifetime), the connector uses **Silent SSO** to automatically re-authenticate without asking for credentials.

#### How Silent SSO Works

1. **Refresh token expires** (30 minutes after login)
2. **App redirects to Keycloak** with `prompt=none` parameter
3. **Keycloak checks SSO session cookie**:
   - **If SSO valid**: Returns new authorization code (no login page shown)
   - **If SSO expired**: Returns `login_required` error
4. **If successful**: App exchanges code for fresh tokens, user continues seamlessly
5. **If failed**: User sees "Session expired" and must re-login

#### User Experience Examples

**Active User (within 10 hours)**:
```
0:00  - Login with username/password
0:05  - Access token expires → auto-refresh (invisible)
0:30  - Refresh token expires → silent SSO (1-second flicker)
1:00  - Another silent SSO (if still active)
10:00 - SSO session expires → must re-login
```

**User Returns After Lunch (45 minutes away)**:
```
0:00 - Login and use app
0:35 - Close laptop, go to lunch
1:20 - Return and click something
     → Silent SSO triggers automatically
     → User continues working (no password needed)
```

**User Returns Next Day (16 hours away)**:
```
Day 1, 17:00 - Login and close laptop
Day 2, 09:00 - Open laptop and click something
             → SSO session expired (10-hour limit)
             → User must enter username/password
```

### Session Expiry Behavior

| Time Since Login | What Happens | User Action Required |
|-----------------|--------------|---------------------|
| 0-5 minutes | Access token valid | None - seamless |
| 5-30 minutes | Auto-refresh access token | None - seamless |
| 30 min - 10 hours | Silent SSO re-authentication | None - tiny redirect flicker |
| After 10 hours | SSO session expired | Re-enter username/password |

### Configuration

Enable refresh tokens by adding `offline_access` scope:

```php
'scopes' => ['openid', 'profile', 'email', 'offline_access'],
```

**Optional Configuration**:

```php
// Refresh 60 seconds before token expiry (prevents edge cases)
'token_refresh_buffer' => 60,

// Enable/disable silent SSO re-authentication
'enable_silent_sso' => true,  // Default: true
```

**Disable Silent SSO** (force re-login after 30 minutes for high-security apps):
```php
'enable_silent_sso' => false,
```

### Security Notes

- **Tokens stored server-side only** - Never exposed to the browser
- **CSRF protection** - State parameter validates all authentication flows
- **SSO session protection** - Keycloak manages SSO session security
- **Automatic cleanup** - Tokens cleared on logout

For more details, see [CONFIGURATION.md](docs/CONFIGURATION.md).

## Installation

### 1. Add as Git Submodule

```bash
cd your-application
git submodule add <repository-url> application/third_party/keycloak-simss-connector
git submodule update --init --recursive
```

### 2. Install Dependencies

```bash
cd application/third_party/keycloak-simss-connector
composer install
```

### 3. Configure Autoloading (CodeIgniter)

Edit `application/config/config.php`:

```php
$config['composer_autoload'] = APPPATH . 'third_party/keycloak-simss-connector/vendor/autoload.php';
```

## Configuration

### 1. Create Configuration File

Copy the example configuration:

```bash
cp application/third_party/keycloak-simss-connector/config/keycloak.example.php \
   application/config/keycloak.php
```

### 2. Configure Keycloak Settings

Edit `application/config/keycloak.php`:

```php
return [
    'issuer' => 'https://your-keycloak-server/realms/simss',
    'client_id' => 'your-client-id',
    'client_secret' => 'your-client-secret',
    'redirect_uri' => 'https://your-app.com/auth/callback',
    'verify_peer' => true,
    'verify_host' => true,
];
```

### 3. Set Up Routes

Edit `application/config/routes.php`:

```php
$route['auth'] = 'AuthKeycloak/index';
$route['auth/login'] = 'AuthKeycloak/login';
$route['auth/callback'] = 'AuthKeycloak/callback';
$route['auth/logout'] = 'AuthKeycloak/logout';
$route['auth/check'] = 'AuthKeycloak/check';
$route['auth/refresh'] = 'AuthKeycloak/refresh';
```

### 4. Create Controller Wrapper

Create `application/controllers/AuthKeycloak.php`:

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

require_once APPPATH . 'third_party/keycloak-simss-connector/vendor/autoload.php';

class AuthKeycloak extends Simss\KeycloakAuth\Controllers\AuthController
{
    public function __construct()
    {
        parent::__construct();
    }
}
```

## Usage

### Basic Authentication Flow

1. User visits `/auth/login`
2. Redirected to Keycloak login page
3. After successful login, redirected to `/auth/callback`
4. Session created with user information
5. Redirected to home page

### Protecting Routes

#### Option 1: Using Middleware in Controller

```php
class Dashboard extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();

        // Require authentication
        $middleware = new \Simss\KeycloakAuth\Middleware\AuthMiddleware();
        $middleware->requireAuth();
    }
}
```

#### Option 2: Using CodeIgniter Hooks

Edit `application/config/hooks.php`:

```php
$hook['post_controller_constructor'] = [
    'class' => 'Simss\KeycloakAuth\Middleware\AuthMiddleware',
    'function' => 'check',
    'filename' => '',
    'filepath' => '',
];
```

### Accessing User Information

```php
$sessionManager = new \Simss\KeycloakAuth\Auth\SessionManager();

// Check if authenticated
if ($sessionManager->isAuthenticated()) {
    // Get user data
    $userData = $sessionManager->getSessionData();
    $username = $userData['username'];
    $level = $userData['lvl'];
    $name = $userData['nama'];

    // Or get specific attributes
    $email = $sessionManager->getUserAttribute('email');
}
```

### Session Data Structure

The module creates a session with the following structure (compatible with existing SIMSS apps):

```php
[
    'username' => 'john.doe',
    'lvl' => 'admin',
    'nama' => 'John Doe',
    'kdcab' => 'CAB001',
    'inicab' => 'STO001',
    'email' => 'john.doe@example.com',
    'logged_in' => true,
]
```

## Keycloak Configuration

### 1. Create Realm

Create a realm named `simss` in your Keycloak instance.

### 2. Create Client

1. Go to Clients > Create Client
2. Set Client ID (e.g., `simadis`)
3. Enable Client Authentication
4. Set Valid Redirect URIs (e.g., `https://your-app.com/auth/callback`)
5. Copy Client Secret from Credentials tab

### 3. Configure User Attributes

Add custom user attributes in Keycloak:

1. Go to Users > User > Attributes
2. Add attributes:
   - `kdcab` - Branch code
   - `inicab` - Store code
   - `lvl` - User level

### 4. Create Protocol Mappers

For each custom attribute, create a User Attribute mapper:

1. Go to Client > Client Scopes > dedicated scope > Add mapper
2. Mapper Type: User Attribute
3. User Attribute: `kdcab` (or `inicab`, `lvl`)
4. Token Claim Name: Same as attribute name
5. Add to ID token, access token, and userinfo

See `docker/realm-export.json` for a complete example configuration.

## Testing

### Run Unit Tests

```bash
cd application/third_party/keycloak-simss-connector
composer install --dev
./vendor/bin/phpunit
```

### Start Test Environment

```bash
cd docker
docker-compose up -d
```

Test users:
- Username: `testuser`, Password: `password123` (admin)
- Username: `regularuser`, Password: `password123` (user)

Access Keycloak Admin: http://localhost:8080 (admin/admin)

## Security Notes

1. Always use HTTPS in production
2. Enable SSL verification (`verify_peer` and `verify_host`)
3. Keep client secrets secure (use environment variables)
4. Set appropriate token lifespans in Keycloak
5. Implement CSRF protection on callback endpoints
6. Use secure, httpOnly cookies for session storage

## Troubleshooting

### "Configuration error" on login
- Check that `application/config/keycloak.php` exists and has correct values
- Verify Keycloak server is accessible

### "Authentication failed"
- Check redirect URI matches exactly in Keycloak client settings
- Verify client secret is correct
- Check Keycloak server logs

### "Failed to get user info"
- Verify user has necessary attributes configured
- Check protocol mappers are set up correctly

### Token expiry issues
- Adjust token lifespan in Keycloak client settings
- Ensure refresh token flow is working

## Documentation

- [Integration Guide](docs/INTEGRATION.md) - Detailed integration instructions
- [Configuration Reference](docs/CONFIGURATION.md) - All configuration options
- [Testing Guide](docs/TESTING.md) - Running tests and test environment

## License

GPL-3.0
