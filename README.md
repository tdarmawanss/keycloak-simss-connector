# Keycloak SIMSS Connector

A shared authentication module for SIMSS applications using Keycloak and OpenID Connect (OIDC).

## Features

- Complete OIDC authentication flow
- Ready-to-use authentication controller
- Session management compatible with CodeIgniter
- Token refresh mechanism
- Route protection middleware
- Comprehensive test suite
- Docker-based test environment

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
