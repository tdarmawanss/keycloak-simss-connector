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

### Token Durations (Keycloak Server Configuration)

Token lifetimes are configured **in Keycloak Admin Console**, not in this connector:

1. **Keycloak Admin Console** → Realm Settings → Tokens (realm-wide defaults)
2. **Keycloak Admin Console** → Clients → [Your Client] → Advanced → Advanced Settings (client overrides)

| Token Type | Keycloak Setting | Typical Value |
|------------|-----------------|---------------|
| Access Token | Access Token Lifespan | 5 minutes |
| Refresh Token | Client Session Idle / Max | 30 minutes / 10 hours |
| SSO Session | SSO Session Idle / Max | 30 minutes / 10 hours |

### How Sessions Work

When a user logs in, three things are created:

1. **Access Token** - Used to fetch user info from Keycloak
2. **Refresh Token** - Used to get new access tokens without re-login
3. **SSO Session** - Keycloak's single sign-on session

Your app session is automatically managed based on these token lifetimes.

### Connector-Side Configuration

This connector provides two options to control token refresh behavior:

```php
// Refresh N seconds before token expiry (default: 60)
'token_refresh_buffer' => 60,

// Enable/disable silent SSO re-authentication (default: true)
'enable_silent_sso' => true,
```

Enable refresh tokens by adding `offline_access` scope:

```php
'scopes' => ['openid', 'profile', 'email', 'offline_access'],
```

For complete configuration options, see [Configuration Reference](docs/CONFIGURATION.md).

## Quick Start

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

### 3. Configure

```bash
cp application/third_party/keycloak-simss-connector/config/keycloak.example.php \
   application/config/keycloak.php
```

Edit `application/config/keycloak.php` with your Keycloak settings. See [Configuration Reference](docs/CONFIGURATION.md) for all options.

### 4. Set Up Routes & Controller

See [Integration Guide](docs/INTEGRATION.md) for complete step-by-step setup including routes, controller wrapper, and route protection.

## Usage

### Basic Authentication Flow

1. User visits `/auth/login`
2. Redirected to Keycloak login page
3. After successful login, redirected to `/auth/callback`
4. Session created with user information
5. Redirected to home page

### Protecting Routes

```php
class Dashboard extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();
        $middleware = new \Simss\KeycloakAuth\Middleware\AuthMiddleware();
        $middleware->requireAuth();
    }
}
```

For global route protection using hooks, role-based access, and attribute-based access control, see [Integration Guide](docs/INTEGRATION.md).

### Accessing User Information

```php
$sessionManager = new \Simss\KeycloakAuth\Auth\SessionManager();

if ($sessionManager->isAuthenticated()) {
    $userData = $sessionManager->getSessionData();
    // username, lvl, nama, kdcab, inicab, email, roles, groups, logged_in
}
```

## Keycloak Server Setup

See [Integration Guide - Keycloak Server Configuration](docs/INTEGRATION.md#keycloak-server-configuration) for:

- Creating the realm and client
- Configuring user attributes (`kdcab`, `inicab`, `lvl`)
- Setting up protocol mappers
- Configuring token lifetimes

See `docker/realm-export.json` for a complete example configuration.

## Docker Image

This repository includes a custom Keycloak Docker image with the PTSS theme pre-installed.

### Building and Pushing to GitHub Container Registry

The image is automatically built and pushed using GitHub Actions:

1. Go to **Actions** tab in your GitHub repository
2. Select **Build and Push Docker Image** workflow
3. Click **Run workflow**
4. Optionally specify a custom tag (default: `latest`)
5. Click **Run workflow**

The image will be available at: `ghcr.io/<your-org>/keycloak-simss-connector`

### Pulling the Image

```bash
# Pull the latest image
docker pull ghcr.io/<your-org>/keycloak-simss-connector:latest

# Pull a specific version
docker pull ghcr.io/<your-org>/keycloak-simss-connector:v1.0.0
```

### Running the Image

```bash
docker run -d \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  ghcr.io/<your-org>/keycloak-simss-connector:latest \
  start-dev
```

For production deployment with proper database and configuration, see [Testing Guide](docs/TESTING.md).

## Testing

```bash
cd application/third_party/keycloak-simss-connector
composer install --dev
./vendor/bin/phpunit
```

For Docker test environment and integration testing, see [Testing Guide](docs/TESTING.md).

## Security Notes

- Always use HTTPS in production
- Enable SSL verification (`verify_peer` and `verify_host`)
- Keep client secrets secure (use environment variables)
- Tokens stored server-side only, never exposed to browser
- CSRF protection via state parameter on all auth flows

## Documentation

| Document | Description |
|----------|-------------|
| [Integration Guide](docs/INTEGRATION.md) | Step-by-step setup, route protection, role-based access |
| [Configuration Reference](docs/CONFIGURATION.md) | All configuration options with examples |
| [Testing Guide](docs/TESTING.md) | Running tests, Docker environment, troubleshooting |

## License

GPL-3.0
