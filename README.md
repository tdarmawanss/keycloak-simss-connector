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

This connector implements proper OAuth2/OIDC token management with **ID token-based session validation** for SSR applications.

### Understanding Token Types

| Token Type | Purpose | Used For | Expiry Checked |
|------------|---------|----------|----------------|
| **ID Token** | Authentication (who you are) | Session validation | ✅ Yes - determines session lifetime |
| **Access Token** | Authorization (API access) | External API calls | No - auto-refreshed |
| **Refresh Token** | Token renewal | Getting new tokens | When refresh fails |

**Key Principle**: Session validity is tied to **ID token expiry** (authentication), not access token expiry (authorization).

### Token Durations (Keycloak Server Configuration)

Token lifetimes are configured **in Keycloak Admin Console**, not in this connector:

1. **Keycloak Admin Console** → Realm Settings → Tokens (realm-wide defaults)
2. **Keycloak Admin Console** → Clients → [Your Client] → Advanced → Advanced Settings (client overrides)

| Token Type | Keycloak Setting | Typical Value | Notes |
|------------|-----------------|---------------|-------|
| ID Token | Access Token Lifespan | 5-15 minutes | Controls session lifetime |
| Access Token | Access Token Lifespan | 5 minutes | Auto-refreshed for APIs |
| Refresh Token | Client Session Idle / Max | 30 min / 10 hours | Used to renew tokens |
| SSO Session | SSO Session Idle / Max | 30 min / 10 hours | Keycloak SSO session |

### How Session Validation Works

When a user makes a request to a protected route:

1. **AuthMiddleware** checks if ID token is expired
2. **If ID token valid** → Request proceeds
3. **If ID token expired** → Automatic token refresh:
   - Attempts refresh using refresh token (gets new ID + access + refresh tokens)
   - If refresh succeeds → User stays authenticated
   - If refresh fails → Attempts silent SSO re-authentication
   - If both fail → Session destroyed, redirect to login

**What gets stored in session:**
```php
$_SESSION['keycloak_tokens'] = [
    'id_token' => '...',              // JWT token for authentication
    'id_token_expires_at' => 1234567, // Unix timestamp (from JWT exp claim)
    'access_token' => '...',          // For API calls
    'access_token_expires_at' => 123, // Unix timestamp
    'refresh_token' => '...',         // For token renewal
];
```

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

    // Available fields:
    // - username: User's preferred username
    // - lvl: User level (for backward compatibility)
    // - nama: Full name
    // - email: Email address
    // - simss: Organizational attributes (see below)
    // - iat, exp, sub: Token metadata
    // - logged_in: Authentication status

    // Access SIMSS organizational attributes
    $simss = $userData['simss'];
    // - cabang: Branch codes (array)
    // - role: User roles (array)
    // - divisi: Division codes (array)
    // - station: Station codes (array)
    // - subdivisi: Subdivision codes (array)

    // Helper methods
    $roles = $sessionManager->getRoles();        // Returns simss.role
    $simssData = $sessionManager->getSimssData(); // Returns all simss attributes
}
```

**Note:** `roles`, `groups`, `kdcab`, and `inicab` have been removed from the top-level session structure. Use `simss` object for organizational data.

## Recent Changes & Migration

### Session Structure Changes

**What Changed:**
- Removed top-level `roles`, `groups`, `kdcab`, `inicab` fields from session
- All organizational data now nested under `simss` object
- `SessionManager::getRoles()` now returns `simss.role` (not top-level `roles`)
- `SessionManager::getGroups()` deprecated (returns empty array)

**Migration:**

```php
// ❌ Old (no longer works)
$roles = $sessionData['roles'];
$kdcab = $sessionData['kdcab'];

// ✅ New (use simss object)
$roles = $sessionData['simss']['role'];
$cabang = $sessionData['simss']['cabang'];

// ✅ Or use helper methods
$roles = $sessionManager->getRoles();          // Returns simss.role
$simssData = $sessionManager->getSimssData();  // Returns all simss attributes
```

### Token Management Changes

**What Changed:**
- Session validation now uses **ID token expiry** (was: access token expiry)
- Token refresh now includes `scope=openid` to ensure new ID token is returned
- `SessionManager::isTokenExpired()` checks ID token expiry, not access token
- Tokens are now stored with separate expiry fields (`id_token_expires_at`, `access_token_expires_at`)

**Why This Matters:**
- **ID tokens** prove authentication (who you are) → controls session lifetime
- **Access tokens** prove authorization (API access) → refreshed automatically
- This aligns with OIDC best practices for SSR applications

**No code changes required** - token refresh happens automatically. Your session lifetime is now correctly tied to authentication validity.

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
