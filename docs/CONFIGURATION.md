# Configuration Reference

Complete reference for all configuration options in the Keycloak SIMSS Connector.

## Configuration File Location

### CodeIgniter Applications
`application/config/keycloak.php`

### Standalone PHP Applications
`config/keycloak.php` (in the connector directory)

## Required Configuration Options

### `issuer` (string, required)

The Keycloak realm URL that acts as the OpenID Connect issuer.

**Format**: `https://your-keycloak-server/realms/your-realm-name`

**Example**:
```php
'issuer' => 'https://keycloak.example.com/realms/simss'
```

### `client_id` (string, required)

The client identifier configured in Keycloak.

**Example**:
```php
'client_id' => 'simadis'
```

### `client_secret` (string, required)

The client secret from Keycloak.

**Location in Keycloak**: Clients > [Your Client] > Credentials tab

**Security Note**: Never commit this to version control. Use environment variables in production.

**Example**:
```php
'client_secret' => 'abc123-secret-key-xyz789'
```

### `redirect_uri` (string, required)

The callback URL where Keycloak redirects after authentication.

**Must Match**: Valid Redirect URIs in Keycloak client settings (exact match, including protocol and trailing slash)

**Example**:
```php
'redirect_uri' => 'https://your-app.com/auth/callback'
```

## Optional Configuration Options

### `scopes` (array, optional)

OAuth2/OIDC scopes to request during authentication.

**Default**: `['openid', 'profile', 'email']`

**Example**:
```php
'scopes' => ['openid', 'profile', 'email', 'offline_access']
```

**Available Scopes**:
- `openid` - Required for OIDC (always include this)
- `profile` - User profile information (name, username, etc.)
- `email` - Email address
- `offline_access` - Enables refresh tokens
- Custom scopes defined in Keycloak

### `token_endpoint` (string, optional)

Token endpoint URL.

**Default**: Auto-generated from `issuer`
**Auto-generated value**: `{issuer}/protocol/openid-connect/token`

**Example**:
```php
'token_endpoint' => 'https://keycloak.example.com/realms/simss/protocol/openid-connect/token'
```

### `userinfo_endpoint` (string, optional)

UserInfo endpoint URL.

**Default**: Auto-generated from `issuer`
**Auto-generated value**: `{issuer}/protocol/openid-connect/userinfo`

**Example**:
```php
'userinfo_endpoint' => 'https://keycloak.example.com/realms/simss/protocol/openid-connect/userinfo'
```

### `authorization_endpoint` (string, optional)

Authorization endpoint URL.

**Default**: Auto-generated from `issuer`
**Auto-generated value**: `{issuer}/protocol/openid-connect/auth`

**Example**:
```php
'authorization_endpoint' => 'https://keycloak.example.com/realms/simss/protocol/openid-connect/auth'
```

### `logout_endpoint` (string, optional)

Logout endpoint URL.

**Default**: Auto-generated from `issuer`
**Auto-generated value**: `{issuer}/protocol/openid-connect/logout`

**Example**:
```php
'logout_endpoint' => 'https://keycloak.example.com/realms/simss/protocol/openid-connect/logout'
```

### `verify_peer` (boolean, optional)

Enable SSL peer verification.

**Default**: `true`
**Production**: Must be `true`
**Development**: Can be `false` for self-signed certificates

**Example**:
```php
'verify_peer' => true
```

### `verify_host` (boolean, optional)

Enable SSL host verification.

**Default**: `true`
**Production**: Must be `true`
**Development**: Can be `false` for local testing

**Example**:
```php
'verify_host' => true
```

### `cert_path` (string, optional)

Path to CA certificate bundle for SSL verification.

**Default**: `null` (uses system default)

**Example**:
```php
'cert_path' => '/path/to/ca-bundle.crt'
```

### `http_proxy` (string, optional)

HTTP proxy server for outbound connections.

**Default**: `null`

**Example**:
```php
'http_proxy' => 'http://proxy.example.com:8080'
```

### `token_refresh_buffer` (integer, optional)

Seconds before token expiry to trigger a refresh. This prevents edge cases where a token expires mid-request.

**Default**: `60`

**Example**:
```php
'token_refresh_buffer' => 60
```

### `enable_silent_sso` (boolean, optional)

Enable silent SSO re-authentication when refresh token expires but SSO session is still valid.

**Default**: `true`

When enabled, users are seamlessly re-authenticated via Keycloak's SSO session without seeing a login page (as long as SSO session hasn't expired).

Disable for high-security apps that require explicit re-login after refresh token expiry.

**Example**:
```php
'enable_silent_sso' => false  // Force re-login after refresh token expires
```

## Token Duration Configuration (Keycloak Server)

Token lifetimes are configured **in Keycloak Admin Console**, not in this connector:

### Realm-Wide Defaults

**Keycloak Admin Console** → Realm Settings → Tokens

| Setting | Description | Typical Value |
|---------|-------------|---------------|
| Access Token Lifespan | How long access tokens are valid | 5 minutes |
| SSO Session Idle | Idle timeout for SSO session | 30 minutes |
| SSO Session Max | Maximum SSO session lifetime | 10 hours |

### Client-Specific Overrides

**Keycloak Admin Console** → Clients → [Your Client] → Advanced → Advanced Settings

| Setting | Description |
|---------|-------------|
| Access Token Lifespan | Override realm default for this client |
| Client Session Idle | Idle timeout for refresh token |
| Client Session Max | Maximum refresh token lifetime |

### Session Behavior Summary

| Time Since Login | What Happens | User Action Required |
|-----------------|--------------|---------------------|
| 0 - Access Token Lifespan | Access token valid | None |
| Access Token expired - Refresh Token valid | Auto-refresh | None |
| Refresh Token expired - SSO Session valid | Silent SSO (if enabled) | None (brief redirect) |
| SSO Session expired | Session fully expired | Re-enter credentials |

## Complete Configuration Example

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

return [
    // Required
    'issuer' => 'https://keycloak.example.com/realms/simss',
    'client_id' => 'simadis',
    'client_secret' => getenv('KEYCLOAK_CLIENT_SECRET'), // From environment variable
    'redirect_uri' => 'https://simadis.example.com/auth/callback',

    // Scopes (include offline_access for refresh tokens)
    'scopes' => ['openid', 'profile', 'email', 'offline_access'],

    // SSL (Production)
    'verify_peer' => true,
    'verify_host' => true,
    'cert_path' => '/etc/ssl/certs/ca-bundle.crt',

    // Token refresh settings
    'token_refresh_buffer' => 60,  // Refresh 60s before expiry
    'enable_silent_sso' => true,   // Auto re-auth via SSO session

    // Proxy (if needed)
    'http_proxy' => getenv('HTTP_PROXY'),
];
```

## Built-in Behavior (non-configurable defaults)

- **Role & group extraction**: Roles are collected from `roles`, `realm_access.roles`, and `resource_access.*.roles`. Groups are collected from `groups`. Both are stored in session (`roles`, `groups`), with `lvl` kept for backward compatibility (first role/group found).
- **Session storage**: Only the ID token is stored (for OIDC logout). Auth state is server-side via CI session.
- **Rate limiting**: Applied to `auth/login` (30 attempts / 60s) and `auth/callback` (60 attempts / 5m), per IP. Uses CI cache if available; falls back to PHP session.
- **Idle timeout notice**: When a session expires, a gentle notice is shown on the login page via flash message.

## Environment-Specific Configurations

### Development Configuration

```php
return [
    'issuer' => 'http://localhost:8080/realms/simss',
    'client_id' => 'simadis',
    'client_secret' => 'simadis-secret-key-change-in-production',
    'redirect_uri' => 'http://localhost:8000/auth/callback',
    'verify_peer' => false,  // Local testing only
    'verify_host' => false,  // Local testing only
];
```

### Production Configuration

```php
return [
    'issuer' => 'https://keycloak.production.com/realms/simss',
    'client_id' => 'simadis',
    'client_secret' => getenv('KEYCLOAK_CLIENT_SECRET'),
    'redirect_uri' => 'https://simadis.production.com/auth/callback',
    'verify_peer' => true,
    'verify_host' => true,
    'scopes' => ['openid', 'profile', 'email', 'offline_access'],
    'token_refresh_buffer' => 60,
    'enable_silent_sso' => true,
];
```

## Using Environment Variables

It's recommended to use environment variables for sensitive configuration:

### Using PHP `getenv()`

```php
return [
    'issuer' => getenv('KEYCLOAK_ISSUER'),
    'client_id' => getenv('KEYCLOAK_CLIENT_ID'),
    'client_secret' => getenv('KEYCLOAK_CLIENT_SECRET'),
    'redirect_uri' => getenv('KEYCLOAK_REDIRECT_URI'),
];
```

## Configuration Validation

The configuration is automatically validated when loaded. Errors will be thrown for:

- Missing required fields
- Invalid URL formats for `issuer` and `redirect_uri`
- Invalid data types

## Programmatic Configuration

You can also pass configuration directly to classes:

```php
use Simss\KeycloakAuth\Config\KeycloakConfig;

$config = KeycloakConfig::getInstance([
    'issuer' => 'https://keycloak.example.com/realms/simss',
    'client_id' => 'simadis',
    'client_secret' => 'secret',
    'redirect_uri' => 'https://app.com/callback',
]);
```

## Troubleshooting Configuration Issues

### Invalid issuer URL

**Error**: `Invalid issuer URL`

**Cause**: The `issuer` is not a valid URL

**Solution**: Ensure it starts with `http://` or `https://`

### Missing required configuration

**Error**: `Missing required configuration: client_id`

**Cause**: Required field is missing or empty

**Solution**: Add all required fields: `issuer`, `client_id`, `client_secret`, `redirect_uri`

### SSL verification errors

**Error**: `SSL certificate problem: unable to get local issuer certificate`

**Cause**: SSL verification is enabled but certificate validation fails

**Solutions**:
1. Set `verify_peer` and `verify_host` to `false` (development only)
2. Provide path to CA bundle via `cert_path`
3. Update system CA certificates

### Configuration not loading

**Cause**: Configuration file doesn't exist or has syntax errors

**Solutions**:
1. Check file exists at correct path
2. Verify PHP syntax (`php -l config/keycloak.php`)
3. Ensure file returns an array

## Security Best Practices

1. **Never commit secrets**: Add `keycloak.php` to `.gitignore`
2. **Use environment variables**: For production secrets
3. **Enable SSL verification**: Always in production
4. **Restrict file permissions**: `chmod 600 config/keycloak.php`
5. **Rotate secrets regularly**: Update client secrets periodically
6. **Use HTTPS**: For all production endpoints
