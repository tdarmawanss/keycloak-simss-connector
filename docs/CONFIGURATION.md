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

    // Optional
    'scopes' => ['openid', 'profile', 'email', 'offline_access'],

    // SSL (Production)
    'verify_peer' => true,
    'verify_host' => true,
    'cert_path' => '/etc/ssl/certs/ca-bundle.crt',

    // Proxy (if needed)
    'http_proxy' => getenv('HTTP_PROXY'),
];
```

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

### Environment File (.env)

```env
KEYCLOAK_ISSUER=https://keycloak.example.com/realms/simss
KEYCLOAK_CLIENT_ID=simadis
KEYCLOAK_CLIENT_SECRET=your-secret-here
KEYCLOAK_REDIRECT_URI=https://your-app.com/auth/callback
```

### Using CodeIgniter .env (CI 4+) or dotenv library

Install `vlucas/phpdotenv`:
```bash
composer require vlucas/phpdotenv
```

In `index.php` or bootstrap:
```php
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();
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
