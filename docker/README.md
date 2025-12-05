# Docker Test Environment

This directory contains Docker configuration for running a local Keycloak server for testing.

## Quick Start

1. Start Keycloak:
   ```bash
   cd docker
   docker-compose up -d
   ```

2. Wait for Keycloak to be ready (check logs):
   ```bash
   docker-compose logs -f keycloak
   ```

3. Access Keycloak Admin Console:
   - URL: http://localhost:8080
   - Username: `admin`
   - Password: `admin`

4. Test realm `simss` will be available at:
   - Issuer URL: http://localhost:8080/realms/simss

## Pre-configured Test Data

### Client Configuration
- **Client ID**: `simadis`
- **Client Secret**: `simadis-secret-key-change-in-production`
- **Redirect URIs**: http://localhost/*, http://localhost:8000/*

### Test Users

#### Admin User
- Username: `testuser`
- Password: `password123`
- Attributes:
  - lvl: `admin`
  - kdcab: `CAB001`
  - inicab: `STO001`

#### Regular User
- Username: `regularuser`
- Password: `password123`
- Attributes:
  - lvl: `user`
  - kdcab: `CAB002`
  - inicab: `STO002`

## Custom Attributes

The realm is configured with custom attribute mappers for:
- `kdcab` - Branch code
- `inicab` - Store code
- `lvl` - User level/role

These attributes are included in ID tokens, access tokens, and userinfo endpoint.

## Stopping the Environment

```bash
docker-compose down
```

To remove volumes as well:
```bash
docker-compose down -v
```

## Integration with Tests

Configure your test application to use:

```php
[
    'issuer' => 'http://localhost:8080/realms/simss',
    'client_id' => 'simadis',
    'client_secret' => 'simadis-secret-key-change-in-production',
    'redirect_uri' => 'http://localhost:8000/auth/callback',
    'verify_peer' => false,  // For local testing only
    'verify_host' => false,  // For local testing only
]
```
