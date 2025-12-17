# Keycloak PTSS Development Environment

This directory contains everything needed to run Keycloak with the PTSS custom theme for local development and testing.

## Quick Start

```bash
cd docker
docker compose up -d
```

Wait for Keycloak to be ready (check logs):
```bash
docker compose logs -f keycloak
```

Access Keycloak at: http://localhost:8080
- **Admin Console**: http://localhost:8080/admin
- **Username**: `admin`
- **Password**: `admin`

Test realm `simss` will be available at:
- **Issuer URL**: http://localhost:8080/realms/simss

## What's Included

### Services
1. **Keycloak** (ports 8080, 8443)
   - Custom PTSS theme pre-installed and auto-loaded
   - Realm configuration auto-imported from `realm-export.json`
   - Theme hot-reload enabled (changes reflect immediately)
   - Development mode with caching disabled

2. **PostgreSQL** (port 5432)
   - Persistent data storage
   - Database: `keycloak`
   - Username: `keycloak`
   - Password: `keycloak`

## Files Structure

- `docker-compose.yml` - Main orchestration file for development
- `Dockerfile` - Custom Keycloak image with PTSS theme
- `Dockerfile.production` - Optimized production build
- `realm-export.json` - Realm configuration (auto-imported on startup)
- `.env.example` - Example environment variables (copy to `.env`)
- `.dockerignore` - Files to exclude from Docker builds
- `DOCKER_DEPLOYMENT.md` - Detailed deployment documentation

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

### Custom Attributes

The realm is configured with custom attribute mappers for:
- `kdcab` - Branch code
- `inicab` - Store code
- `lvl` - User level/role

These attributes are included in ID tokens, access tokens, and userinfo endpoint.

## Docker Commands

### Start Services
```bash
docker compose up -d
```

### View Logs
```bash
docker compose logs -f           # All services
docker compose logs -f keycloak  # Keycloak only
docker compose logs -f postgres  # PostgreSQL only
```

### Stop Services
```bash
docker compose down
```

### Stop and Remove All Data
```bash
docker compose down -v
```

### Rebuild After Changes
Theme changes should auto-reload, but if you modify Dockerfile or need fresh build:
```bash
docker compose up -d --build
```

### Access PostgreSQL
```bash
docker compose exec postgres psql -U keycloak -d keycloak
```

## Environment Variables

Create a `.env` file in this directory to customize settings (see `.env.example`):

```bash
# Admin Credentials
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin

# Database
KC_DB_PASSWORD=keycloak

# Hostname (use your domain for external access)
KC_HOSTNAME=localhost

# Logging (debug, info, warn, error)
KC_LOG_LEVEL=info
```

## Development Features

- **Theme Cache Disabled**: Changes to theme CSS/templates reflect immediately
- **Hot Reload**: Theme files are mounted as volume for instant updates without rebuild
- **Realm Auto-Import**: Your realm configuration from `realm-export.json` loads automatically
- **Health Checks**: Ensures services are ready before dependencies start
- **PostgreSQL**: More realistic than in-memory database, data persists between restarts
- **Theme Volume Mount**: Edit theme files and see changes without container rebuild

## Integration with Your Application

Configure your application to use this local Keycloak instance:

```php
[
    'issuer' => 'http://localhost:8080/realms/simss',
    'client_id' => 'simadis',
    'client_secret' => 'simadis-secret-key-change-in-production',
    'redirect_uri' => 'http://localhost:8000/auth/callback',
    'verify_peer' => false,  // For local testing only - ENABLE in production
    'verify_host' => false,  // For local testing only - ENABLE in production
]
```

## Troubleshooting

### Keycloak won't start
Check the logs for errors:
```bash
docker compose logs keycloak
```

### Port already in use (8080 conflict)
Change ports in `docker-compose.yml`:
```yaml
ports:
  - "8081:8080"  # Use 8081 instead of 8080
```
Then access at http://localhost:8081

### Database connection errors
Ensure PostgreSQL is running:
```bash
docker compose ps
docker compose logs postgres
```

### Theme changes not showing
1. Clear browser cache (hard refresh: Ctrl+Shift+R or Cmd+Shift+R)
2. Verify theme is mounted correctly:
   ```bash
   docker compose exec keycloak ls -la /opt/keycloak/themes/ptss_keycloak_theme
   ```
3. Check theme caching is disabled in logs
4. Restart Keycloak:
   ```bash
   docker compose restart keycloak
   ```

### Realm not imported
1. Check realm file exists: `ls -la realm-export.json`
2. Check container logs: `docker compose logs keycloak | grep import`
3. Manually import via Admin Console if needed

### Reset Everything
Complete clean restart:
```bash
docker compose down -v
docker compose up -d --build
```

This removes all data including database and forces a fresh build.

## Production Deployment

For production deployment instructions, see `DOCKER_DEPLOYMENT.md`.

Key differences for production:
- Use `Dockerfile.production` for optimized build
- Enable HTTPS with proper certificates
- Use strong passwords and secrets
- Enable hostname strict checking
- Configure proper database backups
- Use environment-specific realm configuration

## How It Works

### Dockerfile and docker-compose.yml Relationship

**Dockerfile** (`docker/Dockerfile`):
- Defines how to BUILD a custom Keycloak image
- Starts from official Keycloak base image
- Copies PTSS custom theme into the image
- Sets permissions and optimizes the build
- Creates a reusable image with your theme baked in

**docker-compose.yml** (`docker/docker-compose.yml`):
- Defines how to RUN and ORCHESTRATE services
- Uses the Dockerfile to build custom Keycloak image
- Configures Keycloak and PostgreSQL containers
- Sets up networking between services
- Manages volumes for data persistence
- Defines environment variables and ports

When you run `docker compose up`:
1. Builds custom Keycloak image using Dockerfile
2. Pulls PostgreSQL image
3. Creates network for services to communicate
4. Starts PostgreSQL and waits for it to be ready
5. Starts Keycloak connected to PostgreSQL
6. Imports realm configuration
7. Makes services available on configured ports
