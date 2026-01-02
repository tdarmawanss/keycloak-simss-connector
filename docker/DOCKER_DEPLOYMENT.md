# Docker Deployment Guide for Keycloak with PTSS Theme

This guide covers building and deploying the custom Keycloak image with the PTSS theme to Azure.

## Table of Contents
- [Local Development](#local-development)
- [Building the Image](#building-the-image)
- [Azure Container Registry](#azure-container-registry)
- [Azure Deployment](#azure-deployment)

---

## Local Development

### Prerequisites
- Docker installed
- Docker Compose installed

### Quick Start

1. **Start Keycloak locally with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

2. **Access Keycloak:**
   - URL: http://localhost:8080
   - Admin Console: http://localhost:8080/admin
   - Username: `admin` (or value from .env)
   - Password: `admin` (or value from .env)

3. **Enable the PTSS theme:**
   - Login to Admin Console
   - Select your realm (or create a new one)
   - Go to Realm Settings → Themes
   - Set "Login theme" to `ptss_keycloak_theme`
   - Click Save

4. **Stop the containers:**
   ```bash
   docker-compose down
   ```

### Environment Variables

Copy `.env.example` to `.env` and update values:
```bash
cp .env.example .env
```

Edit `.env` with your credentials.

---

## Building the Image

### Development Build

```bash
docker build -t keycloak-ptss:dev -f Dockerfile .
```

### Production Build

```bash
docker build -t keycloak-ptss:latest -f Dockerfile.production .
```

### Test the Built Image

```bash
docker run -d \
  --name keycloak-test \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -e KC_HOSTNAME=localhost \
  -e KC_HTTP_ENABLED=true \
  keycloak-ptss:dev \
  start-dev
```

Access at http://localhost:8080

---

## Azure Deployment

### Option 1: Azure Container Instances (Simple)

```bash
# Set variables
CONTAINER_NAME="keycloak-ptss"
DNS_NAME_LABEL="your-keycloak-instance"

# Create container instance
az container create \
  --resource-group $RESOURCE_GROUP \
  --name $CONTAINER_NAME \
  --image $ACR_LOGIN_SERVER/keycloak-ptss:latest \
  --registry-username $ACR_NAME \
  --registry-password $(az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv) \
  --dns-name-label $DNS_NAME_LABEL \
  --ports 8080 443 \
  --environment-variables \
    KEYCLOAK_ADMIN=admin \
    KC_HOSTNAME=$DNS_NAME_LABEL.$LOCATION.azurecontainer.io \
    KC_PROXY=edge \
    KC_HTTP_ENABLED=true \
  --secure-environment-variables \
    KEYCLOAK_ADMIN_PASSWORD=YourSecurePassword123! \
  --cpu 2 \
  --memory 4
```

Access your Keycloak at: `http://$DNS_NAME_LABEL.$LOCATION.azurecontainer.io:8080`

### Option 2: Azure Container Apps (Recommended for Production)

#### Create Container Apps Environment

```bash
# Install the containerapp extension
az extension add --name containerapp --upgrade

# Create Container Apps environment
az containerapp env create \
  --name keycloak-env \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION
```

#### Create PostgreSQL Database

```bash
# Create PostgreSQL server
az postgres flexible-server create \
  --resource-group $RESOURCE_GROUP \
  --name keycloak-db-server \
  --location $LOCATION \
  --admin-user keycloakadmin \
  --admin-password 'YourSecureDBPassword123!' \
  --sku-name Standard_B2s \
  --tier Burstable \
  --version 15 \
  --storage-size 32

# Create database
az postgres flexible-server db create \
  --resource-group $RESOURCE_GROUP \
  --server-name keycloak-db-server \
  --database-name keycloak

# Configure firewall (allow Azure services)
az postgres flexible-server firewall-rule create \
  --resource-group $RESOURCE_GROUP \
  --name keycloak-db-server \
  --rule-name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0
```

#### Deploy Container App

```bash
# Get DB connection string
DB_HOST=$(az postgres flexible-server show --resource-group $RESOURCE_GROUP --name keycloak-db-server --query "fullyQualifiedDomainName" -o tsv)

# Create container app
az containerapp create \
  --name keycloak-ptss \
  --resource-group $RESOURCE_GROUP \
  --environment keycloak-env \
  --image $ACR_LOGIN_SERVER/keycloak-ptss:latest \
  --registry-server $ACR_LOGIN_SERVER \
  --registry-username $ACR_NAME \
  --registry-password $(az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv) \
  --target-port 8080 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 3 \
  --cpu 1.0 \
  --memory 2.0Gi \
  --env-vars \
    KC_DB=postgres \
    KC_DB_URL=jdbc:postgresql://$DB_HOST:5432/keycloak \
    KC_DB_USERNAME=keycloakadmin \
    KC_PROXY=edge \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true \
    KEYCLOAK_ADMIN=admin \
  --secrets \
    db-password=YourSecureDBPassword123! \
    admin-password=YourSecureAdminPassword123! \
  --env-vars \
    KC_DB_PASSWORD=secretref:db-password \
    KEYCLOAK_ADMIN_PASSWORD=secretref:admin-password
```

#### Get the Application URL

```bash
az containerapp show \
  --name keycloak-ptss \
  --resource-group $RESOURCE_GROUP \
  --query properties.configuration.ingress.fqdn \
  -o tsv
```

## Production Checklist

Before deploying to production:

- [ ] Update `KEYCLOAK_ADMIN_PASSWORD` with a strong password
- [ ] Configure SSL/TLS certificates
- [ ] Set `KC_HTTP_ENABLED=false` and use HTTPS only
- [ ] Configure proper database with backups
- [ ] Set up monitoring and logging
- [ ] Configure proper hostname with `KC_HOSTNAME`
- [ ] Review security settings
- [ ] Enable theme caching (remove cache-disable flags)
- [ ] Configure proper resource limits (CPU/Memory)
- [ ] Set up health checks and liveness probes

---

## Updating the Theme

When you update the theme files:

1. Rebuild the Docker image with a new version tag:
   ```bash
   docker build -t keycloak-ptss:v1.0.1 -f Dockerfile.production .
   ```

2. Tag and push to ACR:
   ```bash
   docker tag keycloak-ptss:v1.0.1 $ACR_LOGIN_SERVER/keycloak-ptss:v1.0.1
   docker push $ACR_LOGIN_SERVER/keycloak-ptss:v1.0.1
   ```

3. Update the container in Azure to use the new image version.

---

## Troubleshooting

### View Container Logs

**Container Instances:**
```bash
az container logs --resource-group $RESOURCE_GROUP --name $CONTAINER_NAME
```

**Container Apps:**
```bash
az containerapp logs show --name keycloak-ptss --resource-group $RESOURCE_GROUP
```

### Verify Theme is Loaded

1. Access Keycloak admin console
2. Go to Realm Settings → Themes
3. Check if `ptss_keycloak_theme` appears in the dropdown

### Common Issues

1. **Theme not appearing**: Ensure files are copied correctly in Dockerfile
2. **Permission errors**: Check file ownership in Dockerfile
3. **Startup failures**: Check logs for database connection issues
4. **SSL errors**: Configure `KC_PROXY=edge` when behind a load balancer

---

## Support

For issues with:
- **Keycloak**: https://www.keycloak.org/documentation
- **Azure Container Apps**: https://learn.microsoft.com/azure/container-apps/
- **Theme customization**: See themes/ptss_keycloak_theme/README.md
