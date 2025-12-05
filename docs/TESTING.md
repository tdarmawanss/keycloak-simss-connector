# Testing Guide

Guide for running tests and setting up the test environment for the Keycloak SIMSS Connector.

## Prerequisites

- PHP 7.1 or higher
- Composer
- Docker and Docker Compose (for integration tests)

## Installation

Install development dependencies:

```bash
composer install --dev
```

## Running Tests

### Run All Tests

```bash
./vendor/bin/phpunit
```

### Run Specific Test Suites

**Unit tests only:**
```bash
./vendor/bin/phpunit --testsuite Unit
```

**Integration tests only:**
```bash
./vendor/bin/phpunit --testsuite Integration
```

### Run Specific Test File

```bash
./vendor/bin/phpunit tests/Unit/KeycloakConfigTest.php
```

### Run with Coverage Report

```bash
./vendor/bin/phpunit --coverage-html coverage
```

Then open `coverage/index.html` in your browser.

## Test Structure

```
tests/
├── bootstrap.php              # Test initialization
├── Unit/                      # Unit tests
│   ├── KeycloakConfigTest.php
│   └── SessionManagerTest.php
└── Integration/               # Integration tests
    └── AuthFlowTest.php
```

## Unit Tests

Unit tests test individual components in isolation without external dependencies.

### KeycloakConfigTest

Tests configuration loading, validation, and getters.

**Coverage:**
- Configuration validation
- Required field checking
- URL validation
- Default values
- Endpoint generation

**Run:**
```bash
./vendor/bin/phpunit tests/Unit/KeycloakConfigTest.php
```

### SessionManagerTest

Tests session management functionality.

**Coverage:**
- Session creation
- User data extraction
- Token management
- Session destruction
- Attribute mapping

**Run:**
```bash
./vendor/bin/phpunit tests/Unit/SessionManagerTest.php
```

## Integration Tests

Integration tests require a running Keycloak instance.

### Setup Test Environment

Start the test Keycloak server:

```bash
cd docker
docker-compose up -d
```

Wait for Keycloak to be ready (about 30 seconds):

```bash
docker-compose logs -f keycloak
```

Look for: `Keycloak ... started in ...`

### Verify Test Environment

Check Keycloak is accessible:

```bash
curl http://localhost:8080/realms/simss
```

Should return JSON with realm information.

### Test Data

The test environment includes:

**Realm**: `simss`

**Client**:
- Client ID: `simadis`
- Client Secret: `simadis-secret-key-change-in-production`

**Test Users**:

| Username | Password | Level | kdcab | inicab |
|----------|----------|-------|-------|--------|
| testuser | password123 | admin | CAB001 | STO001 |
| regularuser | password123 | user | CAB002 | STO002 |

### Run Integration Tests

```bash
./vendor/bin/phpunit --testsuite Integration
```

**Note**: Integration tests require the Docker test environment to be running.

## Writing Tests

### Unit Test Example

```php
<?php

namespace Simss\KeycloakAuth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Simss\KeycloakAuth\Config\KeycloakConfig;

class ExampleTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        KeycloakConfig::reset();
    }

    public function testSomething()
    {
        $config = KeycloakConfig::getInstance(TEST_CONFIG);
        $this->assertEquals('expected', $config->get('key'));
    }
}
```

### Integration Test Example

```php
<?php

namespace Simss\KeycloakAuth\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Simss\KeycloakAuth\Auth\KeycloakAuth;

class AuthFlowTest extends TestCase
{
    public function testAuthenticationFlow()
    {
        $config = [
            'issuer' => 'http://localhost:8080/realms/simss',
            'client_id' => 'simadis',
            'client_secret' => 'simadis-secret-key-change-in-production',
            'redirect_uri' => 'http://localhost/auth/callback',
            'verify_peer' => false,
            'verify_host' => false,
        ];

        $auth = new KeycloakAuth(KeycloakConfig::getInstance($config));

        // Test logic here
    }
}
```

## Mocking External Dependencies

For unit tests, mock the OpenID Connect client:

```php
use Mockery;

public function testWithMock()
{
    $mockOidc = Mockery::mock('Jumbojett\OpenIDConnectClient');
    $mockOidc->shouldReceive('authenticate')->andReturn(true);

    // Inject mock and test
}

protected function tearDown(): void
{
    Mockery::close();
    parent::tearDown();
}
```

## Manual Testing

### Test Authentication Flow

1. Start test Keycloak:
   ```bash
   cd docker
   docker-compose up -d
   ```

2. Configure test application with:
   ```php
   'issuer' => 'http://localhost:8080/realms/simss',
   'client_id' => 'simadis',
   'client_secret' => 'simadis-secret-key-change-in-production',
   'redirect_uri' => 'http://localhost:8000/auth/callback',
   'verify_peer' => false,
   'verify_host' => false,
   ```

3. Start PHP development server:
   ```bash
   php -S localhost:8000
   ```

4. Visit: `http://localhost:8000/auth/login`

5. Login with test credentials:
   - Username: `testuser`
   - Password: `password123`

6. Verify session data includes:
   ```php
   [
       'username' => 'testuser',
       'lvl' => 'admin',
       'kdcab' => 'CAB001',
       'inicab' => 'STO001',
   ]
   ```

### Test Logout Flow

1. After successful login, visit: `http://localhost:8000/auth/logout`

2. Should redirect to Keycloak logout

3. Session should be cleared

### Test Token Refresh

1. Login successfully

2. Wait for token to expire (or manually expire it)

3. Make authenticated request

4. Verify token is automatically refreshed

## Keycloak Admin Console

Access the admin console for debugging:

- URL: http://localhost:8080
- Username: `admin`
- Password: `admin`

**Useful for:**
- Viewing user sessions
- Checking token contents
- Modifying user attributes
- Viewing client events
- Debugging authentication issues

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      keycloak:
        image: quay.io/keycloak/keycloak:latest
        env:
          KEYCLOAK_ADMIN: admin
          KEYCLOAK_ADMIN_PASSWORD: admin
        ports:
          - 8080:8080
        options: --health-cmd="curl -f http://localhost:8080/health/ready" --health-interval=10s

    steps:
      - uses: actions/checkout@v2

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '7.4'
          extensions: curl, json

      - name: Install dependencies
        run: composer install --dev

      - name: Run tests
        run: ./vendor/bin/phpunit
```

## Troubleshooting Tests

### Keycloak not starting

**Issue**: Docker container exits immediately

**Solutions**:
- Check Docker logs: `docker-compose logs keycloak`
- Ensure port 8080 is not in use
- Increase Docker memory allocation

### Connection refused errors

**Issue**: Tests can't connect to Keycloak

**Solutions**:
- Verify Keycloak is running: `docker ps`
- Check Keycloak is healthy: `docker-compose ps`
- Wait longer for startup (30-60 seconds)
- Check firewall settings

### SSL verification errors

**Issue**: SSL certificate validation fails

**Solution**: Use `verify_peer: false` and `verify_host: false` for testing

### Session test failures

**Issue**: Session data not persisting

**Solutions**:
- Ensure session is started in `tests/bootstrap.php`
- Check `session.save_path` is writable
- Clear session data between tests

### Token expiry in tests

**Issue**: Tokens expire during test execution

**Solutions**:
- Use short test execution times
- Mock token expiry checks
- Configure longer token lifespans in test realm

## Test Coverage Goals

Target coverage levels:
- Overall: > 80%
- Core classes (Config, Auth, SessionManager): > 90%
- Controllers: > 70%

## Cleaning Up

### Stop Test Environment

```bash
cd docker
docker-compose down
```

### Remove Test Data

```bash
docker-compose down -v
```

### Clear Test Artifacts

```bash
rm -rf coverage/
rm -rf .phpunit.cache/
```

## Performance Testing

Test authentication performance:

```bash
# Install Apache Bench
apt-get install apache2-utils

# Test login endpoint
ab -n 100 -c 10 http://localhost:8000/auth/check
```

Expected performance:
- Configuration load: < 1ms
- Session check: < 5ms
- Full auth flow: < 500ms (including Keycloak roundtrip)

## Security Testing

### Test Invalid Configurations

Ensure proper error handling:
- Missing required fields
- Invalid URLs
- Incorrect credentials
- Expired tokens

### Test Session Security

Verify:
- Sessions are invalidated on logout
- Tokens are not exposed in logs
- CSRF protection works
- Session fixation is prevented

## Next Steps

- Add more integration tests for edge cases
- Set up automated testing in CI/CD pipeline
- Add performance benchmarks
- Test with real Keycloak production instance
