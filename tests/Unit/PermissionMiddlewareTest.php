<?php

namespace Simss\KeycloakAuth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Simss\KeycloakAuth\Middleware\PermissionMiddleware;
use Simss\KeycloakAuth\Auth\SessionManager;
use Simss\KeycloakAuth\Config\KeycloakConfig;

/**
 * Unit tests for PermissionMiddleware class
 *
 * Tests Role-Based Access Control (RBAC) functionality including:
 * - Endpoint permission validation
 * - Role-module-CRUD permission checking
 * - Config file loading and caching
 * - Access denial handling
 * - Multi-role support
 */
class PermissionMiddlewareTest extends TestCase
{
    protected $testConfigDir;
    protected $sessionManager;

    protected function setUp(): void
    {
        parent::setUp();

        // Clear session and server vars
        $_SESSION = [];
        $_SERVER = [
            'HTTP_HOST' => 'localhost',
            'SCRIPT_NAME' => '/index.php',
            'REQUEST_URI' => '/',
        ];

        // Create temporary test config directory
        $this->testConfigDir = sys_get_temp_dir() . '/keycloak_test_' . uniqid();
        mkdir($this->testConfigDir, 0777, true);

        // Clear static cache
        PermissionMiddleware::clearCache();

        // Reset KeycloakConfig singleton and initialize with test config
        KeycloakConfig::reset();
        KeycloakConfig::getInstance(TEST_CONFIG);

        // Create session manager
        $this->sessionManager = new SessionManager();
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        // Clean up test config files
        if (file_exists($this->testConfigDir)) {
            $this->deleteDirectory($this->testConfigDir);
        }

        $_SESSION = [];
        $_SERVER = [];

        PermissionMiddleware::clearCache();
        KeycloakConfig::reset();
    }

    /**
     * Recursively delete a directory
     *
     * @param string $dir Directory path
     */
    protected function deleteDirectory($dir)
    {
        if (!file_exists($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = "$dir/$file";
            is_dir($path) ? $this->deleteDirectory($path) : unlink($path);
        }
        rmdir($dir);
    }

    /**
     * Create test config files
     *
     * @param array $endpointConfig Endpoint permissions configuration
     * @param array $roleConfig Role permissions configuration
     */
    protected function createTestConfigs(array $endpointConfig, array $roleConfig)
    {
        file_put_contents(
            $this->testConfigDir . '/endpoint_permissions.json',
            json_encode($endpointConfig, JSON_PRETTY_PRINT)
        );

        file_put_contents(
            $this->testConfigDir . '/role_permissions.json',
            json_encode(['roles' => $roleConfig], JSON_PRETTY_PRINT)
        );
    }

    /**
     * Create authenticated session with specific roles
     *
     * @param array $roles User roles
     */
    protected function createAuthenticatedSession(array $roles)
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_role' => $roles,
        ];

        $this->sessionManager->createSession($userInfo, ['access_token' => 'test_token']);
    }

    /**
     * Test endpoint permission check with access granted
     *
     * Verifies that:
     * - User with required permissions can access endpoint
     * - check() returns true
     */
    public function testAccessGrantedWhenUserHasRequiredPermissions()
    {
        $_SERVER['REQUEST_URI'] = '/ekspedisi/add';

        // Setup configs
        $endpointConfig = [
            'ekspedisi/add' => [
                'controller' => 'Ekspedisi',
                'modules' => [
                    ['name' => 'data ekspedisi', 'permissions' => ['C']],
                ],
            ],
        ];

        $roleConfig = [
            'logistic_staff' => [
                'modules' => [
                    'data ekspedisi' => ['C', 'R', 'U'],
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        // Create session with required role
        $this->createAuthenticatedSession(['logistic_staff']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'User with required permission should have access');
    }

    /**
     * Test endpoint permission check with access denied
     *
     * Verifies that:
     * - User without required permissions is denied access
     * - check() returns false
     */
    public function testAccessDeniedWhenUserLacksPermissions()
    {
        $_SERVER['REQUEST_URI'] = '/ekspedisi/delete';

        // Setup configs
        $endpointConfig = [
            'ekspedisi/delete' => [
                'modules' => [
                    ['name' => 'data ekspedisi', 'permissions' => ['D']],
                ],
            ],
        ];

        $roleConfig = [
            'logistic_staff' => [
                'modules' => [
                    'data ekspedisi' => ['C', 'R', 'U'], // No 'D' permission
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['logistic_staff']);

        $middleware = new PermissionMiddleware();

        // In CLI environment, redirect triggers header warning
        try {
            $result = $middleware->check();
            $this->assertFalse($result, 'User without required permission should be denied');
        } catch (\PHPUnit\Framework\Error\Warning $e) {
            $this->assertStringContainsString('headers already sent', $e->getMessage());
        }
    }

    /**
     * Test multiple modules requirement
     *
     * Verifies that:
     * - Endpoint requiring multiple modules validates all
     * - User must have ALL required module permissions
     */
    public function testMultipleModulesRequirement()
    {
        $_SERVER['REQUEST_URI'] = '/btb/add';

        // Setup configs
        $endpointConfig = [
            'btb/add' => [
                'modules' => [
                    ['name' => 'btb', 'permissions' => ['C']],
                    ['name' => 'data produk', 'permissions' => ['R']],
                ],
            ],
        ];

        $roleConfig = [
            'warehouse_staff' => [
                'modules' => [
                    'btb' => ['C', 'R'],
                    'data produk' => ['R'],
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['warehouse_staff']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'User with all required module permissions should have access');
    }

    /**
     * Test multiple modules with one missing permission
     *
     * Verifies that:
     * - Missing permission on any required module denies access
     */
    public function testMultipleModulesWithMissingPermission()
    {
        $_SERVER['REQUEST_URI'] = '/btb/add';

        $endpointConfig = [
            'btb/add' => [
                'modules' => [
                    ['name' => 'btb', 'permissions' => ['C']],
                    ['name' => 'data produk', 'permissions' => ['R']],
                ],
            ],
        ];

        $roleConfig = [
            'warehouse_staff' => [
                'modules' => [
                    'btb' => ['C', 'R'],
                    // Missing 'data produk' module
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['warehouse_staff']);

        $middleware = new PermissionMiddleware();

        // In CLI environment, redirect triggers header warning
        try {
            $result = $middleware->check();
            $this->assertFalse($result, 'Missing any required module should deny access');
        } catch (\PHPUnit\Framework\Error\Warning $e) {
            $this->assertStringContainsString('headers already sent', $e->getMessage());
        }
    }

    /**
     * Test multi-role support - access granted if ANY role satisfies
     *
     * Verifies that:
     * - User with multiple roles gets access if ANY role has permissions
     * - First matching role grants access
     */
    public function testMultiRoleAccessGranted()
    {
        $_SERVER['REQUEST_URI'] = '/reports/view';

        $endpointConfig = [
            'reports/view' => [
                'modules' => [
                    ['name' => 'reports', 'permissions' => ['R']],
                ],
            ],
        ];

        $roleConfig = [
            'user' => [
                'modules' => [
                    // No reports access
                ],
            ],
            'manager' => [
                'modules' => [
                    'reports' => ['R'],
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        // User has both roles, manager role grants access
        $this->createAuthenticatedSession(['user', 'manager']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'User with multiple roles should pass if ANY role has permission');
    }

    /**
     * Test unregistered endpoint allows access by default
     *
     * Verifies that:
     * - Endpoints not in config file are allowed by default
     * - Only explicitly configured endpoints are restricted
     */
    public function testUnregisteredEndpointAllowsAccess()
    {
        $_SERVER['REQUEST_URI'] = '/some/random/endpoint';

        $endpointConfig = [
            'ekspedisi/add' => [
                'modules' => [
                    ['name' => 'data ekspedisi', 'permissions' => ['C']],
                ],
            ],
        ];

        $roleConfig = [
            'user' => [
                'modules' => [],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['user']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'Unregistered endpoints should allow access by default');
    }

    /**
     * Test endpoint with empty modules array allows access
     *
     * Verifies that:
     * - Endpoint with modules: [] allows all authenticated users
     */
    public function testEndpointWithEmptyModulesAllowsAccess()
    {
        $_SERVER['REQUEST_URI'] = '/public/endpoint';

        $endpointConfig = [
            'public/endpoint' => [
                'modules' => [], // Empty array = no restrictions
            ],
        ];

        $roleConfig = [
            'user' => [
                'modules' => [],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['user']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'Endpoint with empty modules should allow access');
    }

    /**
     * Test user with no roles is denied access
     *
     * Verifies that:
     * - User without any roles is denied access to protected endpoints
     */
    public function testUserWithNoRolesDenied()
    {
        $_SERVER['REQUEST_URI'] = '/ekspedisi/add';

        $endpointConfig = [
            'ekspedisi/add' => [
                'modules' => [
                    ['name' => 'data ekspedisi', 'permissions' => ['C']],
                ],
            ],
        ];

        $roleConfig = [
            'logistic_staff' => [
                'modules' => [
                    'data ekspedisi' => ['C'],
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        // User with no roles
        $this->createAuthenticatedSession([]);

        $middleware = new PermissionMiddleware();

        // In CLI environment, redirect triggers header warning
        try {
            $result = $middleware->check();
            $this->assertFalse($result, 'User with no roles should be denied');
        } catch (\PHPUnit\Framework\Error\Warning $e) {
            $this->assertStringContainsString('headers already sent', $e->getMessage());
        }
    }

    /**
     * Test role not in config is skipped (multi-role scenario)
     *
     * Verifies that:
     * - Unknown roles are skipped
     * - Other known roles are still checked
     */
    public function testUnknownRoleIsSkipped()
    {
        $_SERVER['REQUEST_URI'] = '/ekspedisi/add';

        $endpointConfig = [
            'ekspedisi/add' => [
                'modules' => [
                    ['name' => 'data ekspedisi', 'permissions' => ['C']],
                ],
            ],
        ];

        $roleConfig = [
            'logistic_staff' => [
                'modules' => [
                    'data ekspedisi' => ['C'],
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        // User has unknown_role (not in config) and logistic_staff (valid)
        $this->createAuthenticatedSession(['unknown_role', 'logistic_staff']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'Unknown roles should be skipped, known role should grant access');
    }

    /**
     * Test endpoint normalization (case handling and path cleaning)
     *
     * Verifies that:
     * - Endpoint keys are normalized to lowercase
     * - Leading/trailing slashes are removed
     */
    public function testEndpointNormalization()
    {
        $middleware = new PermissionMiddleware();

        $reflection = new \ReflectionClass($middleware);
        $method = $reflection->getMethod('normalizeEndpoint');
        $method->setAccessible(true);

        $testCases = [
            '/Ekspedisi/Add' => 'ekspedisi/add',
            '/ekspedisi/add/' => 'ekspedisi/add',
            'ekspedisi/add' => 'ekspedisi/add',
            '/BTBCONTROLLER/DELETE' => 'btbcontroller/delete',
            '/simadiskc/ekspedisi/add' => 'ekspedisi/add', // Remove base path prefix
        ];

        foreach ($testCases as $input => $expected) {
            $result = $method->invoke($middleware, $input);
            $this->assertEquals($expected, $result, "Failed for input: $input");
        }
    }

    /**
     * Test excluded paths skip permission checks
     *
     * Verifies that:
     * - Default excluded paths (/auth, /home) bypass checks
     * - Custom excluded paths are respected
     */
    public function testExcludedPathsSkipPermissionCheck()
    {
        $_SERVER['REQUEST_URI'] = '/auth/login';

        // Config would normally deny this, but it's excluded
        $endpointConfig = [
            'auth/login' => [
                'modules' => [
                    ['name' => 'admin', 'permissions' => ['C']],
                ],
            ],
        ];

        $roleConfig = [
            'user' => [
                'modules' => [],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['user']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'Excluded path should bypass permission check');
    }

    /**
     * Test custom excluded paths
     *
     * Verifies that:
     * - Custom paths can be added to exclusion list
     */
    public function testCustomExcludedPaths()
    {
        $_SERVER['REQUEST_URI'] = '/public/api';

        $endpointConfig = [
            'public/api' => [
                'modules' => [
                    ['name' => 'api', 'permissions' => ['R']],
                ],
            ],
        ];

        $roleConfig = [
            'user' => [
                'modules' => [],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['user']);

        // Add custom excluded path
        $middleware = new PermissionMiddleware(['/public/api']);
        $result = $middleware->check();

        $this->assertTrue($result, 'Custom excluded path should bypass permission check');
    }

    /**
     * Test config caching (static cache)
     *
     * Verifies that:
     * - Config files are loaded only once
     * - Subsequent checks use cached data
     */
    public function testConfigCaching()
    {
        $_SERVER['REQUEST_URI'] = '/ekspedisi/add';

        $endpointConfig = [
            'ekspedisi/add' => [
                'modules' => [
                    ['name' => 'data ekspedisi', 'permissions' => ['C']],
                ],
            ],
        ];

        $roleConfig = [
            'logistic_staff' => [
                'modules' => [
                    'data ekspedisi' => ['C'],
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['logistic_staff']);

        // First check - loads config
        $middleware1 = new PermissionMiddleware();
        $middleware1->check();

        // Verify config is cached
        $cachedEndpoints = PermissionMiddleware::getEndpointPermissions();
        $cachedRoles = PermissionMiddleware::getRolePermissions();

        $this->assertNotEmpty($cachedEndpoints, 'Endpoint config should be cached');
        $this->assertNotEmpty($cachedRoles, 'Role config should be cached');

        // Second check - uses cached config
        $middleware2 = new PermissionMiddleware();
        $middleware2->check();

        // Verify same cached data is used
        $this->assertEquals($cachedEndpoints, PermissionMiddleware::getEndpointPermissions());
        $this->assertEquals($cachedRoles, PermissionMiddleware::getRolePermissions());
    }

    /**
     * Test cache clearing
     *
     * Verifies that:
     * - clearCache() resets static cache
     * - Config is reloaded after cache clear
     */
    public function testCacheClear()
    {
        $endpointConfig = ['test' => []];
        $roleConfig = ['test_role' => []];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        // Load config
        $middleware = new PermissionMiddleware();
        $_SERVER['REQUEST_URI'] = '/test';
        $this->createAuthenticatedSession(['test_role']);
        $middleware->check();

        $this->assertNotEmpty(PermissionMiddleware::getEndpointPermissions());

        // Clear cache
        PermissionMiddleware::clearCache();

        $this->assertEmpty(PermissionMiddleware::getEndpointPermissions());
        $this->assertEmpty(PermissionMiddleware::getRolePermissions());
    }

    /**
     * Test missing config files
     *
     * Verifies that:
     * - Missing config files don't crash
     * - Defaults to empty config (allow all access)
     */
    public function testMissingConfigFiles()
    {
        $_SERVER['REQUEST_URI'] = '/some/endpoint';

        // Set config path to non-existent directory
        PermissionMiddleware::setConfigPath('/non/existent/path');

        $this->createAuthenticatedSession(['user']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        // Should allow access when config is missing
        $this->assertTrue($result, 'Missing config should allow access');
    }

    /**
     * Test case-insensitive role matching
     *
     * Verifies that:
     * - Role names are matched case-insensitively
     * - "Administrator" matches "administrator" in config
     */
    public function testCaseInsensitiveRoleMatching()
    {
        $_SERVER['REQUEST_URI'] = '/admin/panel';

        $endpointConfig = [
            'admin/panel' => [
                'modules' => [
                    ['name' => 'admin', 'permissions' => ['R']],
                ],
            ],
        ];

        $roleConfig = [
            'administrator' => [  // lowercase in config
                'modules' => [
                    'admin' => ['R'],
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        // User role has different case
        $this->createAuthenticatedSession(['Administrator']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'Role matching should be case-insensitive');
    }

    /**
     * Test permission letter case-insensitive matching
     *
     * Verifies that:
     * - Permission letters (CRUD) are matched case-insensitively
     */
    public function testCaseInsensitivePermissionMatching()
    {
        $_SERVER['REQUEST_URI'] = '/ekspedisi/add';

        $endpointConfig = [
            'ekspedisi/add' => [
                'modules' => [
                    ['name' => 'data ekspedisi', 'permissions' => ['c']],  // lowercase
                ],
            ],
        ];

        $roleConfig = [
            'logistic_staff' => [
                'modules' => [
                    'data ekspedisi' => ['C'],  // uppercase
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['logistic_staff']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'Permission matching should be case-insensitive');
    }

    /**
     * Test administrator role with full CRUD access
     *
     * Verifies that:
     * - Admin role with all CRUD permissions can access any endpoint
     */
    public function testAdministratorFullAccess()
    {
        $_SERVER['REQUEST_URI'] = '/ekspedisi/delete';

        $endpointConfig = [
            'ekspedisi/delete' => [
                'modules' => [
                    ['name' => 'data ekspedisi', 'permissions' => ['D']],
                ],
            ],
        ];

        $roleConfig = [
            'administrator' => [
                'modules' => [
                    'data ekspedisi' => ['C', 'R', 'U', 'D'],  // Full access
                ],
            ],
        ];

        $this->createTestConfigs($endpointConfig, $roleConfig);
        PermissionMiddleware::setConfigPath($this->testConfigDir);

        $this->createAuthenticatedSession(['administrator']);

        $middleware = new PermissionMiddleware();
        $result = $middleware->check();

        $this->assertTrue($result, 'Administrator should have full access');
    }
}
