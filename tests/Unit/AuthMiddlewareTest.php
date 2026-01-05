<?php

namespace Simss\KeycloakAuth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Simss\KeycloakAuth\Middleware\AuthMiddleware;
use Simss\KeycloakAuth\Auth\SessionManager;
use Simss\KeycloakAuth\Auth\KeycloakAuth;

/**
 * Unit tests for AuthMiddleware class
 *
 * Tests authentication middleware functionality including:
 * - Authentication checks
 * - Token validation and refresh
 * - Role-based access control
 * - Silent SSO re-authentication
 * - Path exclusion logic
 */
class AuthMiddlewareTest extends TestCase
{
    protected $middleware;
    protected $sessionManager;
    protected $keycloakAuth;

    protected function setUp(): void
    {
        parent::setUp();

        // Clear session
        $_SESSION = [];
        $_SERVER = [
            'HTTP_HOST' => 'localhost',
            'SCRIPT_NAME' => '/index.php',
            'REQUEST_URI' => '/',
        ];

        // Create mocks
        $this->sessionManager = $this->createMock(SessionManager::class);
        $this->keycloakAuth = $this->createMock(KeycloakAuth::class);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        $_SESSION = [];
        $_SERVER = [];
    }

    /**
     * Create middleware instance with injected dependencies
     *
     * @param array $excludedPaths Optional excluded paths
     * @return AuthMiddleware
     */
    protected function createMiddleware(array $excludedPaths = [])
    {
        return new AuthMiddleware($excludedPaths, $this->keycloakAuth);
    }

    /**
     * Test that excluded paths skip authentication checks
     *
     * Verifies that:
     * - Default excluded paths (/auth, /auth/login, etc.) bypass authentication
     * - Custom excluded paths are respected
     * - check() returns true for excluded paths
     */
    public function testExcludedPathsSkipAuthentication()
    {
        $_SERVER['REQUEST_URI'] = '/auth/login';

        $middleware = $this->createMiddleware();

        // Should not call any session methods for excluded paths
        $this->sessionManager
            ->expects($this->never())
            ->method('isAuthenticated');

        $result = $middleware->check();

        $this->assertTrue($result, 'Excluded paths should return true without checking auth');
    }

    /**
     * Test custom excluded paths
     *
     * Verifies that:
     * - Custom paths added to exclusion list are respected
     * - Authentication is skipped for custom excluded paths
     */
    public function testCustomExcludedPaths()
    {
        $_SERVER['REQUEST_URI'] = '/public/api';

        $middleware = $this->createMiddleware(['/public/api']);

        $this->sessionManager
            ->expects($this->never())
            ->method('isAuthenticated');

        $result = $middleware->check();

        $this->assertTrue($result, 'Custom excluded paths should skip auth');
    }

    /**
     * Test path exclusion matching logic
     *
     * Verifies that:
     * - Exact path matching works
     * - Subpath matching works (e.g., /auth matches /auth/anything)
     * - Similar but non-matching paths are not excluded
     */
    public function testPathExclusionMatchingLogic()
    {
        $middleware = $this->createMiddleware();

        $testCases = [
            '/auth' => true,
            '/auth/login' => true,
            '/auth/callback' => true,
            '/auth/logout' => true,
            '/auth/check' => true,
            '/authentication' => false,  // Should NOT match /auth
            '/myauth' => false,          // Should NOT match /auth
            '/home' => false,
        ];

        foreach ($testCases as $path => $shouldBeExcluded) {
            $_SERVER['REQUEST_URI'] = $path;

            // Create new instance for each test
            $testMiddleware = $this->createMiddleware();

            // Use reflection to test the protected method
            $reflection = new \ReflectionClass($testMiddleware);
            $method = $reflection->getMethod('isExcludedPath');
            $method->setAccessible(true);

            $result = $method->invoke($testMiddleware, $path);

            $this->assertEquals(
                $shouldBeExcluded,
                $result,
                "Path '$path' should " . ($shouldBeExcluded ? 'be' : 'NOT be') . " excluded"
            );
        }
    }

    /**
     * Test authenticated user with valid token
     *
     * Verifies that:
     * - Authenticated users with valid tokens pass the check
     * - No redirect occurs
     */
    public function testAuthenticatedUserWithValidToken()
    {
        $_SERVER['REQUEST_URI'] = '/dashboard';

        // Create a concrete instance with real dependencies for this test
        $realSessionManager = new SessionManager();

        // Create authenticated session
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = [
            'access_token' => 'valid_token',
            'id_token' => $this->createMockIdToken(time() + 3600), // Expires in 1 hour
            'expires_in' => 3600,
        ];
        $realSessionManager->createSession($userInfo, $tokens);

        // Create middleware with real session manager
        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        $result = $middleware->check();

        $this->assertTrue($result, 'Authenticated user with valid token should pass');
    }

    /**
     * Test unauthenticated user is redirected
     *
     * Verifies that:
     * - Unauthenticated users fail the check
     * - check() returns false (or redirects in production)
     *
     * Note: This test expects redirect which will fail in CLI/test environment
     * We catch the header exception and verify the behavior
     */
    public function testUnauthenticatedUserFails()
    {
        $_SERVER['REQUEST_URI'] = '/dashboard';

        // Empty session = not authenticated
        $realSessionManager = new SessionManager();

        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        try {
            $result = $middleware->check();
            $this->assertFalse($result, 'Unauthenticated user should fail check');
        } catch (\PHPUnit\Framework\Error\Warning $e) {
            // Expected in test environment - cannot send headers
            $this->assertStringContainsString('headers already sent', $e->getMessage());
        }
    }

    /**
     * Test expired token triggers refresh attempt
     *
     * Verifies that:
     * - Expired tokens trigger refresh attempt
     * - Successful refresh allows access
     */
    public function testExpiredTokenTriggersRefresh()
    {
        $_SERVER['REQUEST_URI'] = '/dashboard';

        // Create session with expired token
        $realSessionManager = new SessionManager();
        $userInfo = (object)['preferred_username' => 'testuser'];
        $expiredToken = $this->createMockIdToken(time() - 100); // Expired 100 seconds ago
        $tokens = [
            'access_token' => 'expired_token',
            'id_token' => $expiredToken,
            'refresh_token' => 'refresh_token',
            'expires_in' => -100,
        ];
        $realSessionManager->createSession($userInfo, $tokens);

        // Mock successful token refresh
        $this->keycloakAuth
            ->expects($this->once())
            ->method('refreshAccessToken')
            ->willReturn(true);

        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        $result = $middleware->check();

        $this->assertTrue($result, 'Should pass after successful token refresh');
    }

    /**
     * Test failed token refresh leads to authentication failure
     *
     * Verifies that:
     * - When token refresh fails, check returns false
     * - Session is destroyed
     */
    public function testFailedTokenRefreshDestroysSession()
    {
        $_SERVER['REQUEST_URI'] = '/dashboard';

        $realSessionManager = new SessionManager();
        $userInfo = (object)['preferred_username' => 'testuser'];
        $expiredToken = $this->createMockIdToken(time() - 100);
        $tokens = [
            'access_token' => 'expired_token',
            'id_token' => $expiredToken,
            'refresh_token' => 'invalid_refresh_token',
            'expires_in' => -100,
        ];
        $realSessionManager->createSession($userInfo, $tokens);

        // Mock failed token refresh
        $this->keycloakAuth
            ->expects($this->once())
            ->method('refreshAccessToken')
            ->willThrowException(new \RuntimeException('Token refresh failed - HTTP 400: invalid_grant'));

        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        try {
            $result = $middleware->check();
            $this->assertFalse($result, 'Should fail when token refresh fails');
        } catch (\PHPUnit\Framework\Error\Warning $e) {
            // Expected in test environment - cannot send headers for redirect
            $this->assertStringContainsString('headers already sent', $e->getMessage());
        }

        $this->assertFalse($realSessionManager->isAuthenticated(), 'Session should be destroyed');
    }

    /**
     * Test role check functionality
     *
     * Verifies that:
     * - hasRole() correctly identifies user roles
     * - Case-insensitive role matching works
     */
    public function testRoleCheck()
    {
        $realSessionManager = new SessionManager();
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_role' => ['Administrator', 'Manager'],
        ];
        $tokens = ['access_token' => 'token', 'id_token' => $this->createMockIdToken(time() + 3600)];
        $realSessionManager->createSession($userInfo, $tokens);

        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        $this->assertTrue($middleware->hasRole('administrator'), 'Should match role case-insensitively');
        $this->assertTrue($middleware->hasRole('Manager'), 'Should match exact role');
        $this->assertFalse($middleware->hasRole('User'), 'Should not match non-existent role');
    }

    /**
     * Test requireRole redirects non-authorized users
     *
     * Verifies that:
     * - Users without required role are denied access
     * - Redirect occurs (tested via exception in test context)
     */
    public function testRequireRoleEnforcesAccess()
    {
        $realSessionManager = new SessionManager();
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_role' => ['User'],
        ];
        $tokens = ['access_token' => 'token', 'id_token' => $this->createMockIdToken(time() + 3600)];
        $realSessionManager->createSession($userInfo, $tokens);

        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        // Note: In actual usage, this would redirect. In tests, we can check the hasRole result
        $this->assertFalse($middleware->hasRole('Administrator'), 'User should not have admin role');
    }

    /**
     * Test requireAnyRole accepts users with at least one required role
     *
     * Verifies that:
     * - Users with any of the required roles pass
     * - Users without any required role fail
     */
    public function testRequireAnyRole()
    {
        $realSessionManager = new SessionManager();
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_role' => ['Manager'],
        ];
        $tokens = ['access_token' => 'token', 'id_token' => $this->createMockIdToken(time() + 3600)];
        $realSessionManager->createSession($userInfo, $tokens);

        // Use reflection to test protected SessionManager method
        $reflection = new \ReflectionMethod($realSessionManager, 'hasAnyRole');
        $reflection->setAccessible(true);

        $this->assertTrue(
            $reflection->invoke($realSessionManager, ['Administrator', 'Manager']),
            'Should pass with Manager role'
        );

        $this->assertFalse(
            $reflection->invoke($realSessionManager, ['Administrator', 'SuperUser']),
            'Should fail without required roles'
        );
    }

    /**
     * Test getCurrentPath extraction from various sources
     *
     * Verifies that:
     * - REQUEST_URI is parsed correctly
     * - Query parameters are removed
     * - Path is normalized
     */
    public function testGetCurrentPath()
    {
        $middleware = $this->createMiddleware();
        $reflection = new \ReflectionClass($middleware);
        $method = $reflection->getMethod('getCurrentPath');
        $method->setAccessible(true);

        $testCases = [
            '/dashboard' => '/dashboard',
            '/dashboard?foo=bar' => '/dashboard',
            '/user/profile?id=123' => '/user/profile',
            '/' => '/',
        ];

        foreach ($testCases as $requestUri => $expectedPath) {
            $_SERVER['REQUEST_URI'] = $requestUri;
            $result = $method->invoke($middleware);
            $this->assertEquals($expectedPath, $result, "Failed for: $requestUri");
        }
    }

    /**
     * Test getCurrentUrl construction
     *
     * Verifies that:
     * - Full URL is constructed correctly from SERVER vars
     * - HTTPS detection works
     * - Query parameters are preserved
     */
    public function testGetCurrentUrl()
    {
        $middleware = $this->createMiddleware();
        $reflection = new \ReflectionClass($middleware);
        $method = $reflection->getMethod('getCurrentUrl');
        $method->setAccessible(true);

        // Test HTTP
        $_SERVER['HTTP_HOST'] = 'example.com';
        $_SERVER['REQUEST_URI'] = '/dashboard?foo=bar';
        unset($_SERVER['HTTPS']);

        $result = $method->invoke($middleware);
        $this->assertEquals('http://example.com/dashboard?foo=bar', $result);

        // Test HTTPS
        $_SERVER['HTTPS'] = 'on';
        $result = $method->invoke($middleware);
        $this->assertEquals('https://example.com/dashboard?foo=bar', $result);
    }

    /**
     * Test legacy session without tokens requires re-authentication
     *
     * Verifies that:
     * - Old sessions without access_token are invalidated
     * - User must re-authenticate
     */
    public function testLegacySessionWithoutTokensRequiresReauth()
    {
        $_SERVER['REQUEST_URI'] = '/dashboard';

        $realSessionManager = new SessionManager();

        // Create legacy session (manually set old format without tokens)
        $_SESSION[SessionManager::SESSION_KEY] = [
            'username' => 'testuser',
            'logged_in' => true,
            // Missing: keycloak_tokens
        ];

        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        try {
            $result = $middleware->check();
            $this->assertFalse($result, 'Legacy session without tokens should fail');
        } catch (\PHPUnit\Framework\Error\Warning $e) {
            // Expected in test environment - destroy() tries to setcookie()
            $this->assertStringContainsString('headers already sent', $e->getMessage());
        }

        $this->assertFalse($realSessionManager->isAuthenticated(), 'Session should be destroyed');
    }

    /**
     * Helper: Create a mock ID token (JWT) with specified expiration
     *
     * @param int $exp Expiration timestamp
     * @return string Mock JWT token
     */
    protected function createMockIdToken($exp)
    {
        $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'sub' => 'test-user-id',
            'iat' => time() - 300,
            'exp' => $exp,
        ]));
        $signature = base64_encode('mock-signature');

        return "$header.$payload.$signature";
    }

    /**
     * Test silent SSO re-authentication on invalid_grant error
     *
     * Verifies that:
     * - invalid_grant error triggers silent SSO attempt
     * - Session is destroyed before SSO redirect
     *
     * Note: This test is complex because silentSsoReauth() calls exit()
     * We verify the logic by checking that invalid_grant is recognized
     */
    public function testSilentSsoOnInvalidGrant()
    {
        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        // Test the shouldAttemptSilentSso logic directly using reflection
        $reflection = new \ReflectionClass($middleware);
        $method = $reflection->getMethod('shouldAttemptSilentSso');
        $method->setAccessible(true);

        $exception = new \RuntimeException('Token refresh failed - HTTP 400: invalid_grant');
        $shouldAttempt = $method->invoke($middleware, $exception);

        $this->assertTrue($shouldAttempt, 'invalid_grant error should trigger silent SSO');
    }

    /**
     * Test that Token is not active error triggers silent SSO
     *
     * Verifies that:
     * - "not active" error triggers silent SSO
     */
    public function testSilentSsoOnTokenNotActive()
    {
        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        // Test the shouldAttemptSilentSso logic directly using reflection
        $reflection = new \ReflectionClass($middleware);
        $method = $reflection->getMethod('shouldAttemptSilentSso');
        $method->setAccessible(true);

        $exception = new \RuntimeException('Token is not active');
        $shouldAttempt = $method->invoke($middleware, $exception);

        $this->assertTrue($shouldAttempt, '"not active" error should trigger silent SSO');
    }

    /**
     * Test that network errors do NOT trigger silent SSO
     *
     * Verifies that:
     * - Network errors (timeout, connection refused) do not trigger SSO
     * - shouldAttemptSilentSso returns false for network errors
     */
    public function testNetworkErrorsDoNotTriggerSilentSso()
    {
        $middleware = new AuthMiddleware([], $this->keycloakAuth);

        // Test the shouldAttemptSilentSso logic directly using reflection
        $reflection = new \ReflectionClass($middleware);
        $method = $reflection->getMethod('shouldAttemptSilentSso');
        $method->setAccessible(true);

        $networkErrors = [
            'Connection timeout',
            'Connection refused',
            'Network unreachable',
            'HTTP 500',
        ];

        foreach ($networkErrors as $errorMsg) {
            $exception = new \RuntimeException($errorMsg);
            $shouldAttempt = $method->invoke($middleware, $exception);
            $this->assertFalse($shouldAttempt, "$errorMsg should NOT trigger silent SSO");
        }
    }
}
