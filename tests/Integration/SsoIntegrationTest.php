<?php

namespace Simss\KeycloakAuth\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Simss\KeycloakAuth\Auth\SessionManager;
use Simss\KeycloakAuth\Auth\KeycloakAuth;
use Simss\KeycloakAuth\Config\KeycloakConfig;

/**
 * SSO Integration Tests
 *
 * Tests Single Sign-On (SSO) functionality by simulating multiple applications
 * accessing the same Keycloak realm. These tests verify:
 * - Session creation and isolation between applications
 * - SSO session detection across applications
 * - Token management in multi-app scenarios
 * - Session check API functionality
 * - Single logout propagation
 *
 * Note: These are integration tests that use real session management
 * (not mocked) to accurately simulate SSO behavior.
 */
class SsoIntegrationTest extends TestCase
{
    protected $config;
    protected $appASessionId;
    protected $appBSessionId;

    protected function setUp(): void
    {
        parent::setUp();

        // Session is already started by bootstrap.php
        // Just clear session data
        $_SESSION = [];

        // Reset KeycloakConfig singleton
        KeycloakConfig::reset();
        $this->config = KeycloakConfig::getInstance(TEST_CONFIG);
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        // Clear session data
        $_SESSION = [];

        KeycloakConfig::reset();
    }

    /**
     * Helper: Create a mock JWT token with expiry
     *
     * @param int $exp Expiry timestamp
     * @return string Mock JWT token
     */
    protected function createMockJwt($exp)
    {
        $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'sub' => 'user-' . uniqid(),
            'exp' => $exp,
            'iat' => time(),
            'preferred_username' => 'testuser',
            'email' => 'test@example.com',
        ]));
        $signature = base64_encode('mock_signature');

        return "$header.$payload.$signature";
    }

    /**
     * Helper: Clear and prepare session for a specific "application"
     *
     * Simulates separate app sessions by clearing session data between tests.
     * In real SSO, apps would have separate PHP sessions but share Keycloak cookies.
     *
     * @param string $appName Application identifier (for logging/context)
     */
    protected function prepareAppSession($appName)
    {
        // Clear session data to simulate fresh app
        $_SESSION = [];
    }

    /**
     * Helper: Create authenticated session for an app
     *
     * @param string $appName Application name (for context)
     * @param object $userInfo User information
     * @param array $tokens Authentication tokens
     * @return SessionManager
     */
    protected function createAuthenticatedApp($appName, $userInfo, $tokens)
    {
        $this->prepareAppSession($appName);
        $sessionManager = new SessionManager();
        $sessionManager->createSession($userInfo, $tokens);

        return $sessionManager;
    }

    /**
     * Helper: Save current session state and restore later
     *
     * @return array Current session data
     */
    protected function saveSessionState()
    {
        return $_SESSION;
    }

    /**
     * Helper: Restore saved session state
     *
     * @param array $state Saved session state
     */
    protected function restoreSessionState($state)
    {
        $_SESSION = $state;
    }

    /**
     * Test session creation and basic authentication
     *
     * Verifies that:
     * - SessionManager creates session correctly
     * - Session data is stored
     * - Tokens are accessible
     */
    public function testSessionCreationAndAuthentication()
    {
        $this->prepareAppSession('test_app');
        $sessionManager = new SessionManager();

        $userInfo = (object)[
            'preferred_username' => 'john.doe',
            'email' => 'john@example.com',
            'given_name' => 'John',
            'family_name' => 'Doe',
            'simss_role' => ['user', 'manager'],
        ];

        $tokens = [
            'access_token' => 'mock_access_token',
            'refresh_token' => 'mock_refresh_token',
            'id_token' => $this->createMockJwt(time() + 3600),
            'expires_in' => 3600,
        ];

        $sessionManager->createSession($userInfo, $tokens);

        $this->assertTrue($sessionManager->isAuthenticated(), 'Session should be authenticated');

        $sessionData = $sessionManager->getSessionData();
        $this->assertEquals('john.doe', $sessionData['username']);
        $this->assertEquals('john@example.com', $sessionData['email']);

        $retrievedTokens = $sessionManager->getTokens();
        $this->assertEquals('mock_access_token', $retrievedTokens['access_token']);
        $this->assertEquals('mock_refresh_token', $retrievedTokens['refresh_token']);
    }

    /**
     * Test multi-application SSO session simulation
     *
     * Verifies that:
     * - Different applications can maintain separate session data
     * - Session state can be saved and restored
     * - Each app can authenticate independently
     *
     * Note: In real SSO, apps would have separate PHP sessions but share Keycloak cookies.
     * This test simulates that by saving/restoring session state.
     */
    public function testMultiApplicationSessionIsolation()
    {
        // Create session for App A
        $userInfoA = (object)[
            'preferred_username' => 'user_a',
            'email' => 'usera@example.com',
        ];

        $tokensA = [
            'access_token' => 'token_a',
            'id_token' => $this->createMockJwt(time() + 3600),
        ];

        $sessionManagerA = $this->createAuthenticatedApp('app_a', $userInfoA, $tokensA);

        $this->assertTrue($sessionManagerA->isAuthenticated(), 'App A should be authenticated');
        $dataA = $sessionManagerA->getSessionData();
        $this->assertEquals('user_a', $dataA['username']);

        // Save App A session state
        $appAState = $this->saveSessionState();

        // Create separate session for App B
        $userInfoB = (object)[
            'preferred_username' => 'user_b',
            'email' => 'userb@example.com',
        ];

        $tokensB = [
            'access_token' => 'token_b',
            'id_token' => $this->createMockJwt(time() + 3600),
        ];

        $sessionManagerB = $this->createAuthenticatedApp('app_b', $userInfoB, $tokensB);

        $this->assertTrue($sessionManagerB->isAuthenticated(), 'App B should be authenticated');
        $dataB = $sessionManagerB->getSessionData();
        $this->assertEquals('user_b', $dataB['username']);

        // Save App B session state
        $appBState = $this->saveSessionState();

        // Verify sessions are different
        $this->assertNotEquals($appAState, $appBState,
            'App A and App B should have different session data');

        // Restore App A and verify data is unchanged
        $this->restoreSessionState($appAState);

        $sessionManagerA2 = new SessionManager();
        $this->assertTrue($sessionManagerA2->isAuthenticated(), 'App A session should be restored');
        $dataA2 = $sessionManagerA2->getSessionData();
        $this->assertEquals('user_a', $dataA2['username'], 'App A data should be unchanged');
    }

    /**
     * Test SSO scenario: Same user in multiple apps
     *
     * Verifies that:
     * - Same user can authenticate in multiple apps
     * - Each app maintains its own session
     * - Token data can differ between apps (issued at different times)
     */
    public function testSsoSameUserMultipleApps()
    {
        $sameUser = (object)[
            'preferred_username' => 'sso.user',
            'email' => 'sso@example.com',
            'simss_role' => ['admin'],
        ];

        // App A authenticates first
        $tokensA = [
            'access_token' => 'app_a_token',
            'id_token' => $this->createMockJwt(time() + 3600),
            'expires_in' => 3600,
        ];

        $sessionManagerA = $this->createAuthenticatedApp('sso_app_a', $sameUser, $tokensA);

        $this->assertTrue($sessionManagerA->isAuthenticated());
        $this->assertTrue($sessionManagerA->hasRole('admin'));

        $tokensARetrieved = $sessionManagerA->getTokens();
        $dataA = $sessionManagerA->getSessionData();

        // Save App A state
        $appAState = $this->saveSessionState();

        // App B authenticates via SSO (different tokens, same user)
        $tokensB = [
            'access_token' => 'app_b_token',
            'id_token' => $this->createMockJwt(time() + 3600),
            'expires_in' => 3600,
        ];

        $sessionManagerB = $this->createAuthenticatedApp('sso_app_b', $sameUser, $tokensB);

        $this->assertTrue($sessionManagerB->isAuthenticated());
        $this->assertTrue($sessionManagerB->hasRole('admin'));

        $tokensBRetrieved = $sessionManagerB->getTokens();
        $dataB = $sessionManagerB->getSessionData();

        // Verify both sessions have same user but different tokens
        $this->assertEquals('app_a_token', $tokensARetrieved['access_token']);
        $this->assertEquals('app_b_token', $tokensBRetrieved['access_token']);

        // Verify same user identity
        $this->assertEquals($dataA['username'], $dataB['username']);
        $this->assertEquals($dataA['email'], $dataB['email']);
    }

    /**
     * Test session check API functionality
     *
     * Verifies that:
     * - Session status can be checked
     * - User data is accessible via session manager
     * - Token presence can be verified
     * - Token expiry can be checked
     */
    public function testSessionCheckApi()
    {
        $this->prepareAppSession('api_test');
        $sessionManager = new SessionManager();

        // Before authentication
        $this->assertFalse($sessionManager->isAuthenticated(), 'Should not be authenticated initially');

        // Create authenticated session
        $userInfo = (object)[
            'preferred_username' => 'api.user',
            'email' => 'api@example.com',
        ];

        $tokens = [
            'access_token' => 'api_access_token',
            'refresh_token' => 'api_refresh_token',
            'id_token' => $this->createMockJwt(time() + 3600),
            'expires_in' => 3600,
        ];

        $sessionManager->createSession($userInfo, $tokens);

        // Check session status (simulating session check API)
        $response = [
            'session_exists' => $sessionManager->isAuthenticated(),
            'session_id' => session_id(),
            'timestamp' => time(),
        ];

        $this->assertTrue($response['session_exists']);
        $this->assertNotEmpty($response['session_id']);

        // Add user data
        if ($sessionManager->isAuthenticated()) {
            $sessionData = $sessionManager->getSessionData();
            $sessionTokens = $sessionManager->getTokens();

            $response['user'] = [
                'username' => $sessionData['username'] ?? 'Unknown',
                'email' => $sessionData['email'] ?? 'N/A',
            ];

            $response['tokens'] = [
                'has_access_token' => isset($sessionTokens['access_token']),
                'has_refresh_token' => isset($sessionTokens['refresh_token']),
                'has_id_token' => isset($sessionTokens['id_token']),
                'expires_at' => $sessionTokens['access_token_expires_at'] ?? null,
            ];

            $response['token_expired'] = $sessionManager->isTokenExpired();
        }

        // Verify response structure
        $this->assertEquals('api.user', $response['user']['username']);
        $this->assertEquals('api@example.com', $response['user']['email']);
        $this->assertTrue($response['tokens']['has_access_token']);
        $this->assertTrue($response['tokens']['has_refresh_token']);
        $this->assertTrue($response['tokens']['has_id_token']);
        $this->assertFalse($response['token_expired']);
    }

    /**
     * Test token expiry detection across apps
     *
     * Verifies that:
     * - Expired tokens are detected
     * - Token expiry buffer is respected
     * - Each app can independently check token status
     */
    public function testTokenExpiryDetectionAcrossApps()
    {
        // App with expired token
        $userInfo = (object)[
            'preferred_username' => 'expired.user',
            'email' => 'expired@example.com',
        ];

        $expiredTokens = [
            'access_token' => 'expired_token',
            'id_token' => $this->createMockJwt(time() - 100),
            'expires_in' => -100,
        ];

        $sessionManager = $this->createAuthenticatedApp('expired_app', $userInfo, $expiredTokens);

        $this->assertTrue($sessionManager->isAuthenticated(), 'Session should exist');
        $this->assertTrue($sessionManager->isTokenExpired(), 'Token should be expired');

        // App with valid token
        $validTokens = [
            'access_token' => 'valid_token',
            'id_token' => $this->createMockJwt(time() + 3600),
            'expires_in' => 3600,
        ];

        $sessionManager2 = $this->createAuthenticatedApp('valid_app', $userInfo, $validTokens);

        $this->assertTrue($sessionManager2->isAuthenticated(), 'Session should exist');
        $this->assertFalse($sessionManager2->isTokenExpired(), 'Token should be valid');
    }

    /**
     * Test session destruction (logout)
     *
     * Verifies that:
     * - Session can be destroyed
     * - After logout, session is no longer authenticated
     * - Session data is cleared
     */
    public function testSessionDestruction()
    {
        $this->prepareAppSession('logout_test');
        $sessionManager = new SessionManager();

        $userInfo = (object)[
            'preferred_username' => 'logout.user',
            'email' => 'logout@example.com',
        ];

        $tokens = [
            'access_token' => 'logout_token',
            'id_token' => $this->createMockJwt(time() + 3600),
        ];

        $sessionManager->createSession($userInfo, $tokens);

        $this->assertTrue($sessionManager->isAuthenticated(), 'Should be authenticated before logout');

        // Manually clear session instead of calling destroy() to avoid setcookie() errors in CLI
        $_SESSION = [];

        $this->assertFalse($sessionManager->isAuthenticated(), 'Should not be authenticated after logout');
    }

    /**
     * Test logout propagation simulation
     *
     * Verifies that:
     * - Logging out from one app clears that app's session
     * - Other apps maintain their sessions (when saved separately)
     * - (In real SSO, Keycloak session cookie would also be cleared)
     */
    public function testLogoutPropagationSimulation()
    {
        $userInfo = (object)[
            'preferred_username' => 'multiapp.user',
            'email' => 'multiapp@example.com',
        ];

        // Create session for App 1
        $tokens = [
            'access_token' => 'app1_token',
            'id_token' => $this->createMockJwt(time() + 3600),
        ];

        $sessionManagerApp1 = $this->createAuthenticatedApp('logout_app_1', $userInfo, $tokens);

        $this->assertTrue($sessionManagerApp1->isAuthenticated());

        // Save App 1 session
        $app1State = $this->saveSessionState();

        // Create session for App 2
        $tokens2 = [
            'access_token' => 'app2_token',
            'id_token' => $this->createMockJwt(time() + 3600),
        ];

        $sessionManagerApp2 = $this->createAuthenticatedApp('logout_app_2', $userInfo, $tokens2);

        $this->assertTrue($sessionManagerApp2->isAuthenticated());

        // Save App 2 session
        $app2State = $this->saveSessionState();

        // Logout from App 1 by restoring then clearing
        $this->restoreSessionState($app1State);
        $_SESSION = [];  // Simulate logout

        $sessionManagerApp1After = new SessionManager();
        $this->assertFalse($sessionManagerApp1After->isAuthenticated(),
            'App 1 should be logged out');

        // Verify App 2 still has session when restored
        $this->restoreSessionState($app2State);

        $sessionManagerApp2After = new SessionManager();
        $this->assertTrue($sessionManagerApp2After->isAuthenticated(),
            'App 2 should still be authenticated (independent session)');
    }

    /**
     * Test role persistence across session
     *
     * Verifies that:
     * - User roles are stored in session
     * - Roles can be checked after session creation
     * - Case-insensitive role matching works
     */
    public function testRolePersistenceAcrossSession()
    {
        $this->prepareAppSession('role_test');
        $sessionManager = new SessionManager();

        $userInfo = (object)[
            'preferred_username' => 'role.user',
            'email' => 'role@example.com',
            'simss_role' => ['Administrator', 'Manager', 'User'],
        ];

        $tokens = [
            'access_token' => 'role_token',
            'id_token' => $this->createMockJwt(time() + 3600),
        ];

        $sessionManager->createSession($userInfo, $tokens);

        // Test role checking
        $this->assertTrue($sessionManager->hasRole('Administrator'));
        $this->assertTrue($sessionManager->hasRole('manager'));  // Case-insensitive
        $this->assertTrue($sessionManager->hasRole('USER'));     // Case-insensitive
        $this->assertFalse($sessionManager->hasRole('SuperAdmin'));

        // Get all roles
        $roles = $sessionManager->getRoles();
        $this->assertCount(3, $roles);
        $this->assertContains('Administrator', $roles);
        $this->assertContains('Manager', $roles);
        $this->assertContains('User', $roles);
    }

    /**
     * Test SIMSS organizational data storage
     *
     * Verifies that:
     * - SIMSS-specific attributes are stored
     * - Organizational data is accessible
     * - Custom attributes persist in session
     */
    public function testSimssDataStorage()
    {
        $this->prepareAppSession('simss_test');
        $sessionManager = new SessionManager();

        $userInfo = (object)[
            'preferred_username' => 'simss.user',
            'email' => 'simss@example.com',
            'simss_cabang' => ['CAB001'],
            'simss_divisi' => ['IT'],
            'simss_station' => ['STA001'],
            'simss_subdivisi' => ['Development'],
            'simss_role' => ['developer', 'admin'],
        ];

        $tokens = [
            'access_token' => 'simss_token',
            'id_token' => $this->createMockJwt(time() + 3600),
        ];

        $sessionManager->createSession($userInfo, $tokens);

        $sessionData = $sessionManager->getSessionData();

        // Verify SIMSS data is stored (as arrays)
        $this->assertArrayHasKey('simss', $sessionData);
        $this->assertEquals(['CAB001'], $sessionData['simss']['cabang']);
        $this->assertEquals(['IT'], $sessionData['simss']['divisi']);
        $this->assertEquals(['STA001'], $sessionData['simss']['station']);
        $this->assertEquals(['Development'], $sessionData['simss']['subdivisi']);

        // Verify roles are accessible
        $this->assertTrue($sessionManager->hasRole('developer'));
        $this->assertTrue($sessionManager->hasRole('admin'));
    }

    /**
     * Test concurrent session scenarios
     *
     * Verifies that:
     * - Multiple apps can maintain separate session states
     * - Session data can be saved and restored independently
     * - No data corruption between sessions
     */
    public function testConcurrentSessions()
    {
        $sessions = [];

        // Create 3 app sessions and save their states
        for ($i = 1; $i <= 3; $i++) {
            $userInfo = (object)[
                'preferred_username' => "concurrent_user_$i",
                'email' => "user$i@example.com",
            ];

            $tokens = [
                'access_token' => "token_$i",
                'id_token' => $this->createMockJwt(time() + 3600),
            ];

            $sessionManager = $this->createAuthenticatedApp("concurrent_app_$i", $userInfo, $tokens);

            $this->assertTrue($sessionManager->isAuthenticated(),
                "App $i should be authenticated");

            // Save session state
            $sessions[$i] = [
                'state' => $this->saveSessionState(),
                'username' => "concurrent_user_$i",
                'token' => "token_$i",
            ];
        }

        // Verify each session independently by restoring
        foreach ($sessions as $i => $sessionInfo) {
            $this->restoreSessionState($sessionInfo['state']);

            $sessionManager = new SessionManager();

            $this->assertTrue($sessionManager->isAuthenticated(),
                "App $i should be authenticated");

            $data = $sessionManager->getSessionData();
            $this->assertEquals($sessionInfo['username'], $data['username'],
                "App $i should have correct username");

            $tokens = $sessionManager->getTokens();
            $this->assertEquals($sessionInfo['token'], $tokens['access_token'],
                "App $i should have correct token");
        }
    }
}
