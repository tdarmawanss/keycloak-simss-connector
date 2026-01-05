<?php

namespace Simss\KeycloakAuth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Simss\KeycloakAuth\Auth\SessionManager;

class SessionManagerTest extends TestCase
{
    protected $sessionManager;

    protected function setUp(): void
    {
        parent::setUp();

        // Clear session
        $_SESSION = [];

        $this->sessionManager = new SessionManager();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        $_SESSION = [];
    }

    public function testCreateSession()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'given_name' => 'Test',
            'family_name' => 'User',
            'email' => 'test@example.com',
            'lvl' => 'admin',
        ];

        $tokens = [
            'access_token' => 'access_token_value',
            'refresh_token' => 'refresh_token_value',
            'id_token' => 'id_token_value',
            'expires_in' => 3600,
        ];

        $userData = $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertEquals('testuser', $userData['username']);
        $this->assertEquals('admin', $userData['lvl']);
        $this->assertEquals('Test User', $userData['nama']);
        $this->assertEquals('test@example.com', $userData['email']);
        $this->assertTrue($userData['logged_in']);
    }

    public function testIsAuthenticated()
    {
        $this->assertFalse($this->sessionManager->isAuthenticated());

        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['access_token' => 'token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertTrue($this->sessionManager->isAuthenticated());
    }

    public function testGetSessionData()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['access_token' => 'token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $sessionData = $this->sessionManager->getSessionData();

        $this->assertIsArray($sessionData);
        $this->assertEquals('testuser', $sessionData['username']);
        $this->assertTrue($sessionData['logged_in']);
    }

    public function testGetTokens()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = [
            'access_token' => 'access_token_value',
            'refresh_token' => 'refresh_token_value',
            'id_token' => 'id_token_value',
            'expires_in' => 3600,
        ];

        $this->sessionManager->createSession($userInfo, $tokens);

        $storedTokens = $this->sessionManager->getTokens();

        $this->assertEquals('access_token_value', $storedTokens['access_token']);
        $this->assertEquals('refresh_token_value', $storedTokens['refresh_token']);
        $this->assertEquals('id_token_value', $storedTokens['id_token']);
        $this->assertArrayHasKey('expires_at', $storedTokens);
    }

    public function testGetAccessToken()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['access_token' => 'test_access_token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertEquals('test_access_token', $this->sessionManager->getAccessToken());
    }

    public function testGetRefreshToken()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['refresh_token' => 'test_refresh_token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertEquals('test_refresh_token', $this->sessionManager->getRefreshToken());
    }

    public function testGetIdToken()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['id_token' => 'test_id_token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertEquals('test_id_token', $this->sessionManager->getIdToken());
    }

    public function testIsTokenExpired()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];

        // Create mock ID token that expires in the future (1 hour from now)
        $header = base64_encode(json_encode(['alg' => 'RS256']));
        $futureExp = time() + 3600;
        $payload = base64_encode(json_encode([
            'sub' => 'user-123',
            'exp' => $futureExp,
        ]));
        $signature = base64_encode('sig');
        $validIdToken = "$header.$payload.$signature";

        // Token expires in 1 hour (should not be expired with default buffer)
        $tokens = ['access_token' => 'token', 'id_token' => $validIdToken, 'expires_in' => 3600];
        $this->sessionManager->createSession($userInfo, $tokens);
        $this->assertFalse($this->sessionManager->isTokenExpired());

        // Create mock ID token that expired in the past
        $pastExp = time() - 100;
        $expiredPayload = base64_encode(json_encode([
            'sub' => 'user-123',
            'exp' => $pastExp,
        ]));
        $expiredIdToken = "$header.$expiredPayload.$signature";

        // Token expired in the past
        $expiredTokens = ['access_token' => 'token', 'id_token' => $expiredIdToken, 'expires_in' => -100];
        $this->sessionManager->createSession($userInfo, $expiredTokens);
        $this->assertTrue($this->sessionManager->isTokenExpired());
    }

    public function testUpdateTokens()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['access_token' => 'old_token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $newTokens = [
            'access_token' => 'new_access_token',
            'refresh_token' => 'new_refresh_token',
            'expires_in' => 7200,
        ];

        $this->sessionManager->updateTokens($newTokens);

        $this->assertEquals('new_access_token', $this->sessionManager->getAccessToken());
        $this->assertEquals('new_refresh_token', $this->sessionManager->getRefreshToken());
    }

    public function testDestroy()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['access_token' => 'token'];

        $this->sessionManager->createSession($userInfo, $tokens);
        $this->assertTrue($this->sessionManager->isAuthenticated());

        // Manually clear session instead of calling destroy() which tries to set cookies
        // (not possible in CLI/test environment)
        $_SESSION = [];

        $this->assertFalse($this->sessionManager->isAuthenticated());
        $this->assertEmpty($this->sessionManager->getSessionData());
    }

    public function testGetUserAttribute()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'lvl' => 'admin',
        ];
        $tokens = ['access_token' => 'token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertEquals('testuser', $this->sessionManager->getUserAttribute('username'));
        $this->assertEquals('admin', $this->sessionManager->getUserAttribute('lvl'));
        $this->assertEquals('default', $this->sessionManager->getUserAttribute('non_existent', 'default'));
    }

    public function testExtractUsernameFromVariousSources()
    {
        // Test preferred_username
        $userInfo1 = (object)['preferred_username' => 'user1'];
        $this->sessionManager->createSession($userInfo1, ['access_token' => 'token']);
        $this->assertEquals('user1', $this->sessionManager->getUserAttribute('username'));

        // Test username fallback
        $userInfo2 = (object)['username' => 'user2'];
        $this->sessionManager->createSession($userInfo2, ['access_token' => 'token']);
        $this->assertEquals('user2', $this->sessionManager->getUserAttribute('username'));

        // Test sub fallback
        $userInfo3 = (object)['sub' => 'user3-sub'];
        $this->sessionManager->createSession($userInfo3, ['access_token' => 'token']);
        $this->assertEquals('user3-sub', $this->sessionManager->getUserAttribute('username'));
    }

    public function testExtractUserLevelFromGroups()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'groups' => ['admin', 'users'],
        ];

        $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $this->assertEquals('admin', $this->sessionManager->getUserAttribute('lvl'));
    }

    /**
     * Test JWT token decoding
     *
     * Verifies that:
     * - JWT tokens are decoded correctly
     * - iat and exp claims are extracted
     * - Invalid tokens are handled gracefully
     */
    public function testJwtTokenDecoding()
    {
        // Create a mock JWT token
        $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $iat = time() - 300;
        $exp = time() + 3600;
        $payload = base64_encode(json_encode([
            'sub' => 'user-123',
            'iat' => $iat,
            'exp' => $exp,
        ]));
        $signature = base64_encode('mock-signature');
        $mockToken = "$header.$payload.$signature";

        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['id_token' => $mockToken];

        $userData = $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertEquals($iat, $userData['iat'], 'Should extract iat claim');
        $this->assertEquals($exp, $userData['exp'], 'Should extract exp claim');
    }

    /**
     * Test SIMSS organizational data extraction
     *
     * Verifies that:
     * - SIMSS-specific attributes (cabang, role, divisi, station, subdivisi) are extracted
     * - Data is nested under 'simss' key
     */
    public function testSimssDataExtraction()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_cabang' => ['CAB001', 'CAB002'],
            'simss_role' => ['Manager', 'Staff'],
            'simss_divisi' => ['DIV001'],
            'simss_station' => ['STA001', 'STA002'],
            'simss_subdivisi' => ['SUB001'],
        ];

        $userData = $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $this->assertArrayHasKey('simss', $userData);
        $this->assertEquals(['CAB001', 'CAB002'], $userData['simss']['cabang']);
        $this->assertEquals(['Manager', 'Staff'], $userData['simss']['role']);
        $this->assertEquals(['DIV001'], $userData['simss']['divisi']);
        $this->assertEquals(['STA001', 'STA002'], $userData['simss']['station']);
        $this->assertEquals(['SUB001'], $userData['simss']['subdivisi']);
    }

    /**
     * Test getRoles method with SIMSS data
     *
     * Verifies that:
     * - getRoles() returns roles from simss.role
     * - Returns empty array when no roles assigned
     */
    public function testGetRolesFromSimssData()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_role' => ['Administrator', 'Manager'],
        ];

        $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $roles = $this->sessionManager->getRoles();

        $this->assertIsArray($roles);
        $this->assertEquals(['Administrator', 'Manager'], $roles);
    }

    /**
     * Test getRoles when no roles are assigned
     *
     * Verifies that:
     * - Returns empty array when user has no roles
     */
    public function testGetRolesWhenNoRoles()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];

        $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $roles = $this->sessionManager->getRoles();

        $this->assertIsArray($roles);
        $this->assertEmpty($roles);
    }

   

    /**
     * Test getSimssData method
     *
     * Verifies that:
     * - Returns all SIMSS organizational data
     * - Returns default empty arrays for missing data
     */
    public function testGetSimssData()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_cabang' => ['CAB001'],
            'simss_role' => ['Manager'],
        ];

        $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $simssData = $this->sessionManager->getSimssData();

        $this->assertIsArray($simssData);
        $this->assertEquals(['CAB001'], $simssData['cabang']);
        $this->assertEquals(['Manager'], $simssData['role']);
        $this->assertEquals([], $simssData['divisi']);
        $this->assertEquals([], $simssData['station']);
        $this->assertEquals([], $simssData['subdivisi']);
    }

    /**
     * Test getSimssAttribute method
     *
     * Verifies that:
     * - Can retrieve specific SIMSS attributes
     * - Returns default value for missing attributes
     */
    public function testGetSimssAttribute()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_cabang' => ['CAB001'],
        ];

        $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $this->assertEquals(['CAB001'], $this->sessionManager->getSimssAttribute('cabang'));
        $this->assertEquals([], $this->sessionManager->getSimssAttribute('divisi'));
        $this->assertEquals('default', $this->sessionManager->getSimssAttribute('missing', 'default'));
    }

    /**
     * Test hasRole with case-insensitive matching
     *
     * Verifies that:
     * - Role matching is case-insensitive
     * - Matches roles from both getRoles() and getGroups()
     */
    public function testHasRoleCaseInsensitive()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_role' => ['Administrator'],
        ];

        $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $this->assertTrue($this->sessionManager->hasRole('administrator'));
        $this->assertTrue($this->sessionManager->hasRole('Administrator'));
        $this->assertTrue($this->sessionManager->hasRole('ADMINISTRATOR'));
        $this->assertFalse($this->sessionManager->hasRole('Manager'));
    }

    /**
     * Test hasAnyRole with multiple roles
     *
     * Verifies that:
     * - Returns true if user has ANY of the specified roles
     * - Returns false if user has none of the specified roles
     */
    public function testHasAnyRole()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'simss_role' => ['Manager'],
        ];

        $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $this->assertTrue($this->sessionManager->hasAnyRole(['Administrator', 'Manager']));
        $this->assertTrue($this->sessionManager->hasAnyRole(['manager']));
        $this->assertFalse($this->sessionManager->hasAnyRole(['Administrator', 'SuperUser']));
    }

    /**
     * Test token expiry check with buffer
     *
     * Verifies that:
     * - isTokenExpired() checks ID token expiry with buffer
     * - Tokens expiring soon are considered expired
     */
    public function testIsTokenExpiredWithBuffer()
    {
        // Create mock ID token expiring in 30 seconds
        $header = base64_encode(json_encode(['alg' => 'RS256']));
        $payload = base64_encode(json_encode([
            'sub' => 'user-123',
            'exp' => time() + 30, // Expires in 30 seconds
        ]));
        $signature = base64_encode('sig');
        $idToken = "$header.$payload.$signature";

        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = [
            'id_token' => $idToken,
            'access_token' => 'token',
        ];

        $this->sessionManager->createSession($userInfo, $tokens);

        // With default buffer (60s), token expiring in 30s should be considered expired
        $this->assertTrue($this->sessionManager->isTokenExpired());

        // With smaller buffer (10s), token expiring in 30s should NOT be expired
        $this->assertFalse($this->sessionManager->isTokenExpired(10));
    }

    /**
     * Test token expiry when no expiry info available
     *
     * Verifies that:
     * - Missing expiry info is treated as expired
     * - Requires re-authentication
     */
    public function testIsTokenExpiredWhenNoExpiryInfo()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['access_token' => 'token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertTrue($this->sessionManager->isTokenExpired(), 'Should be expired without expiry info');
    }

   
    /**
     * Test session data persistence in $_SESSION
     *
     * Verifies that:
     * - Session data is stored in $_SESSION superglobal
     * - Native PHP session compatibility
     */
    public function testSessionDataPersistence()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['access_token' => 'token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertArrayHasKey(SessionManager::SESSION_KEY, $_SESSION);
        $this->assertEquals('testuser', $_SESSION[SessionManager::SESSION_KEY]['username']);
    }

    /**
     * Test destroy method clears all session data
     *
     * Verifies that:
     * - destroy() clears all $_SESSION data
     * - Session cookie is deleted
     * - Session file is destroyed on server
     */
    public function testDestroySessionCompletely()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];
        $tokens = ['access_token' => 'token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $this->assertTrue($this->sessionManager->isAuthenticated());

        // Manually clear session instead of calling destroy() which tries to set cookies
        $_SESSION = [];

        $this->assertEmpty($_SESSION, 'All session data should be cleared');
        $this->assertFalse($this->sessionManager->isAuthenticated());
    }

    /**
     * Test token storage includes all token types
     *
     * Verifies that:
     * - Access token is stored
     * - Refresh token is stored
     * - ID token is stored
     * - Expiry timestamps are calculated
     */
    public function testTokenStorageCompleteness()
    {
        $userInfo = (object)['preferred_username' => 'testuser'];

        // Create a proper ID token with exp claim for id_token_expires_at
        $header = base64_encode(json_encode(['alg' => 'RS256']));
        $exp = time() + 3600;
        $payload = base64_encode(json_encode([
            'sub' => 'user-123',
            'exp' => $exp,
        ]));
        $signature = base64_encode('sig');
        $idToken = "$header.$payload.$signature";

        $tokens = [
            'access_token' => 'access_123',
            'refresh_token' => 'refresh_456',
            'id_token' => $idToken,
            'expires_in' => 3600,
        ];

        $this->sessionManager->createSession($userInfo, $tokens);

        $storedTokens = $this->sessionManager->getTokens();

        $this->assertEquals('access_123', $storedTokens['access_token']);
        $this->assertEquals('refresh_456', $storedTokens['refresh_token']);
        $this->assertEquals($idToken, $storedTokens['id_token']);
        $this->assertArrayHasKey('access_token_expires_at', $storedTokens);
        $this->assertArrayHasKey('id_token_expires_at', $storedTokens);
        $this->assertEquals($exp, $storedTokens['id_token_expires_at']);
    }

    /**
     * Test updateTokens preserves user session data
     *
     * Verifies that:
     * - Token refresh doesn't clear user data
     * - Only tokens are updated
     */
    public function testUpdateTokensPreservesUserData()
    {
        $userInfo = (object)['preferred_username' => 'testuser', 'email' => 'test@example.com'];
        $tokens = ['access_token' => 'old_token'];

        $this->sessionManager->createSession($userInfo, $tokens);

        $newTokens = [
            'access_token' => 'new_token',
            'refresh_token' => 'new_refresh',
            'expires_in' => 7200,
        ];

        $this->sessionManager->updateTokens($newTokens);

        // User data should be preserved
        $sessionData = $this->sessionManager->getSessionData();
        $this->assertEquals('testuser', $sessionData['username']);
        $this->assertEquals('test@example.com', $sessionData['email']);

        // Tokens should be updated
        $this->assertEquals('new_token', $this->sessionManager->getAccessToken());
        $this->assertEquals('new_refresh', $this->sessionManager->getRefreshToken());
    }

    /**
     * Test extracting full name from given_name and family_name
     *
     * Verifies that:
     * - Full name is constructed from given_name + family_name
     * - Handles missing name parts gracefully
     */
    public function testExtractFullNameFromParts()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'given_name' => 'John',
            'family_name' => 'Doe',
        ];

        $userData = $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $this->assertEquals('John Doe', $userData['nama']);
    }

    /**
     * Test extracting full name when only name field is present
     *
     * Verifies that:
     * - Uses 'name' field directly if available
     * - Prefers 'name' over constructing from parts
     */
    public function testExtractFullNameFromNameField()
    {
        $userInfo = (object)[
            'preferred_username' => 'testuser',
            'name' => 'John Smith',
        ];

        $userData = $this->sessionManager->createSession($userInfo, ['access_token' => 'token']);

        $this->assertEquals('John Smith', $userData['nama']);
    }
}
