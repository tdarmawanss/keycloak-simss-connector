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
            'kdcab' => 'CAB001',
            'inicab' => 'STO001',
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
        $this->assertEquals('CAB001', $userData['kdcab']);
        $this->assertEquals('STO001', $userData['inicab']);
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

        // Token expires in 1 second (should not be expired)
        $tokens = ['access_token' => 'token', 'expires_in' => 3600];
        $this->sessionManager->createSession($userInfo, $tokens);
        $this->assertFalse($this->sessionManager->isTokenExpired());

        // Token expired in the past
        $expiredTokens = ['access_token' => 'token', 'expires_in' => -100];
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

        $this->sessionManager->destroy();

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
}
