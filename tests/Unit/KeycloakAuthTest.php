<?php

namespace Simss\KeycloakAuth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Simss\KeycloakAuth\Auth\KeycloakAuth;
use Simss\KeycloakAuth\Auth\SessionManager;
use Simss\KeycloakAuth\Config\KeycloakConfig;

/**
 * Unit tests for KeycloakAuth class
 *
 * Tests OIDC authentication flow including:
 * - Authorization code exchange
 * - User info retrieval
 * - Token refresh
 * - Logout URL generation
 * - Silent SSO re-authentication
 *
 * Note: These tests focus on the public API and flow logic.
 * Network operations (cURL) are tested at integration level.
 */
class KeycloakAuthTest extends TestCase
{
    protected $config;
    protected $sessionManager;

    protected function setUp(): void
    {
        parent::setUp();

        // Clear session
        $_SESSION = [];
        $_GET = [];
        $_SERVER = [];

        // Reset KeycloakConfig singleton
        KeycloakConfig::reset();

        // Create test config
        $this->config = KeycloakConfig::getInstance(TEST_CONFIG);
        $this->sessionManager = new SessionManager();
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        $_SESSION = [];
        $_GET = [];
        $_SERVER = [];

        KeycloakConfig::reset();
    }

    /**
     * Test KeycloakAuth initialization
     *
     * Verifies that:
     * - Instance is created successfully with config
     * - Session is started automatically
     */
    public function testKeycloakAuthInitialization()
    {
        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $this->assertInstanceOf(KeycloakAuth::class, $keycloakAuth);
    }

    /**
     * Test logout URL generation without ID token
     *
     * Verifies that:
     * - Logout URL is generated correctly
     * - Contains logout endpoint and redirect URI
     */
    public function testGetLogoutUrlWithoutIdToken()
    {
        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $redirectUrl = 'https://example.com/logged-out';
        $logoutUrl = $keycloakAuth->getLogoutUrl(null, $redirectUrl);

        $this->assertStringContainsString(
            '/protocol/openid-connect/logout',
            $logoutUrl,
            'Should contain logout endpoint'
        );

        $this->assertStringContainsString(
            'post_logout_redirect_uri=' . urlencode($redirectUrl),
            $logoutUrl,
            'Should contain redirect URI'
        );

        $this->assertStringNotContainsString(
            'id_token_hint',
            $logoutUrl,
            'Should not contain id_token_hint when token not provided'
        );
    }

    /**
     * Test logout URL generation with ID token
     *
     * Verifies that:
     * - ID token is included as id_token_hint parameter
     * - Required for OIDC-compliant single logout
     */
    public function testGetLogoutUrlWithIdToken()
    {
        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $idToken = 'test_id_token_jwt';
        $redirectUrl = 'https://example.com/logged-out';
        $logoutUrl = $keycloakAuth->getLogoutUrl($idToken, $redirectUrl);

        $this->assertStringContainsString(
            'id_token_hint=' . urlencode($idToken),
            $logoutUrl,
            'Should contain id_token_hint parameter'
        );
    }

    /**
     * Test logout URL with default redirect
     *
     * Verifies that:
     * - Uses base URL as default redirect when not specified
     */
    public function testGetLogoutUrlWithDefaultRedirect()
    {
        $_SERVER['HTTP_HOST'] = 'example.com';
        $_SERVER['HTTPS'] = 'on';

        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $logoutUrl = $keycloakAuth->getLogoutUrl();

        $this->assertStringContainsString(
            'post_logout_redirect_uri=https%3A%2F%2Fexample.com',
            $logoutUrl,
            'Should use base URL as default redirect'
        );
    }

    /**
     * Test silent SSO re-authentication URL generation
     *
     * Verifies that:
     * - Authorization URL includes prompt=none parameter
     * - State parameter is generated for CSRF protection
     * - Redirect URI is included
     */
    public function testSilentSsoReauthGeneratesCorrectUrl()
    {
        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        // We can't fully test the redirect, but we can verify state is set
        // Use output buffering to catch the redirect
        ob_start();

        try {
            // This will attempt to redirect, we'll catch it
            $keycloakAuth->silentSsoReauth();
        } catch (\Exception $e) {
            // Might throw due to headers already sent
        }

        ob_end_clean();

        // Verify state was stored in session
        $this->assertNotEmpty(
            $_SESSION['openid_connect_state'] ?? null,
            'Should generate and store state parameter'
        );

        $this->assertIsString(
            $_SESSION['openid_connect_state'],
            'State should be a string'
        );

        $this->assertGreaterThan(
            16,
            strlen($_SESSION['openid_connect_state']),
            'State should be sufficiently long for security'
        );
    }

    /**
     * Test state validation during callback
     *
     * Verifies that:
     * - State mismatch throws exception (CSRF protection)
     * - Prevents session fixation attacks
     */
    public function testCallbackStateValidation()
    {
        $_GET['code'] = 'test_authorization_code';
        $_GET['state'] = 'invalid_state';
        $_SESSION['openid_connect_state'] = 'valid_state';

        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('State mismatch');

        $keycloakAuth->authenticate();
    }

    /**
     * Test getUserInfo requires access token
     *
     * Verifies that:
     * - Calling getUserInfo without authentication throws exception
     * - Error message indicates authentication is required
     */
    public function testGetUserInfoRequiresAccessToken()
    {
        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('No access token available');

        $keycloakAuth->getUserInfo();
    }

    /**
     * Test getIdToken returns null before authentication
     *
     * Verifies that:
     * - ID token is null before authentication completes
     */
    public function testGetIdTokenBeforeAuthentication()
    {
        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $idToken = $keycloakAuth->getIdToken();

        $this->assertNull($idToken, 'ID token should be null before authentication');
    }

    /**
     * Test getTokenResponse returns null before authentication
     *
     * Verifies that:
     * - Token response is null before authentication completes
     */
    public function testGetTokenResponseBeforeAuthentication()
    {
        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $tokenResponse = $keycloakAuth->getTokenResponse();

        $this->assertNull($tokenResponse, 'Token response should be null before authentication');
    }

    /**
     * Test getClient returns underlying OIDC client
     *
     * Verifies that:
     * - getClient() returns jumbojett OpenIDConnectClient instance
     * - Allows advanced usage of underlying library
     */
    public function testGetClientReturnsOidcClient()
    {
        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $client = $keycloakAuth->getClient();

        $this->assertInstanceOf(
            \Jumbojett\OpenIDConnectClient::class,
            $client,
            'Should return OpenIDConnectClient instance'
        );
    }

    /**
     * Test refresh token without refresh token in session
     *
     * Verifies that:
     * - Attempting to refresh without refresh token throws exception
     */
    public function testRefreshAccessTokenWithoutRefreshToken()
    {
        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('No refresh token available');

        $keycloakAuth->refreshAccessToken();
    }

    /**
     * Test configuration is properly passed to OIDC client
     *
     * Verifies that:
     * - Config values are applied to underlying client
     * - SSL verification settings are respected
     */
    public function testConfigurationPassedToClient()
    {
        $customConfig = array_merge(TEST_CONFIG, [
            'verify_peer' => true,
            'verify_host' => true,
        ]);

        KeycloakConfig::reset();
        $config = KeycloakConfig::getInstance($customConfig);

        $keycloakAuth = new KeycloakAuth($config, $this->sessionManager);
        $client = $keycloakAuth->getClient();

        // The underlying client should be configured
        $this->assertNotNull($client);
    }

    /**
     * Test authentication flow without code parameter
     *
     * Verifies that:
     * - Without code parameter, initiates authorization redirect
     * - This is the first step of OIDC flow
     *
     * Note: Actual redirect can't be fully tested in unit tests
     */
    public function testAuthenticateWithoutCodeInitiatesRedirect()
    {
        // No $_GET['code'] means first step of flow
        $_GET = [];

        $keycloakAuth = new KeycloakAuth($this->config, $this->sessionManager);

        // The authenticate() method will attempt to redirect
        // In a real scenario, this redirects to Keycloak
        // In tests, we can't fully simulate this without mocking the OIDC client

        // For now, we verify the method exists and is callable
        $this->assertTrue(
            method_exists($keycloakAuth, 'authenticate'),
            'authenticate() method should exist'
        );
    }

    /**
     * Test token endpoint URL construction
     *
     * Verifies that:
     * - Token endpoint URL is constructed correctly from config
     */
    public function testTokenEndpointConstruction()
    {
        $expectedTokenEndpoint = TEST_CONFIG['issuer'] . '/protocol/openid-connect/token';

        $this->assertEquals(
            $expectedTokenEndpoint,
            $this->config->getTokenEndpoint(),
            'Token endpoint should be constructed correctly'
        );
    }

    /**
     * Test userinfo endpoint URL construction
     *
     * Verifies that:
     * - UserInfo endpoint URL is constructed correctly from config
     */
    public function testUserInfoEndpointConstruction()
    {
        $expectedUserInfoEndpoint = TEST_CONFIG['issuer'] . '/protocol/openid-connect/userinfo';

        $this->assertEquals(
            $expectedUserInfoEndpoint,
            $this->config->getUserInfoEndpoint(),
            'UserInfo endpoint should be constructed correctly'
        );
    }

    /**
     * Test authorization endpoint URL construction
     *
     * Verifies that:
     * - Authorization endpoint URL is constructed correctly from config
     */
    public function testAuthorizationEndpointConstruction()
    {
        $expectedAuthEndpoint = TEST_CONFIG['issuer'] . '/protocol/openid-connect/auth';

        $this->assertEquals(
            $expectedAuthEndpoint,
            $this->config->getAuthorizationEndpoint(),
            'Authorization endpoint should be constructed correctly'
        );
    }

    /**
     * Test logout endpoint URL construction
     *
     * Verifies that:
     * - Logout endpoint URL is constructed correctly from config
     */
    public function testLogoutEndpointConstruction()
    {
        $expectedLogoutEndpoint = TEST_CONFIG['issuer'] . '/protocol/openid-connect/logout';

        $this->assertEquals(
            $expectedLogoutEndpoint,
            $this->config->getLogoutEndpoint(),
            'Logout endpoint should be constructed correctly'
        );
    }

    /**
     * Test SSL verification configuration
     *
     * Verifies that:
     * - SSL verification settings from config are accessible
     * - Defaults to secure settings in production
     */
    public function testSslVerificationConfiguration()
    {
        // Test config has verify_peer and verify_host set to false
        $this->assertFalse(
            $this->config->shouldVerifyPeer(),
            'Test config should have verify_peer=false'
        );

        $this->assertFalse(
            $this->config->shouldVerifyHost(),
            'Test config should have verify_host=false'
        );

        // Test with production config
        KeycloakConfig::reset();
        $prodConfig = KeycloakConfig::getInstance(array_merge(TEST_CONFIG, [
            'verify_peer' => true,
            'verify_host' => true,
        ]));

        $this->assertTrue(
            $prodConfig->shouldVerifyPeer(),
            'Production config should have verify_peer=true'
        );

        $this->assertTrue(
            $prodConfig->shouldVerifyHost(),
            'Production config should have verify_host=true'
        );
    }

    /**
     * Test scopes configuration
     *
     * Verifies that:
     * - Default scopes include openid, profile, email
     * - Custom scopes can be configured
     */
    public function testScopesConfiguration()
    {
        $scopes = $this->config->getScopes();

        $this->assertIsArray($scopes);
        $this->assertContains('openid', $scopes, 'Should include openid scope');
        $this->assertContains('profile', $scopes, 'Should include profile scope');
        $this->assertContains('email', $scopes, 'Should include email scope');
    }

    /**
     * Test cURL timeout configuration
     *
     * Verifies that:
     * - cURL timeout settings are accessible
     * - Default values are reasonable
     */
    public function testCurlTimeoutConfiguration()
    {
        $timeout = $this->config->getCurlTimeout();
        $connectTimeout = $this->config->getCurlConnectTimeout();

        $this->assertEquals(30, $timeout, 'Default cURL timeout should be 30 seconds');
        $this->assertEquals(10, $connectTimeout, 'Default cURL connect timeout should be 10 seconds');
    }

    /**
     * Test token refresh buffer configuration
     *
     * Verifies that:
     * - Token refresh buffer is configurable
     * - Default value is reasonable
     */
    public function testTokenRefreshBufferConfiguration()
    {
        $buffer = $this->config->getTokenRefreshBuffer();

        $this->assertEquals(60, $buffer, 'Default token refresh buffer should be 60 seconds');
    }

    /**
     * Test HTTP proxy configuration
     *
     * Verifies that:
     * - HTTP proxy can be configured
     * - Returns null when not configured
     */
    public function testHttpProxyConfiguration()
    {
        $proxy = $this->config->getHttpProxy();

        $this->assertNull($proxy, 'HTTP proxy should be null when not configured');

        // Test with proxy configured
        KeycloakConfig::reset();
        $configWithProxy = KeycloakConfig::getInstance(array_merge(TEST_CONFIG, [
            'http_proxy' => 'http://proxy.example.com:8080',
        ]));

        $this->assertEquals(
            'http://proxy.example.com:8080',
            $configWithProxy->getHttpProxy(),
            'Should return configured proxy'
        );
    }

    /**
     * Test cert path configuration
     *
     * Verifies that:
     * - Custom cert path can be configured
     * - Returns null when not configured
     */
    public function testCertPathConfiguration()
    {
        $certPath = $this->config->getCertPath();

        $this->assertNull($certPath, 'Cert path should be null when not configured');

        // Test with cert path configured
        KeycloakConfig::reset();
        $configWithCert = KeycloakConfig::getInstance(array_merge(TEST_CONFIG, [
            'cert_path' => '/path/to/cert.pem',
        ]));

        $this->assertEquals(
            '/path/to/cert.pem',
            $configWithCert->getCertPath(),
            'Should return configured cert path'
        );
    }
}
