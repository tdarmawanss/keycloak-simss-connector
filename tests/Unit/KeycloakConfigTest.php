<?php

namespace Simss\KeycloakAuth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Simss\KeycloakAuth\Config\KeycloakConfig;


/** 
 * Unit tests for KeycloakConfig class
 *
 * Tests configuration loading, validation, and getters.
 */
class KeycloakConfigTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        KeycloakConfig::reset();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        KeycloakConfig::reset();
    }

    public function testConfigurationLoadsCorrectly()
    {
        $config = KeycloakConfig::getInstance(TEST_CONFIG);

        $this->assertEquals('https://keycloak.test.local/realms/simss', $config->getIssuer());
        $this->assertEquals('test-client', $config->getClientId());
        $this->assertEquals('test-secret', $config->getClientSecret());
        $this->assertEquals('http://localhost/auth/callback', $config->getRedirectUri());
    }

    public function testMissingRequiredConfigThrowsException()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Missing required configuration");

        KeycloakConfig::getInstance(['issuer' => 'https://test.local']);
    }

    public function testInvalidIssuerUrlThrowsException()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid issuer URL");

        KeycloakConfig::getInstance([
            'issuer' => 'not-a-url',
            'client_id' => 'test',
            'client_secret' => 'secret',
            'redirect_uri' => 'http://localhost/callback',
        ]);
    }

    public function testInvalidRedirectUriThrowsException()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid redirect_uri URL");

        KeycloakConfig::getInstance([
            'issuer' => 'https://test.local',
            'client_id' => 'test',
            'client_secret' => 'secret',
            'redirect_uri' => 'not-a-url',
        ]);
    }

    public function testGetWithDefault()
    {
        $config = KeycloakConfig::getInstance(TEST_CONFIG);

        $this->assertEquals('default-value', $config->get('non_existent_key', 'default-value'));
        $this->assertEquals('test-client', $config->get('client_id', 'default'));
    }

    public function testEndpointsAreGeneratedCorrectly()
    {
        $config = KeycloakConfig::getInstance(TEST_CONFIG);

        $expectedBase = 'https://keycloak.test.local/realms/simss/protocol/openid-connect';

        $this->assertEquals($expectedBase . '/token', $config->getTokenEndpoint());
        $this->assertEquals($expectedBase . '/userinfo', $config->getUserInfoEndpoint());
        $this->assertEquals($expectedBase . '/auth', $config->getAuthorizationEndpoint());
        $this->assertEquals($expectedBase . '/logout', $config->getLogoutEndpoint());
    }

    public function testDefaultScopes()
    {
        $config = KeycloakConfig::getInstance(TEST_CONFIG);

        $scopes = $config->getScopes();
        $this->assertIsArray($scopes);
        $this->assertContains('openid', $scopes);
        $this->assertContains('profile', $scopes);
        $this->assertContains('email', $scopes);
    }

    public function testCustomScopes()
    {
        $customConfig = array_merge(TEST_CONFIG, [
            'scopes' => ['openid', 'custom-scope'],
        ]);

        $config = KeycloakConfig::getInstance($customConfig);

        $scopes = $config->getScopes();
        $this->assertEquals(['openid', 'custom-scope'], $scopes);
    }

    public function testVerificationSettings()
    {
        $config = KeycloakConfig::getInstance(TEST_CONFIG);

        $this->assertFalse($config->shouldVerifyPeer());
        $this->assertFalse($config->shouldVerifyHost());
    }

    public function testSingletonPattern()
    {
        $config1 = KeycloakConfig::getInstance(TEST_CONFIG);
        $config2 = KeycloakConfig::getInstance();

        $this->assertSame($config1, $config2);
    }

    public function testToArray()
    {
        $config = KeycloakConfig::getInstance(TEST_CONFIG);

        $array = $config->toArray();
        $this->assertIsArray($array);
        $this->assertEquals(TEST_CONFIG['issuer'], $array['issuer']);
        $this->assertEquals(TEST_CONFIG['client_id'], $array['client_id']);
    }
}
