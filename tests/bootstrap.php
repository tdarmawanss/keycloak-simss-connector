<?php

// Load Composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';

// Start session for tests
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Define test configuration
define('TEST_CONFIG', [
    'issuer' => 'https://keycloak.test.local/realms/simss',

    /**
     * Client ID
     * The client identifier configured in Keycloak
     */
    'client_id' => 'test-client',

    /**
     * Client Secret
     * The client secret from Keycloak (Clients > Credentials)
     * IMPORTANT: Keep this secret and never commit to version control
     */
    'client_secret' => 'test-secret',

    /**
     * Redirect URI
     * The callback URL where Keycloak will redirect after authentication
     * Must match one of the Valid Redirect URIs in Keycloak client settings
     */
    'redirect_uri' => 'http://localhost/auth/callback',

    /**
     *
     * OAuth2/OIDC Scopes
     * Scopes to request during authentication
     * Default: ['openid', 'profile', 'email']
     */
    'scopes' => ['openid', 'profile', 'email'],

    /**
     * Allow HTTP for testing
     * IMPORTANT: Only for testing! Use HTTPS in production.
     */
    'allow_http' => true,

    /**
     * Token Endpoint (Optional)
     * Auto-generated from issuer if not specified
     */
    // 'token_endpoint' => 'https://keycloak.example.com/realms/simss/protocol/openid-connect/token',

    /**
     * UserInfo Endpoint (Optional)
     * Auto-generated from issuer if not specified
     */
    // 'userinfo_endpoint' => 'https://keycloak.example.com/realms/simss/protocol/openid-connect/userinfo',

    /**
     * Authorization Endpoint (Optional)
     * Auto-generated from issuer if not specified
     */
    // 'authorization_endpoint' => 'https://keycloak.example.com/realms/simss/protocol/openid-connect/auth',

    /**
     * Logout Endpoint (Optional)
     * Auto-generated from issuer if not specified
     */
    // 'logout_endpoint' => 'https://keycloak.example.com/realms/simss/protocol/openid-connect/logout',

    /**
     * SSL Verification
     * IMPORTANT: Set to true in production!
     * Only disable for local development with self-signed certificates
     */
    'verify_peer' => false,
    'verify_host' => false,

]);
