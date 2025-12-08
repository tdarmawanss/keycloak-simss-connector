<?php

/**
 * Keycloak OIDC Configuration
 *
 * Copy this file to ==your application's== config directory and customize it.
 * For CodeIgniter: application/config/keycloak.php
 */

return [
    /**
     * Keycloak realm URL (issuer)
     * This is the base URL of your Keycloak realm
     * Format: https://your-keycloak-server/realms/your-realm-name
     */
    'issuer' => 'https://keycloak.example.com/realms/simss',

    /**
     * Client ID
     * The client identifier configured in Keycloak
     */
    'client_id' => 'simadis',

    /**
     * Client Secret
     * The client secret from Keycloak (Clients > Credentials)
     * IMPORTANT: Keep this secret and never commit to version control
     */
    'client_secret' => 'your-client-secret-here',

    /**
     * Redirect URI
     * The callback URL where Keycloak will redirect after authentication
     * Must match one of the Valid Redirect URIs in Keycloak client settings
     */
    'redirect_uri' => 'https://your-app.com/auth/callback',

    /**
     * OAuth2/OIDC Scopes
     * Scopes to request during authentication
     * Default: ['openid', 'profile', 'email']
     */
    'scopes' => ['openid', 'profile', 'email'],

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
    'verify_peer' => true,
    'verify_host' => true,

    /**
     * Certificate Path (Optional)
     * Path to CA certificate bundle for SSL verification
     */
    // 'cert_path' => '/path/to/certificate.pem',

    /**
     * HTTP Proxy (Optional)
     * Proxy server if required for outbound connections
     */
    // 'http_proxy' => 'http://proxy.example.com:8080',
];
