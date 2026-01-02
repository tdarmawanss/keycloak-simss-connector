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

    /**
     * Token Refresh Buffer (Optional)
     * Seconds before token expiry to trigger a refresh
     * Default: 60
     */
    // 'token_refresh_buffer' => 60,

    /**
     * Enable Silent SSO (Optional)
     * When refresh token expires but SSO session is valid, automatically
     * re-authenticate without showing login page
     * Set to false for high-security apps requiring explicit re-login
     * Default: true
     */
    // 'enable_silent_sso' => true,

    /**
     * cURL Request Timeout (Optional)
     * Maximum time in seconds for the entire HTTP request to complete
     * Applies to token exchange, userinfo, and token refresh requests
     *
     * RECOMMENDED: 15-20 seconds for production
     * - Lower timeout = faster failure detection
     * - Automatic retry logic handles transient failures
     * - Total retry time: timeout * (1 + 2 + 4) = 7x timeout for 3 retries
     *
     * Default: 30
     */
    // 'curl_timeout' => 20,

    /**
     * cURL Connection Timeout (Optional)
     * Maximum time in seconds to establish connection to Keycloak
     *
     * RECOMMENDED: 5 seconds for production
     * - Fail fast on connection issues
     * - Automatic retry with exponential backoff
     *
     * Default: 10
     */
    // 'curl_connect_timeout' => 5,

    /**
     * Access Control Configuration (Optional)
     * Configure paths to role-based access control (RBAC) JSON files
     *
     * These files define:
     * - endpoint_permissions.json: Maps API endpoints to required module permissions
     * - role_permissions.json: Maps user roles to their module privileges (CRUD)
     *
     * If not specified, defaults to:
     * third_party/keycloak-simss-connector/config/access_control/[client_id]/endpoint_permissions.json
     * third_party/keycloak-simss-connector/config/access_control/[client_id]/role_permissions.json
     *
     * Example for custom client-specific paths:
     */
    // 'access_control' => [
    //     'endpoint_permissions' => APPPATH . 'third_party/keycloak-simss-connector/config/access_control/client_acme/endpoint_permissions.json',
    //     'role_permissions' => APPPATH . 'third_party/keycloak-simss-connector/config/access_control/client_acme/role_permissions.json'
    // ],
];
