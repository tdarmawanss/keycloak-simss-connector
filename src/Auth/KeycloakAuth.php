<?php

namespace Simss\KeycloakAuth\Auth;

use Jumbojett\OpenIDConnectClient;
use Simss\KeycloakAuth\Config\KeycloakConfig;

/**
 * KeycloakAuth - OIDC client for Keycloak authentication
 * 
 * Handles the Authorization Code flow for SSR applications, using Keycloak.
 * This class is NOT exposed to the client, to be used internally by the connector.
 * 
 * NOTE: This class uses a hybrid approach:
 * - The jumbojett/OpenIDConnectClient library is used for initiating the login
 *   redirect (generating state, nonce, and authorization URL)
 * - Manual cURL is used for token exchange and userinfo requests
 * 
 * Why manual cURL instead of the library?
 * The jumbojett library's internal fetchURL() method can fail with "Connection refused"
 * on some server configurations (particularly with Azure-hosted Keycloak instances).
 * This appears to be related to missing timeout settings and potential IPv4/IPv6 issues.
 * Using direct cURL with explicit timeout settings resolves these connection problems.
 * 
 * @see https://github.com/jumbojett/OpenID-Connect-PHP
 */
class KeycloakAuth
{
    /** @var OpenIDConnectClient Used only for generating login redirect */
    private $oidcClient;
    
    /** @var KeycloakConfig */
    private $config;
    
    /** @var string|null Access token from token exchange */
    private $accessToken;
    
    /** @var string|null ID token from token exchange (needed for logout) */
    private $idToken;
    
    /** @var object|null Full token response from Keycloak */
    private $tokenResponse;

    public function __construct(KeycloakConfig $config = null)
    {
        // Native PHP session required for storing OAuth state parameter
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $this->config = $config ?: KeycloakConfig::getInstance();
        $this->initializeClient();
    }

    /**
     * Initialize the jumbojett OIDC client
     * Used only for generating the authorization redirect URL
     */
    private function initializeClient()
    {
        $this->oidcClient = new OpenIDConnectClient(
            $this->config->getIssuer(),
            $this->config->getClientId(),
            $this->config->getClientSecret()
        );

        $this->oidcClient->setRedirectURL($this->config->getRedirectUri());
        $this->oidcClient->setProviderURL($this->config->getIssuer());
        $this->oidcClient->setVerifyPeer($this->config->shouldVerifyPeer());
        $this->oidcClient->setVerifyHost($this->config->shouldVerifyHost());

        if ($certPath = $this->config->getCertPath()) {
            $this->oidcClient->setCertPath($certPath);
        }

        if ($proxy = $this->config->getHttpProxy()) {
            $this->oidcClient->setHttpProxy($proxy);
        }

        // Add requested scopes
        foreach ($this->config->getScopes() as $scope) {
            $this->oidcClient->addScope($scope);
        }
    }

    /**
     * Initiate or complete OIDC authentication
     * 
     * Flow:
     * 1. If no 'code' param → redirect user to Keycloak login page
     * 2. If 'code' param present → exchange code for tokens
     * 
     * @return bool True on success
     * @throws \RuntimeException On authentication failure
     */
    public function authenticate()
    {
        // Step 1: No code = user needs to authenticate at Keycloak
        if (!isset($_GET['code'])) {
            // This redirects to Keycloak and exits
            $this->oidcClient->authenticate();
            return true;
        }

        // Step 2: We have a code = user returned from Keycloak
        // Validate state parameter to prevent CSRF attacks
        $urlState = $_GET['state'] ?? '';
        $sessionState = $_SESSION['openid_connect_state'] ?? '';
        
        if (empty($urlState) || $urlState !== $sessionState) {
            throw new \RuntimeException("State mismatch - possible CSRF attack");
        }

        // Exchange authorization code for tokens
        $this->exchangeCodeForTokens($_GET['code']);
        
        return true;
    }

    /**
     * Exchange authorization code for access/ID tokens
     * 
     * Uses direct cURL instead of jumbojett library to avoid connection issues.
     * Key settings that make this work:
     * - CURLOPT_TIMEOUT: 30 seconds for the entire request
     * - CURLOPT_CONNECTTIMEOUT: 10 seconds for connection establishment
     * 
     * @param string $code Authorization code from Keycloak callback
     * @throws \RuntimeException On token exchange failure
     */
    private function exchangeCodeForTokens($code)
    {
        $tokenEndpoint = $this->config->getTokenEndpoint();
        
        $ch = curl_init($tokenEndpoint);
        
        // Essential: Set explicit timeouts (missing in jumbojett library)
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        
        // SSL settings
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->config->shouldVerifyPeer());
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->config->shouldVerifyHost() ? 2 : 0);
        
        // POST the token request
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'authorization_code',
            'client_id' => $this->config->getClientId(),
            'client_secret' => $this->config->getClientSecret(),
            'code' => $code,
            'redirect_uri' => $this->config->getRedirectUri(),
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
        
        $result = curl_exec($ch);
        $error = curl_error($ch);
        $errno = curl_errno($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($errno !== 0) {
            throw new \RuntimeException("Token exchange failed - curl error: $error");
        }
        
        if ($httpCode !== 200) {
            throw new \RuntimeException("Token exchange failed - HTTP $httpCode: $result");
        }
        
        $this->tokenResponse = json_decode($result);
        
        if (!$this->tokenResponse || !isset($this->tokenResponse->access_token)) {
            throw new \RuntimeException("Token exchange failed - invalid response");
        }
        
        $this->accessToken = $this->tokenResponse->access_token;
        $this->idToken = $this->tokenResponse->id_token ?? null;
        
        // Clear the state from session (one-time use for CSRF protection)
        unset($_SESSION['openid_connect_state']);
    }

    /**
     * Fetch user information from Keycloak's userinfo endpoint
     * 
     * Requires access token. 
     * Must be called after successful authenticate() which obtains the access token.
     * Uses direct cURL for consistency with token exchange.
     * 
     * @return object User info object with claims (sub, email, name, etc.)
     * @throws \RuntimeException If no access token or request fails
     */
    public function getUserInfo()
    {
        if (!$this->accessToken) {
            throw new \RuntimeException("No access token available - authenticate first");
        }

        $userInfoEndpoint = $this->config->getUserInfoEndpoint();
        
        $ch = curl_init($userInfoEndpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->config->shouldVerifyPeer());
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->config->shouldVerifyHost() ? 2 : 0);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $this->accessToken,
            'Accept: application/json',
        ]);
        
        $result = curl_exec($ch);
        $error = curl_error($ch);
        $errno = curl_errno($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($errno !== 0) {
            throw new \RuntimeException("UserInfo request failed - curl error: $error");
        }
        
        if ($httpCode !== 200) {
            throw new \RuntimeException("UserInfo request failed - HTTP $httpCode: $result");
        }
        
        $userInfo = json_decode($result);
        
        if (!$userInfo) {
            throw new \RuntimeException("Failed to retrieve user information");
        }

        return $userInfo;
    }

    /**
     * Get the ID token obtained during authentication
     * 
     * The ID token is required for OIDC-compliant single logout (RP-initiated logout).
     * It's passed as id_token_hint to Keycloak's end_session_endpoint.
     * 
     * @return string|null The ID token JWT, or null if not available
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * Build the OIDC logout URL for single sign-out
     * 
     * @param string|null $idToken ID token for the id_token_hint parameter
     * @param string|null $redirectUrl Where to redirect after logout
     * @return string Full logout URL to redirect the user to
     */
    public function getLogoutUrl($idToken = null, $redirectUrl = null)
    {
        // keycloak logout endpoint
        $logoutEndpoint = $this->config->getLogoutEndpoint();

        $params = [];

        if ($idToken) {
            $params['id_token_hint'] = $idToken;
        }

        if ($redirectUrl) {
            $params['post_logout_redirect_uri'] = $redirectUrl;
        } else {
            $params['post_logout_redirect_uri'] = $this->getBaseUrl();
        }
        
        // idtoken, post logout redirect are sent as params to keycloak
        return $logoutEndpoint . '?' . http_build_query($params);
    }

    /**
     * Get application base URL
     */
    private function getBaseUrl()
    {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        return $protocol . $host;
    }

    /**
     * Get the underlying jumbojett OIDC client for advanced usage
     * 
     * @return OpenIDConnectClient
     */
    public function getClient()
    {
        return $this->oidcClient;
    }
}
