<?php

namespace Simss\KeycloakAuth\Auth;

use Jumbojett\OpenIDConnectClient;
use Simss\KeycloakAuth\Config\KeycloakConfig;

/**
 * KeycloakAuth - OIDC client for Keycloak authentication
 * 
 * Handles the Authorization Code flow for SSR applications.
 */
class KeycloakAuth
{
    private $oidcClient;
    private $config;

    public function __construct(KeycloakConfig $config = null)
    {
        $this->config = $config ?: KeycloakConfig::getInstance();
        $this->initializeClient();
    }

    private function initializeClient()
    {
        //configures OIDC client using JumboJett library
        $this->oidcClient = new OpenIDConnectClient(
            $this->config->getIssuer(),
            $this->config->getClientId(),
            $this->config->getClientSecret()
        );

        // Set redirect URI
        $this->oidcClient->setRedirectURL($this->config->getRedirectUri());

        // Set endpoints explicitly
        $this->oidcClient->setProviderURL($this->config->getIssuer());

        // Configure SSL verification
        $this->oidcClient->setVerifyPeer($this->config->shouldVerifyPeer());
        $this->oidcClient->setVerifyHost($this->config->shouldVerifyHost());

        // Optional: Set certificate path
        if ($certPath = $this->config->getCertPath()) {
            $this->oidcClient->setCertPath($certPath);
        }

        // Optional: Set HTTP proxy
        if ($proxy = $this->config->getHttpProxy()) {
            $this->oidcClient->setHttpProxy($proxy);
        }

        // Set client scopes
        $scopes = $this->config->getScopes();
        foreach ($scopes as $scope) {
            $this->oidcClient->addScope($scope);
        }
    }

    /**
     * Initiate or complete OIDC authentication
     */
    public function authenticate()
    {
        try {
            $this->oidcClient->authenticate();
            return true;
        } catch (\Exception $e) {
            throw new \RuntimeException("Authentication failed: " . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Get user info from Keycloak
     */
    public function getUserInfo()
    {
        try {
            $userInfo = $this->oidcClient->requestUserInfo();

            if (!$userInfo) {
                throw new \RuntimeException("Failed to retrieve user information");
            }

            return $userInfo;
        } catch (\Exception $e) {
            throw new \RuntimeException("Failed to get user info: " . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Get ID token (needed for OIDC logout)
     */
    public function getIdToken()
    {
        return $this->oidcClient->getIdToken();
    }

    /**
     * Get logout URL for OIDC single logout
     */
    public function getLogoutUrl($idToken = null, $redirectUrl = null)
    {
        $logoutEndpoint = $this->config->getLogoutEndpoint();

        $params = [];

        if ($idToken) {
            $params['id_token_hint'] = $idToken;
        }

        if ($redirectUrl) {
            $params['post_logout_redirect_uri'] = $redirectUrl;
        } else {
            // Default to application base URL
            $params['post_logout_redirect_uri'] = $this->getBaseUrl();
        }

        return $logoutEndpoint . '?' . http_build_query($params);
    }

    private function getBaseUrl()
    {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        return $protocol . $host;
    }

    /**
     * Get the underlying OIDC client (for advanced usage)
     */
    public function getClient()
    {
        return $this->oidcClient;
    }
}
