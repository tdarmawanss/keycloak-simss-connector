<?php

namespace Simss\KeycloakAuth\Controllers;

use Simss\KeycloakAuth\Auth\KeycloakAuth;
use Simss\KeycloakAuth\Auth\SessionManager;
use Simss\KeycloakAuth\Config\KeycloakConfig;

/**
 * AuthController - Main authentication controller for Keycloak OIDC
 *
 * This controller can be used standalone or extended by CodeIgniter applications
 */
class AuthController
{
    protected $keycloakAuth;
    protected $sessionManager;
    protected $config;
    protected $ci;

    public function __construct()
    {
        // Initialize configuration
        try {
            $this->config = KeycloakConfig::getInstance();
        } catch (\Exception $e) {
            $this->handleError("Configuration error: " . $e->getMessage());
            return;
        }

        // Initialize auth and session managers
        $this->keycloakAuth = new KeycloakAuth($this->config);
        $this->sessionManager = new SessionManager();

        // Load CodeIgniter instance if available
        if (function_exists('get_instance')) {
            $this->ci =& get_instance();
        }
    }

    /**
     * Index - Display login page or redirect if already authenticated
     */
    public function index()
    {
        // Destroy any existing session
        $this->sessionManager->destroy();

        if ($this->sessionManager->isAuthenticated()) {
            $this->redirect($this->getHomeUrl());
            return;
        }

        $this->loadView('auth-login', [
            'login_url' => $this->getLoginUrl(),
        ]);
    }

    /**
     * Login - Initiate OIDC authentication flow
     */
    public function login()
    {
        try {
            // Check if already authenticated
            if ($this->sessionManager->isAuthenticated()) {
                $this->redirect($this->getHomeUrl());
                return;
            }

            // Initiate OIDC authentication
            // This will redirect to Keycloak login page
            $this->keycloakAuth->authenticate();

            // If we reach here, authentication was successful
            // Get user info and create session
            $this->handleSuccessfulAuthentication();

        } catch (\Exception $e) {
            $this->handleError("Authentication failed: " . $e->getMessage());
        }
    }

    /**
     * Callback - Handle OIDC callback after authentication
     */
    public function callback()
    {
        try {
            // The authenticate method will handle the callback
            $this->keycloakAuth->authenticate();

            // Get user information
            $this->handleSuccessfulAuthentication();

        } catch (\Exception $e) {
            $this->handleError("Callback failed: " . $e->getMessage());
        }
    }

    /**
     * Logout - Clear session and redirect to Keycloak logout
     */
    public function logout()
    {
        try {
            // Get ID token before destroying session
            $idToken = $this->sessionManager->getIdToken();

            // Destroy local session
            $this->sessionManager->destroy();

            // Build logout URL
            $postLogoutRedirect = $this->getBaseUrl();
            $logoutUrl = $this->keycloakAuth->getLogoutUrl($idToken, $postLogoutRedirect);

            // Redirect to Keycloak logout
            $this->redirect($logoutUrl);

        } catch (\Exception $e) {
            // Even if logout fails, destroy local session
            $this->sessionManager->destroy();
            $this->handleError("Logout failed: " . $e->getMessage());
        }
    }

    /**
     * Refresh - Refresh access token using refresh token
     */
    public function refresh()
    {
        try {
            $refreshToken = $this->sessionManager->getRefreshToken();

            if (!$refreshToken) {
                throw new \RuntimeException("No refresh token available");
            }

            // Refresh tokens
            $newTokens = $this->keycloakAuth->refreshToken($refreshToken);

            // Update session with new tokens
            $this->sessionManager->updateTokens($newTokens);

            $this->respondJson([
                'success' => true,
                'message' => 'Token refreshed successfully',
            ]);

        } catch (\Exception $e) {
            $this->respondJson([
                'success' => false,
                'message' => 'Token refresh failed: ' . $e->getMessage(),
            ], 401);
        }
    }

    /**
     * Check - Check authentication status
     */
    public function check()
    {
        $isAuthenticated = $this->sessionManager->isAuthenticated();
        $isExpired = $this->sessionManager->isTokenExpired();

        $this->respondJson([
            'authenticated' => $isAuthenticated,
            'token_expired' => $isExpired,
            'user' => $isAuthenticated ? $this->sessionManager->getSessionData() : null,
        ]);
    }

    /**
     * Handle successful authentication
     */
    protected function handleSuccessfulAuthentication()
    {
        // Get user information from Keycloak
        $userInfo = $this->keycloakAuth->getUserInfo();

        // Get tokens
        $tokens = [
            'access_token' => $this->keycloakAuth->getAccessToken(),
            'refresh_token' => $this->keycloakAuth->getRefreshToken(),
            'id_token' => $this->keycloakAuth->getIdToken(),
        ];

        // Create session
        $this->sessionManager->createSession($userInfo, $tokens);

        // Redirect to home page
        $this->redirect($this->getHomeUrl());
    }

    /**
     * Handle errors
     */
    protected function handleError($message)
    {
        if ($this->isAjaxRequest()) {
            $this->respondJson([
                'success' => false,
                'message' => $message,
            ], 400);
        } else {
            $this->loadView('auth-error', [
                'error' => $message,
                'login_url' => $this->getLoginUrl(),
            ]);
        }
    }

    /**
     * Helper methods
     */
    protected function redirect($url)
    {
        if (function_exists('redirect')) {
            redirect($url);
        } else {
            header("Location: " . $url);
            exit;
        }
    }

    protected function loadView($view, $data = [])
    {
        if ($this->ci) {
            $this->ci->load->view('pages/' . $view, $data);
        } else {
            // Fallback: output simple HTML
            echo "<html><body><pre>";
            print_r($data);
            echo "</pre></body></html>";
        }
    }

    protected function respondJson($data, $statusCode = 200)
    {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }

    protected function isAjaxRequest()
    {
        return !empty($_SERVER['HTTP_X_REQUESTED_WITH'])
            && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    }

    protected function getHomeUrl()
    {
        return function_exists('base_url')
            ? base_url('home')
            : $this->getBaseUrl() . '/home';
    }

    protected function getLoginUrl()
    {
        return function_exists('base_url')
            ? base_url('auth/login')
            : $this->getBaseUrl() . '/auth/login';
    }

    protected function getBaseUrl()
    {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $script = dirname($_SERVER['SCRIPT_NAME']);
        $base = $protocol . $host . ($script !== '/' ? $script : '');
        return rtrim($base, '/');
    }
}
