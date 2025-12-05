<?php

namespace Simss\KeycloakAuth\Middleware;

use Simss\KeycloakAuth\Auth\SessionManager;
use Simss\KeycloakAuth\Auth\KeycloakAuth;

/**
 * AuthMiddleware - Protect routes requiring authentication
 *
 * Can be used as a CodeIgniter hook or standalone
 */
class AuthMiddleware
{
    protected $sessionManager;
    protected $keycloakAuth;
    protected $excludedPaths;

    public function __construct(array $excludedPaths = [])
    {
        $this->sessionManager = new SessionManager();
        $this->keycloakAuth = new KeycloakAuth();
        $this->excludedPaths = array_merge([
            '/auth',
            '/auth/login',
            '/auth/callback',
            '/auth/logout',
        ], $excludedPaths);
    }

    /**
     * Check if current request requires authentication
     */
    public function check()
    {
        // Get current path
        $currentPath = $this->getCurrentPath();

        // Skip authentication for excluded paths
        if ($this->isExcludedPath($currentPath)) {
            return true;
        }

        // Check if user is authenticated
        if (!$this->sessionManager->isAuthenticated()) {
            $this->redirectToLogin();
            return false;
        }

        // Check if token is expired and try to refresh
        if ($this->sessionManager->isTokenExpired()) {
            $this->handleTokenExpiry();
            return false;
        }

        return true;
    }

    /**
     * Check authentication and redirect if not authenticated
     */
    public function requireAuth()
    {
        if (!$this->sessionManager->isAuthenticated()) {
            $this->redirectToLogin();
            exit;
        }

        // Auto-refresh token if needed
        if ($this->sessionManager->isTokenExpired()) {
            $this->handleTokenExpiry();
        }
    }

    /**
     * Handle token expiry by attempting refresh
     */
    protected function handleTokenExpiry()
    {
        try {
            $refreshToken = $this->sessionManager->getRefreshToken();

            if (!$refreshToken) {
                throw new \RuntimeException("No refresh token available");
            }

            // Attempt to refresh
            $newTokens = $this->keycloakAuth->refreshToken($refreshToken);

            // Update session with new tokens
            $this->sessionManager->updateTokens($newTokens);

        } catch (\Exception $e) {
            // Refresh failed, redirect to login
            $this->sessionManager->destroy();
            $this->redirectToLogin();
            exit;
        }
    }

    /**
     * Redirect to login page
     */
    protected function redirectToLogin()
    {
        $loginUrl = $this->getLoginUrl();

        // Store intended URL for post-login redirect
        $intendedUrl = $this->getCurrentUrl();
        $this->storeIntendedUrl($intendedUrl);

        if (function_exists('redirect')) {
            redirect($loginUrl);
        } else {
            header("Location: " . $loginUrl);
            exit;
        }
    }

    /**
     * Check if current path is excluded from authentication
     */
    protected function isExcludedPath($path)
    {
        foreach ($this->excludedPaths as $excludedPath) {
            if (strpos($path, $excludedPath) === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get current request path
     */
    protected function getCurrentPath()
    {
        if (function_exists('uri_string')) {
            return '/' . uri_string();
        }

        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
        return $path ?: '/';
    }

    /**
     * Get current full URL
     */
    protected function getCurrentUrl()
    {
        if (function_exists('current_url')) {
            return current_url();
        }

        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $uri = $_SERVER['REQUEST_URI'] ?? '/';

        return $protocol . $host . $uri;
    }

    /**
     * Get login URL
     */
    protected function getLoginUrl()
    {
        return function_exists('base_url')
            ? base_url('auth/login')
            : $this->getBaseUrl() . '/auth/login';
    }

    /**
     * Get base URL
     */
    protected function getBaseUrl()
    {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $script = dirname($_SERVER['SCRIPT_NAME']);
        $base = $protocol . $host . ($script !== '/' ? $script : '');
        return rtrim($base, '/');
    }

    /**
     * Store intended URL for post-login redirect
     */
    protected function storeIntendedUrl($url)
    {
        if (function_exists('get_instance')) {
            $ci =& get_instance();
            $ci->session->set_userdata('intended_url', $url);
        } else {
            $_SESSION['intended_url'] = $url;
        }
    }

    /**
     * Get and clear intended URL
     */
    public function getIntendedUrl($default = null)
    {
        if (function_exists('get_instance')) {
            $ci =& get_instance();
            $url = $ci->session->userdata('intended_url');
            $ci->session->unset_userdata('intended_url');
            return $url ?: $default;
        } else {
            $url = $_SESSION['intended_url'] ?? null;
            unset($_SESSION['intended_url']);
            return $url ?: $default;
        }
    }
}
