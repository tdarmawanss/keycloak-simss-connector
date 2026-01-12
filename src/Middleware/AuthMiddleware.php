<?php

namespace Simss\KeycloakAuth\Middleware;

use Simss\KeycloakAuth\Auth\KeycloakAuth;
use Simss\KeycloakAuth\Auth\SessionManager;

/**
 * AuthMiddleware - Protect routes requiring authentication
 *
 * For SSR applications, authentication is checked via server-side session.
 * Implements automatic token refresh and silent SSO re-authentication.
 */
class AuthMiddleware
{
    protected $sessionManager;
    protected $keycloakAuth;
    protected $excludedPaths;

    public function __construct(array $excludedPaths = [], KeycloakAuth $keycloakAuth = null)
    {
        $this->sessionManager = new SessionManager();
        $this->keycloakAuth = $keycloakAuth ?: new KeycloakAuth();
        $this->excludedPaths = array_merge([
            '/auth',
            '/auth/login',
            '/auth/callback',
            '/auth/logout',
            '/auth/check',
        ], $excludedPaths);
    }

    /**
     * Check if current request requires authentication
     */
    public function check()
    {
        // Ensure native PHP session is started (required for SessionManager)
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Get current path
        $currentPath = $this->getCurrentPath();

        // Skip authentication for excluded paths
        if ($this->isExcludedPath($currentPath)) {
            return true;
        }

        // Check if user is authenticated with valid token
        if (!$this->isAuthenticatedWithValidToken()) {
            $this->redirectToLogin();
            return false;
        }

        return true;
    }

    /**
     * Check authentication and redirect if not authenticated
     */
    public function requireAuth()
    {
        if (!$this->isAuthenticatedWithValidToken()) {
            $this->setIdleNotice();
            $this->redirectToLogin();
            exit;
        }
    }

    /**
     * Check if user has a specific role
     */
    public function hasRole($role)
    {
        return $this->sessionManager->hasRole($role);
    }

    /**
     * Require a specific role, redirect to home if not authorized
     */
    public function requireRole($role)
    {
        $this->requireAuth();

        if (!$this->hasRole($role)) {
            // User is authenticated but doesn't have required role
            $this->redirectToHome();
            exit;
        }
    }

    /**
     * Require any of the provided roles
     */
    public function requireAnyRole(array $roles)
    {
        $this->requireAuth();

        if (!$this->sessionManager->hasAnyRole($roles)) {
            $this->redirectToHome();
            exit;
        }
    }

    /**
     * Check if user is authenticated AND has valid tokens
     * Automatically refreshes tokens if needed
     *
     * @return bool True if authenticated with valid token
     */
    protected function isAuthenticatedWithValidToken()
    {
        // Step 1: Check basic session authentication
        if (!$this->sessionManager->isAuthenticated()) {
            return false;
        }

        // Step 2: Check if tokens exist (migration path)
        if (!$this->sessionManager->getAccessToken()) {
            // Legacy session without tokens - force re-login
            $this->sessionManager->destroy();
            return false;
        }

        // Step 3: Check token expiry
        if (!$this->sessionManager->isTokenExpired()) {
            // Token is valid, user is authenticated
            return true;
        }

        // Step 4: Token expired - attempt refresh
        try {
            return $this->attemptTokenRefresh();
        } catch (\Exception $e) {
            // Refresh failed - log and treat as unauthenticated
            $this->logTokenRefreshError($e);
            return false;
        }
    }

    /**
     * Attempt to refresh tokens (access, refresh, and ID tokens) or initiate silent SSO re-auth
     *
     * When ID token expires, this method:
     * 1. Attempts to refresh all tokens using the refresh token (includes new ID token)
     * 2. If refresh fails, attempts silent SSO re-authentication
     * 3. If both fail, destroys session and requires login
     *
     * @return bool True if tokens refreshed successfully
     */
    protected function attemptTokenRefresh()
    {
        // Check if we have a refresh token
        $refreshToken = $this->sessionManager->getRefreshToken();

        if (!$refreshToken) {
            // No refresh token - clear session and require login
            $this->sessionManager->destroy();
            return false;
        }

        // Attempt token refresh
        try {
            $this->keycloakAuth->refreshAccessToken();

            // Refresh successful - user remains authenticated
            return true;

        } catch (\RuntimeException $e) {
            // Token refresh failed
            // This typically means refresh token is expired or invalid

            // Check if we should attempt silent SSO re-auth
            if ($this->shouldAttemptSilentSso($e)) {
                // Clear current session
                $this->sessionManager->destroy();

                // Attempt silent SSO re-authentication
                $this->keycloakAuth->silentSsoReauth();
                exit;  // silentSsoReauth() redirects
            }

            // Clear session and require login
            $this->sessionManager->destroy();
            return false;
        }
    }

    /**
     * Determine if we should attempt silent SSO re-authentication
     *
     * @param \RuntimeException $refreshError The error from token refresh
     * @return bool True if should attempt silent SSO
     */
    protected function shouldAttemptSilentSso(\RuntimeException $refreshError)
    {
        $errorMessage = $refreshError->getMessage();

        // Attempt silent SSO for these conditions:
        // 1. HTTP 400 with "invalid_grant" (expired refresh token)
        // 2. HTTP 400 with "Token is not active" (expired refresh token)

        if (stripos($errorMessage, 'invalid_grant') !== false) {
            return true;
        }

        if (stripos($errorMessage, 'not active') !== false) {
            return true;
        }

        // For other errors (network, server error), don't attempt SSO
        return false;
    }

    /**
     * Log token refresh errors for debugging
     */
    protected function logTokenRefreshError(\Exception $e)
    {
        $message = sprintf(
            "[KeycloakAuth] Token refresh failed: %s",
            $e->getMessage()
        );

        if (function_exists('log_message')) {
            log_message('info', $message);
        } else {
            error_log($message);
        }
    }

    /**
     * Redirect to login page or return JSON for AJAX requests
     */
    protected function redirectToLogin()
    {
        // Check if this is an AJAX request
        $isAjax = $this->isAjaxRequest();

        // Debug logging
        error_log('[AuthMiddleware] redirectToLogin called. isAjax=' . ($isAjax ? 'true' : 'false'));
        error_log('[AuthMiddleware] Headers: X-Requested-With=' . ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? 'not set') .
                  ', Accept=' . ($_SERVER['HTTP_ACCEPT'] ?? 'not set'));

        if ($isAjax) {
            // Return JSON response for AJAX requests
            error_log('[AuthMiddleware] Returning JSON 401 response for AJAX request');
            header('Content-Type: application/json');
            http_response_code(401);
            echo json_encode([
                'error' => 'Unauthorized',
                'message' => 'Sesi Anda berakhir. Silakan muat ulang halaman dan login kembali.',
                'redirect' => $this->getLoginUrl()
            ]);
            exit;
        }

        error_log('[AuthMiddleware] Redirecting to login page (not AJAX)');

        $loginUrl = $this->getLoginUrl();

        // Store intended URL for post-login redirect
        $intendedUrl = $this->getCurrentUrl();
        $this->storeIntendedUrl($intendedUrl);
        $this->setIdleNotice();

        if (function_exists('redirect')) {
            redirect($loginUrl);
        } else {
            header("Location: " . $loginUrl);
            exit;
        }
    }

    /**
     * Redirect to home page
     */
    protected function redirectToHome()
    {
        $homeUrl = function_exists('base_url')
            ? base_url('home')
            : $this->getBaseUrl() . '/home';

        if (function_exists('redirect')) {
            redirect($homeUrl);
        } else {
            header("Location: " . $homeUrl);
            exit;
        }
    }

    /**
     * Check if current path is excluded from authentication
     * Uses exact matching to prevent false positives
     */
    protected function isExcludedPath($path)
    {
        // Normalize path (remove trailing slash, ensure leading slash)
        $path = '/' . trim($path, '/');
        
        foreach ($this->excludedPaths as $excludedPath) {
            $excludedPath = '/' . trim($excludedPath, '/');
            
            // Exact match
            if ($path === $excludedPath) {
                return true;
            }
            
            // Match path with trailing content (e.g., /auth/login matches /auth/login?foo=bar)
            // But /auth should NOT match /authentication
            if (strpos($path, $excludedPath . '/') === 0) {
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
        // Use SERVER_NAME instead of HTTP_HOST to prevent Host header injection
        $host = $_SERVER['SERVER_NAME'] ?? $_SERVER['HTTP_HOST'] ?? 'localhost';
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
        // Use SERVER_NAME instead of HTTP_HOST to prevent Host header injection
        $host = $_SERVER['SERVER_NAME'] ?? $_SERVER['HTTP_HOST'] ?? 'localhost';
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
     * Set a gentle notice for session expiry
     */
    protected function setIdleNotice()
    {
        if (function_exists('get_instance')) {
            $ci =& get_instance();
            $ci->load->library('session');
            $ci->session->set_flashdata('auth_notice', 'Sesi Anda berakhir. Silakan login kembali.');
        } else {
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            $_SESSION['auth_notice'] = 'Sesi Anda berakhir. Silakan login kembali.';
        }
    }

    /**
     * Check if the current request is an AJAX request
     */
    protected function isAjaxRequest()
    {
        // Check common AJAX indicators
        return (
            // Check X-Requested-With header (jQuery, Axios, etc.)
            (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
             strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest')
            ||
            // Check Accept header contains application/json
            (!empty($_SERVER['HTTP_ACCEPT']) &&
             strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false)
            ||
            // Check Content-Type header for JSON
            (!empty($_SERVER['CONTENT_TYPE']) &&
             strpos($_SERVER['CONTENT_TYPE'], 'application/json') !== false)
        );
    }
}
