<?php

namespace Simss\KeycloakAuth\Middleware;

use Simss\KeycloakAuth\Auth\SessionManager;

/**
 * AuthMiddleware - Protect routes requiring authentication
 *
 * For SSR applications, authentication is checked via server-side session.
 * No token refresh logic - session expiry is managed by CodeIgniter.
 */
class AuthMiddleware
{
    protected $sessionManager;
    protected $excludedPaths;

    public function __construct(array $excludedPaths = [])
    {
        $this->sessionManager = new SessionManager();
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

        // Check if user is authenticated via session
        if (!$this->sessionManager->isAuthenticated()) {
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
        if (!$this->sessionManager->isAuthenticated()) {
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
     * Redirect to login page
     */
    protected function redirectToLogin()
    {
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
}
