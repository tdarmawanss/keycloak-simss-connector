<?php

namespace Simss\KeycloakAuth\Controllers;

use Simss\KeycloakAuth\Auth\KeycloakAuth;
use Simss\KeycloakAuth\Auth\SessionManager;
use Simss\KeycloakAuth\Config\KeycloakConfig;

/**
 * AuthController - Main authentication controller for Keycloak OIDC
 *
 * Implements the Authorization Code flow for SSR applications.
 * Session is managed server-side; only ID token is stored for logout.
 */
class AuthController
{
    protected $keycloakAuth;
    protected $sessionManager;
    protected $config;
    protected $ci;
    protected $cache;

    public function __construct()
    {
        // Initialize configuration
        try {
            $this->config = KeycloakConfig::getInstance();

            // DEBUG: Show loaded config
            if (isset($_GET['debug_config'])) {
                echo "<pre>Loaded Keycloak Config:\n";
                print_r($this->config->toArray());
                echo "</pre>";
                exit;
            }
        } catch (\Exception $e) {
            $this->handleError("Configuration error. Please contact administrator.");
            return;
        }

        // Initialize auth and session managers
        $this->keycloakAuth = new KeycloakAuth($this->config);
        $this->sessionManager = new SessionManager();

        // Load CodeIgniter instance if available
        if (function_exists('get_instance')) {
            $this->ci =& get_instance();
            // Optional cache driver for rate limiting (uses file cache by default)
            if (property_exists($this->ci, 'load')) {
                try {
                    $this->ci->load->driver('cache', ['adapter' => 'file']);
                    $this->cache = $this->ci->cache;
                } catch (\Exception $e) {
                    // Fallback silently
                }
            }
        }
    }

    /**
     * Index - Display login page or redirect if already authenticated
     */
    public function index()
    {
        // If already authenticated, redirect to home
        if ($this->sessionManager->isAuthenticated()) {
            $this->redirect($this->getHomeUrl());
            return;
        }

        // Show login page
        $this->loadView('auth-login', [
            'login_url' => $this->getLoginUrl(),
            'notice' => $this->getAuthNotice(),
        ]);
    }

    /**
     * Login - Initiate OIDC authentication flow
     */
    public function login()
    {
        try {
            // Check if already authenticated, via PHP session
            if ($this->sessionManager->isAuthenticated()) {
                $this->redirect($this->getHomeUrl());
                return;
            }

            // Basic rate limiting
            // key, limit, window
            if ($this->isRateLimited('auth_login', 10, 60)) { // 10 attempts per 60 seconds
                $this->handleError("Terlalu banyak percobaan. Silakan tunggu sebentar.");
                return;
            }

            // Initiate OIDC authentication
            // This will redirect to Keycloak login page
            $this->keycloakAuth->authenticate();

            // If we reach here, authentication was successful
            // Get user info and create session
            $this->handleSuccessfulAuthentication();

        } catch (\Exception $e) {
            $this->logError('Authentication failed', $e);
            $this->handleAuthenticationError($e);
        }
    }

    /**
     * Callback - Handle OIDC callback after authentication
     */
    public function callback()
    {
        try {
            // Basic rate limiting on callback as well
            if ($this->isRateLimited('auth_callback', 60, 300)) { // 60 per 5 minutes
                $this->handleError("Terlalu banyak percobaan. Silakan tunggu sebentar.");
                return;
            }

            // Check for silent SSO errors (prompt=none)
            if (isset($_GET['error'])) {
                $this->handleSilentSsoError($_GET['error'], $_GET['error_description'] ?? '');
                return;
            }

            // The authenticate method will handle the callback
            $this->keycloakAuth->authenticate();

            // Get user information
            $this->handleSuccessfulAuthentication();

        } catch (\Exception $e) {
            $this->logError('Callback failed', $e);
            $this->handleAuthenticationError($e);
        }
    }

    /**
     * Logout - Clear session and redirect to Keycloak logout
     */
   // Replace the logout() method in AuthController.php (lines 129-166):

public function logout()
{
    try {
        // Ensure session is started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        /* DEBUG: Show raw session FIRST
        echo "<pre>\n";
        echo "=== LOGOUT DEBUG - RAW SESSION ===\n";
        echo "Session ID: " . session_id() . "\n";
        echo "Session status: " . session_status() . " (2=active)\n";
        echo "\$_SESSION contents:\n";
        print_r($_SESSION);
        echo "\n";
        */

        // Get ID token before destroying session (for OIDC logout)
        $idToken = $this->sessionManager->getIdToken();

        /*
        echo "=== LOGOUT DEBUG - ID TOKEN CHECK ===\n";
        echo "getIdToken() returned: " . ($idToken ? "YES (length: " . strlen($idToken) . ")" : "NULL") . "\n";
        echo "Direct \$_SESSION['keycloak_id_token']: " . (isset($_SESSION['keycloak_id_token']) ? "EXISTS" : "NOT SET") . "\n";

        if ($idToken) {
            echo "ID Token (first 80 chars): " . substr($idToken, 0, 80) . "...\n";
        }
        */

        // Build logout URL before destroying session
        $postLogoutRedirect = $this->getBaseUrl();
        $logoutUrl = $this->keycloakAuth->getLogoutUrl($idToken, $postLogoutRedirect);

        /*
        echo "\n=== LOGOUT URL ===\n";
        echo "Has id_token_hint: " . (strpos($logoutUrl, 'id_token_hint') !== false ? "YES" : "NO - MISSING!") . "\n";
        echo "Full URL: " . $logoutUrl . "\n";

        // NOW destroy the session
        echo "\n--- Calling sessionManager->destroy() ---\n";
        */

        $this->sessionManager->destroy();

        /*
        echo "\n=== AFTER DESTROY ===\n";
        echo "Session destroyed successfully\n";

        echo "</pre>";
        echo "<p><a href='" . htmlspecialchars($logoutUrl) . "'>Click here to continue to Keycloak logout</a></p>";
        exit;
        // END DEBUG
        */

        // Redirect to Keycloak logout
        $this->redirect($logoutUrl);

    } catch (\Exception $e) {
        // Even if logout fails, destroy local session
        $this->sessionManager->destroy();
        $this->logError('Logout failed', $e);
        // Redirect to home anyway
        $this->redirect($this->getBaseUrl());
    }
}

    /**
     * Check - Check authentication status (for AJAX calls)
     */
    public function check()
    {
        $isAuthenticated = $this->sessionManager->isAuthenticated();

        $this->respondJson([
            'authenticated' => $isAuthenticated,
            'user' => $isAuthenticated ? $this->sessionManager->getSessionData() : null,
        ]);
    }

    /**
     * Handle errors from silent SSO re-authentication (prompt=none)
     *
     * @param string $error Error code from Keycloak
     * @param string $errorDescription Error description
     */
    protected function handleSilentSsoError($error, $errorDescription)
    {
        // Errors that indicate SSO session expired - redirect to login
        $requireLoginErrors = ['login_required', 'consent_required', 'interaction_required'];

        if (in_array($error, $requireLoginErrors)) {
            // SSO session expired - redirect to login page
            $this->setIdleNotice();
            $this->redirect($this->getLoginUrl());
            return;
        }

        // Other errors - log and show error
        $this->logError('Silent SSO failed', new \RuntimeException("$error: $errorDescription"));
        $this->handleError("Session expired. Please login again.");
    }

    /**
     * Handle successful authentication by creating a new PHP session
     * and storing the user information in the session.
     * The user is then redirected to the intended URL or home URL otherwise.

     */
    protected function handleSuccessfulAuthentication()
    {
        // Get user information from Keycloak
        $userInfo = $this->keycloakAuth->getUserInfo();

        // Get ID token (needed for OIDC logout)
        $idToken = $this->keycloakAuth->getIdToken();

        // Extract full tokens array
        $tokenResponse = $this->keycloakAuth->getTokenResponse();
        $tokens = [
            'access_token' => $tokenResponse->access_token ?? null,
            'refresh_token' => $tokenResponse->refresh_token ?? null,
            'id_token' => $tokenResponse->id_token ?? null,
            'expires_in' => $tokenResponse->expires_in ?? 300,
        ];

        /* DEBUG: Show what we got
        echo "<pre>\n";
        echo "=== LOGIN SUCCESS DEBUG ===\n";
        echo "Session ID: " . session_id() . "\n";
        echo "ID Token received: " . ($idToken ? "YES (length: " . strlen($idToken) . ")" : "NO") . "\n";
        echo "ID Token (first 50 chars): " . ($idToken ? substr($idToken, 0, 50) . "..." : "NULL") . "\n";
        echo "User: " . ($userInfo->preferred_username ?? $userInfo->sub ?? 'unknown') . "\n";
        echo "</pre>";
        // END DEBUG
        */

        // Regenerate session ID to prevent session fixation attacks
        $this->regenerateSession();

        // Create session with user info and tokens
        $this->sessionManager->createSession($userInfo, $tokens);

        /* DEBUG: Verify session was saved
        echo "<pre>\n";
        echo "=== AFTER SESSION SAVE ===\n";
        echo "New Session ID: " . session_id() . "\n";
        echo "\$_SESSION keys: " . implode(", ", array_keys($_SESSION ?? [])) . "\n";
        echo "keycloak_id_token saved: " . (isset($_SESSION['keycloak_id_token']) ? "YES" : "NO") . "\n";
        $intendedUrl = $this->getIntendedUrl();
        $redirectTo = $intendedUrl ?: $this->getHomeUrl();
        echo "Will redirect to: " . $redirectTo . "\n";
        echo "</pre>";
        echo "<p><a href='" . htmlspecialchars($redirectTo) . "'>Click here to continue</a></p>";
        exit;
        // END DEBUG
        */

        // Redirect to intended URL or home
        $intendedUrl = $this->getIntendedUrl();
        $this->redirect($intendedUrl ?: $this->getHomeUrl());
    }

    /**
     * Regenerate session ID for security
     */
    protected function regenerateSession()
    {
        if ($this->ci) {
            $this->ci->session->sess_regenerate(true);
        } elseif (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
    }

    /**
     * Get and clear intended URL from session
     */
    protected function getIntendedUrl()
    {
        if ($this->ci) {
            $url = $this->ci->session->userdata('intended_url');
            $this->ci->session->unset_userdata('intended_url');
            return $url ?: null;
        } else {
            $url = $_SESSION['intended_url'] ?? null;
            unset($_SESSION['intended_url']);
            return $url;
        }
    }

    /**
     * Set idle/session expired notice
     */
    protected function setIdleNotice()
    {
        $message = "Your session has expired due to inactivity. Please login again.";

        if ($this->ci) {
            $this->ci->session->set_flashdata('auth_notice', $message);
        } else {
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            $_SESSION['auth_notice'] = $message;
        }
    }

    /**
     * Retrieve notice (e.g., idle timeout) from flash/session
     */
    protected function getAuthNotice()
    {
        if ($this->ci) {
            return $this->ci->session->flashdata('auth_notice') ?: null;
        }

        // For native PHP sessions, retrieve and clear the notice
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        $notice = $_SESSION['auth_notice'] ?? null;
        unset($_SESSION['auth_notice']);
        return $notice;
    }

    /**
     * Handle authentication errors with intelligent error messages
     */
    protected function handleAuthenticationError(\Exception $e)
    {
        $message = $e->getMessage();
        $errorMessage = '';
        $canRetry = false;

        // Detect timeout/network errors
        if ($this->isTimeoutError($message)) {
            $errorMessage = "Koneksi ke server autentikasi timeout. Server mungkin sedang sibuk atau koneksi internet Anda lambat. Silakan coba lagi.";
            $canRetry = true;
        }
        // Connection errors
        elseif ($this->isConnectionError($message)) {
            $errorMessage = "Tidak dapat terhubung ke server autentikasi. Periksa koneksi internet Anda dan coba lagi.";
            $canRetry = true;
        }
        // Server errors (5xx)
        elseif (preg_match('/HTTP 5\d{2}/', $message)) {
            $errorMessage = "Server autentikasi sedang mengalami masalah. Silakan coba lagi dalam beberapa saat.";
            $canRetry = true;
        }
        // Authentication/authorization errors
        elseif (preg_match('/HTTP 401|HTTP 403|invalid_grant/', $message)) {
            $errorMessage = "Autentikasi gagal. Silakan login kembali.";
            $canRetry = true;
        }
        // Generic error
        else {
            $errorMessage = "Autentikasi gagal: " . $message;
            $canRetry = true;
        }

        $this->handleError($errorMessage, $canRetry);
    }

    /**
     * Check if error is a timeout error
     */
    protected function isTimeoutError($message)
    {
        $timeoutPatterns = [
            'timeout',
            'timed out',
            'curl error: (28)',
            'execution time',
            'exceeded',
        ];

        foreach ($timeoutPatterns as $pattern) {
            if (stripos($message, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if error is a connection error
     */
    protected function isConnectionError($message)
    {
        $connectionPatterns = [
            'connection refused',
            'connection reset',
            'couldn\'t connect',
            'failed to connect',
            'network unreachable',
            'curl error: (6)',
            'curl error: (7)',
            'curl error: (52)',
            'curl error: (56)',
        ];

        foreach ($connectionPatterns as $pattern) {
            if (stripos($message, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Handle errors - show user-friendly message
     */
    protected function handleError($message, $canRetry = false)
    {
        if ($this->isAjaxRequest()) {
            $this->respondJson([
                'success' => false,
                'message' => $message,
                'can_retry' => $canRetry,
            ], 400);
        } else {
            $this->loadView('auth-error', [
                'error' => $message,
                'login_url' => $this->getLoginUrl(),
                'can_retry' => $canRetry,
            ]);
        }
    }

    /**
     * Log error for debugging (does not expose to user)
     */
    protected function logError($context, \Exception $e)
    {
        $message = sprintf(
            "[KeycloakAuth] %s: %s in %s:%d",
            $context,
            $e->getMessage(),
            $e->getFile(),
            $e->getLine()
        );

        if (function_exists('log_message')) {
            log_message('error', $message);
        } else {
            error_log($message);
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
            // Fallback: simple error page
            echo "<!DOCTYPE html><html><head><title>Error</title></head><body>";
            echo "<h1>Authentication Error</h1>";
            echo "<p>" . htmlspecialchars($data['error'] ?? 'Unknown error') . "</p>";
            if (!empty($data['login_url'])) {
                echo "<p><a href='" . htmlspecialchars($data['login_url']) . "'>Try again</a></p>";
            }
            echo "</body></html>";
        }
    }

    protected function respondJson($data, $statusCode = 200)
    {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }

    /**
     * Simple rate limiter per IP and key
     */
    protected function isRateLimited($key, $limit, $windowSeconds)
    {
        $ip = $this->getClientIp();
        $bucketKey = "rate_{$key}_{$ip}";
        $now = time();

        // Use CI cache if available
        if ($this->cache && method_exists($this->cache, 'get')) {
            $entry = $this->cache->get($bucketKey);
            if ($entry && isset($entry['count'], $entry['expires_at']) && $entry['expires_at'] > $now) {
                if ($entry['count'] >= $limit) {
                    return true;
                }
                $entry['count'] += 1;
            } else {
                $entry = ['count' => 1, 'expires_at' => $now + $windowSeconds];
            }
            $this->cache->save($bucketKey, $entry, $windowSeconds);
            return false;
        }

        // Fallback to PHP session storage
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (!isset($_SESSION['rate_limit'])) {
            $_SESSION['rate_limit'] = [];
        }
        $entry = $_SESSION['rate_limit'][$bucketKey] ?? ['count' => 0, 'expires_at' => $now + $windowSeconds];
        if ($entry['expires_at'] <= $now) {
            $entry = ['count' => 0, 'expires_at' => $now + $windowSeconds];
        }
        if ($entry['count'] >= $limit) {
            $_SESSION['rate_limit'][$bucketKey] = $entry;
            return true;
        }
        $entry['count'] += 1;
        $_SESSION['rate_limit'][$bucketKey] = $entry;
        return false;
    }

    protected function getClientIp()
    {
        // Only trust X-Forwarded-For if behind a known proxy
        $trustedProxies = $this->config->get('trusted_proxies', []);

        if (!empty($trustedProxies) && in_array($_SERVER['REMOTE_ADDR'] ?? '', $trustedProxies)) {
            if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                return trim($ipList[0]);
            }
        }

        // Default to REMOTE_ADDR (can't be spoofed)
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
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
