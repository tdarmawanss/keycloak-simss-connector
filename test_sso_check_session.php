<?php
/**
 * SSO Session Check API
 *
 * Returns JSON with session status for AJAX calls
 */

define('TEST_MODE', true);
define('SIMSS_ROOT', __DIR__);

require_once SIMSS_ROOT . '/vendor/autoload.php';

use Simss\KeycloakAuth\Auth\SessionManager;

session_start();

header('Content-Type: application/json');

try {
    $sessionManager = new SessionManager();

    $response = [
        'session_exists' => $sessionManager->isAuthenticated(),
        'session_id' => session_id(),
        'timestamp' => time(),
    ];

    if ($sessionManager->isAuthenticated()) {
        $sessionData = $sessionManager->getSessionData();
        $tokens = $sessionManager->getTokens();

        $response['user'] = [
            'username' => $sessionData['username'] ?? 'Unknown',
            'email' => $sessionData['email'] ?? 'N/A',
        ];

        $response['tokens'] = [
            'has_access_token' => isset($tokens['access_token']),
            'has_refresh_token' => isset($tokens['refresh_token']),
            'has_id_token' => isset($tokens['id_token']),
            'expires_at' => $tokens['access_token_expires_at'] ?? null,
        ];

        $response['token_expired'] = $sessionManager->isTokenExpired();
    }

    echo json_encode($response, JSON_PRETTY_PRINT);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'error' => true,
        'message' => $e->getMessage(),
    ], JSON_PRETTY_PRINT);
}
