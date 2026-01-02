<?php
/**
 * SSO Test - Application A (Primary Application)
 *
 * This simulates the first application that user logs into.
 * After successful login, this creates a Keycloak SSO session.
 */

define('TEST_MODE', true);
define('SIMSS_ROOT', __DIR__);

require_once SIMSS_ROOT . '/vendor/autoload.php';

use Simss\KeycloakAuth\Config\KeycloakConfig;
use Simss\KeycloakAuth\Auth\KeycloakAuth;
use Simss\KeycloakAuth\Auth\SessionManager;

// Load config
$configFile = SIMSS_ROOT . '/config/keycloak.php';
if (!file_exists($configFile)) {
    die("Configuration file not found");
}

$keycloakConfig = require $configFile;

// Start session
session_start();

try {
    // Initialize components
    $config = KeycloakConfig::getInstance($keycloakConfig);
    $auth = new KeycloakAuth($config);
    $sessionManager = new SessionManager();

    // Handle callback
    if (isset($_GET['code'])) {
        // Complete authentication
        $auth->authenticate();

        // Get user info
        $userInfo = $auth->getUserInfo();
        $tokenResponse = $auth->getTokenResponse();

        // Create session
        $tokens = [
            'access_token' => $tokenResponse->access_token ?? null,
            'refresh_token' => $tokenResponse->refresh_token ?? null,
            'id_token' => $tokenResponse->id_token ?? null,
            'expires_in' => $tokenResponse->expires_in ?? 300,
        ];

        $sessionManager->createSession($userInfo, $tokens);

        // Redirect back to main test page
        header('Location: test_sso.php');
        exit;
    }

    // Check if already logged in
    if ($sessionManager->isAuthenticated()) {
        header('Location: test_sso.php');
        exit;
    }

    // Initiate login
    $auth->authenticate();

} catch (Exception $e) {
    echo "<!DOCTYPE html>
    <html>
    <head>
        <title>Authentication Error</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
            }
            .error {
                background: #fee;
                border: 1px solid #fcc;
                color: #c33;
                padding: 15px;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <h1>Authentication Error</h1>
        <div class='error'>
            <strong>Error:</strong> " . htmlspecialchars($e->getMessage()) . "
        </div>
        <p><a href='test_sso.php'>← Back to SSO Test</a></p>
    </body>
    </html>";
}
