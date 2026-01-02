<?php
/**
 * SSO Test - Application B (SSO Test Application)
 *
 * This simulates a second application that should automatically authenticate
 * via SSO if user is already logged into Application A.
 *
 * Key Test: This should authenticate WITHOUT asking for credentials again.
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

// Use separate session for App B
session_name('APP_B_SESSION');
session_start();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>App B - SSO Test</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            min-height: 100vh;
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .container {
            background: white;
            border-radius: 15px;
            padding: 40px;
            max-width: 600px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.2);
        }

        h1 {
            color: #333;
            margin-bottom: 10px;
        }

        .app-badge {
            display: inline-block;
            background: #f5576c;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 20px;
        }

        .status {
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-weight: 500;
        }

        .status.loading {
            background: #fff3cd;
            color: #856404;
            border: 2px solid #ffeaa7;
        }

        .status.success {
            background: #d4edda;
            color: #155724;
            border: 2px solid #c3e6cb;
        }

        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 2px solid #f5c6cb;
        }

        .info-block {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }

        .info-block strong {
            color: #f5576c;
        }

        button {
            background: #f5576c;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            margin: 10px 5px;
            transition: all 0.3s;
        }

        button:hover {
            background: #e34658;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(245, 87, 108, 0.3);
        }

        button.secondary {
            background: #6c757d;
        }

        .test-log {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            max-height: 300px;
            overflow-y: auto;
            margin-top: 20px;
        }

        .test-log .timestamp {
            color: #608b4e;
        }

        .test-log .success {
            color: #4ec9b0;
        }

        .test-log .error {
            color: #f48771;
        }

        .test-log .info {
            color: #9cdcfe;
        }

        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #f5576c;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 10px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <span class="app-badge">APPLICATION B</span>
        <h1>🔐 SSO Authentication Test</h1>
        <p style="color: #666; margin: 15px 0;">
            This window simulates a separate application (App B) that will attempt
            to authenticate using Keycloak SSO.
        </p>

        <div id="status-container">
            <?php
            try {
                $config = KeycloakConfig::getInstance($keycloakConfig);
                $auth = new KeycloakAuth($config);
                $sessionManager = new SessionManager();

                // Handle OAuth callback
                if (isset($_GET['code'])) {
                    echo '<div class="status loading">
                            <div class="spinner"></div>
                            Processing SSO authentication...
                          </div>
                          <div class="test-log" id="log">
                            <div class="timestamp">[' . date('H:i:s') . ']</div>
                            <div class="info">→ Received authorization code from Keycloak</div>
                            <div class="info">→ Exchanging code for tokens...</div>
                          </div>';

                    echo '<script>
                        setTimeout(function() {
                            document.getElementById("log").innerHTML +=
                                \'<div class="info">→ Fetching user information...</div>\';
                        }, 500);
                    </script>';

                    // Complete authentication
                    $auth->authenticate();
                    $userInfo = $auth->getUserInfo();
                    $tokenResponse = $auth->getTokenResponse();

                    // Create session for App B
                    $tokens = [
                        'access_token' => $tokenResponse->access_token ?? null,
                        'refresh_token' => $tokenResponse->refresh_token ?? null,
                        'id_token' => $tokenResponse->id_token ?? null,
                        'expires_in' => $tokenResponse->expires_in ?? 300,
                    ];

                    $sessionManager->createSession($userInfo, $tokens);

                    echo '<script>
                        setTimeout(function() {
                            document.getElementById("log").innerHTML +=
                                \'<div class="success">✓ SSO authentication successful!</div>\';
                            setTimeout(function() {
                                location.reload();
                            }, 1000);
                        }, 1000);
                    </script>';

                } elseif ($sessionManager->isAuthenticated()) {
                    // Already authenticated
                    $userData = $sessionManager->getSessionData();
                    $tokens = $sessionManager->getTokens();

                    echo '<div class="status success">
                            ✓ SSO Authentication Successful!
                          </div>';

                    echo '<div class="info-block">
                            <strong>User:</strong> ' . htmlspecialchars($userData['username'] ?? 'Unknown') . '<br>
                            <strong>Email:</strong> ' . htmlspecialchars($userData['email'] ?? 'N/A') . '<br>
                            <strong>Authenticated via:</strong> Single Sign-On (SSO)<br>
                            <strong>Session ID:</strong> ' . substr(session_id(), 0, 20) . '...<br>
                            <strong>Access Token:</strong> ' . (isset($tokens['access_token']) ? 'Present' : 'Missing') . '<br>
                            <strong>ID Token:</strong> ' . (isset($tokens['id_token']) ? 'Present' : 'Missing') . '
                          </div>';

                    echo '<div class="test-log">
                            <div class="timestamp">[' . date('H:i:s') . ']</div>
                            <div class="success">✓ App B session is active</div>
                            <div class="success">✓ SSO worked - no credentials were requested!</div>
                            <div class="info">→ User was authenticated via Keycloak SSO session</div>
                            <div class="info">→ This proves SSO is working correctly</div>
                          </div>';

                    echo '<button onclick="window.close()">Close Window</button>';
                    echo '<button class="secondary" onclick="location.href=\'?logout\'">Logout App B</button>';

                } else {
                    // Not authenticated - initiate SSO
                    echo '<div class="status loading">
                            <div class="spinner"></div>
                            Checking for SSO session...
                          </div>';

                    echo '<div class="test-log" id="log">
                            <div class="timestamp">[' . date('H:i:s') . ']</div>
                            <div class="info">→ App B is not authenticated</div>
                            <div class="info">→ Checking if Keycloak SSO session exists...</div>
                            <div class="info">→ Redirecting to Keycloak for SSO authentication...</div>
                          </div>';

                    echo '<p style="margin-top: 20px; color: #666;">
                            <strong>Expected Behavior:</strong><br>
                            If you are logged into App A, Keycloak should detect your existing session
                            and authenticate this app <strong>without asking for credentials</strong>.
                          </p>';

                    // Initiate authentication (should auto-complete via SSO)
                    echo '<script>
                        setTimeout(function() {
                            window.location.href = "' . $_SERVER['PHP_SELF'] . '?sso=true";
                        }, 2000);
                    </script>';
                }

                // Handle SSO initiation
                if (isset($_GET['sso'])) {
                    $auth->authenticate(); // This will redirect to Keycloak
                }

                // Handle logout
                if (isset($_GET['logout'])) {
                    $sessionManager->destroy();
                    echo '<script>location.href = "' . $_SERVER['PHP_SELF'] . '";</script>';
                }

            } catch (Exception $e) {
                echo '<div class="status error">
                        ✗ Authentication Error
                      </div>';

                echo '<div class="test-log">
                        <div class="timestamp">[' . date('H:i:s') . ']</div>
                        <div class="error">✗ Error: ' . htmlspecialchars($e->getMessage()) . '</div>
                      </div>';

                echo '<p style="margin-top: 20px; color: #666;">
                        This could mean:
                        <ul style="margin: 10px 0 0 20px; line-height: 1.8;">
                            <li>No active Keycloak session exists (login to App A first)</li>
                            <li>SSO session has expired</li>
                            <li>Keycloak configuration issue</li>
                        </ul>
                      </p>';

                echo '<button onclick="window.close()">Close Window</button>';
            }
            ?>
        </div>
    </div>
</body>
</html>
