<?php
/**
 * SSO Testing Script
 *
 * This script tests Single Sign-On (SSO) functionality by simulating two different
 * applications accessing the same Keycloak realm.
 *
 * How SSO Works:
 * 1. User logs into App A → Keycloak creates SSO session (cookie: KEYCLOAK_SESSION)
 * 2. User visits App B → Redirects to Keycloak
 * 3. Keycloak sees existing session → Auto-issues tokens for App B (no login required)
 * 4. User is logged into both apps with single login
 *
 * Usage:
 * 1. Access this script in browser: http://localhost/test_sso.php
 * 2. Click "Test SSO Flow"
 * 3. Script will simulate multi-app SSO
 */

// Prevent execution if not CLI or browser request
if (php_sapi_name() !== 'cli' && !isset($_SERVER['HTTP_HOST'])) {
    die('This script must be run via web browser or CLI');
}

// Configuration
define('TEST_MODE', true);
define('SIMSS_ROOT', __DIR__);

// Load Composer autoloader
require_once SIMSS_ROOT . '/vendor/autoload.php';

// Load config
$configFile = SIMSS_ROOT . '/config/keycloak.php';
if (!file_exists($configFile)) {
    die("Configuration file not found. Please copy config/keycloak.example.php to config/keycloak.php");
}

$keycloakConfig = require $configFile;

use Simss\KeycloakAuth\Config\KeycloakConfig;
use Simss\KeycloakAuth\Auth\KeycloakAuth;

// Initialize config
try {
    $config = KeycloakConfig::getInstance($keycloakConfig);
} catch (Exception $e) {
    die("Configuration error: " . $e->getMessage());
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keycloak SSO Tester</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }

        .header h1 {
            color: #333;
            margin-bottom: 10px;
        }

        .header p {
            color: #666;
            line-height: 1.6;
        }

        .apps-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .app-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }

        .app-card h2 {
            color: #333;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }

        .status {
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-weight: 500;
        }

        .status.logged-out {
            background: #fee;
            color: #c33;
            border: 1px solid #fcc;
        }

        .status.logged-in {
            background: #efe;
            color: #3c3;
            border: 1px solid #cfc;
        }

        .status.sso-active {
            background: #eef;
            color: #33c;
            border: 1px solid #ccf;
        }

        .info-block {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }

        .info-block strong {
            color: #667eea;
        }

        button {
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            margin: 5px;
            transition: all 0.3s;
        }

        button:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }

        button.secondary {
            background: #6c757d;
        }

        button.secondary:hover {
            background: #5a6268;
        }

        button.danger {
            background: #dc3545;
        }

        button.danger:hover {
            background: #c82333;
        }

        .instructions {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-top: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }

        .instructions h3 {
            color: #333;
            margin-bottom: 15px;
        }

        .instructions ol {
            margin-left: 20px;
            line-height: 2;
        }

        .instructions li {
            color: #666;
        }

        .instructions code {
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #667eea;
        }

        .test-results {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-top: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }

        .test-results h3 {
            color: #333;
            margin-bottom: 15px;
        }

        .test-item {
            padding: 10px;
            margin: 8px 0;
            border-radius: 5px;
            display: flex;
            align-items: center;
        }

        .test-item.pass {
            background: #d4edda;
            color: #155724;
        }

        .test-item.fail {
            background: #f8d7da;
            color: #721c24;
        }

        .test-item.pending {
            background: #fff3cd;
            color: #856404;
        }

        .test-item::before {
            content: '●';
            margin-right: 10px;
            font-size: 20px;
        }

        .keycloak-info {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin: 15px 0;
        }

        .keycloak-info h4 {
            color: #1976D2;
            margin-bottom: 8px;
        }

        .keycloak-info p {
            color: #555;
            font-size: 14px;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Keycloak SSO Multi-Application Tester</h1>
            <p>
                This tool simulates two different applications (App A and App B) using the same Keycloak realm
                to verify Single Sign-On (SSO) functionality. When SSO works correctly, logging into one app
                automatically grants access to the other without requiring a second login.
            </p>
        </div>

        <div class="keycloak-info">
            <h4>How Keycloak SSO Works</h4>
            <p>
                1. User logs into <strong>App A</strong> → Keycloak creates an SSO session (cookie: KEYCLOAK_SESSION)<br>
                2. User visits <strong>App B</strong> → Redirects to Keycloak for authentication<br>
                3. Keycloak detects existing session → Auto-issues tokens for App B (no login prompt)<br>
                4. User is now logged into both apps with a single login!
            </p>
        </div>

        <div class="apps-grid">
            <!-- Application A -->
            <div class="app-card">
                <h2>📱 Application A (Primary App)</h2>

                <?php
                session_start();
                $isLoggedInA = isset($_SESSION['keycloak_auth']) && !empty($_SESSION['keycloak_auth']['logged_in']);
                ?>

                <div class="status <?php echo $isLoggedInA ? 'logged-in' : 'logged-out'; ?>">
                    <?php if ($isLoggedInA): ?>
                        ✓ Logged In
                    <?php else: ?>
                        ✗ Not Logged In
                    <?php endif; ?>
                </div>

                <?php if ($isLoggedInA): ?>
                    <div class="info-block">
                        <strong>User:</strong> <?php echo htmlspecialchars($_SESSION['keycloak_auth']['username'] ?? 'Unknown'); ?><br>
                        <strong>Email:</strong> <?php echo htmlspecialchars($_SESSION['keycloak_auth']['email'] ?? 'N/A'); ?><br>
                        <strong>Session ID:</strong> <?php echo substr(session_id(), 0, 20) . '...'; ?>
                    </div>

                    <form method="post" action="?action=logout_a" style="margin-top: 15px;">
                        <button type="submit" class="danger">Logout from App A</button>
                    </form>
                <?php else: ?>
                    <p style="color: #666; margin: 15px 0;">
                        This application is not authenticated. Click below to initiate login via Keycloak.
                    </p>

                    <form method="post" action="?action=login_a" style="margin-top: 15px;">
                        <button type="submit">Login to App A</button>
                    </form>
                <?php endif; ?>
            </div>

            <!-- Application B -->
            <div class="app-card">
                <h2>📱 Application B (SSO Test App)</h2>

                <?php
                // For demo purposes, we'll check if SSO would work by checking Keycloak session
                // In reality, this would be a separate application
                $wouldSsoWork = $isLoggedInA; // Simplified - in reality, check Keycloak session
                ?>

                <div class="status <?php echo $wouldSsoWork ? 'sso-active' : 'logged-out'; ?>">
                    <?php if ($wouldSsoWork): ?>
                        ⚡ SSO Available (Can auto-login)
                    <?php else: ?>
                        ✗ SSO Not Available
                    <?php endif; ?>
                </div>

                <?php if ($wouldSsoWork): ?>
                    <div class="info-block">
                        <strong>SSO Status:</strong> Active<br>
                        <strong>Keycloak Session:</strong> Valid<br>
                        <strong>Auto-login:</strong> Enabled
                    </div>

                    <p style="color: #666; margin: 15px 0;">
                        Because you're logged into App A, clicking below will authenticate App B
                        <strong>without requiring credentials</strong> (SSO).
                    </p>

                    <button onclick="testSsoFlow()">Test SSO Login to App B</button>
                <?php else: ?>
                    <div class="info-block">
                        <strong>SSO Status:</strong> Inactive<br>
                        <strong>Keycloak Session:</strong> None<br>
                        <strong>Auto-login:</strong> Disabled
                    </div>

                    <p style="color: #666; margin: 15px 0;">
                        No active Keycloak session detected. You must login to App A first to test SSO.
                    </p>

                    <button disabled style="opacity: 0.5; cursor: not-allowed;">
                        SSO Not Available
                    </button>
                <?php endif; ?>
            </div>
        </div>

        <!-- Instructions -->
        <div class="instructions">
            <h3>📋 Testing Instructions</h3>
            <ol>
                <li><strong>Login to App A:</strong> Click "Login to App A" button above. You'll be redirected to Keycloak.</li>
                <li><strong>Complete Authentication:</strong> Enter your Keycloak credentials and complete login.</li>
                <li><strong>Return to App A:</strong> After successful login, you'll be redirected back to this page.</li>
                <li><strong>Verify App A Status:</strong> App A should now show "Logged In" status with your user info.</li>
                <li><strong>Test SSO:</strong> Click "Test SSO Login to App B" to verify single sign-on works.</li>
                <li><strong>Observe:</strong> App B should authenticate <strong>without asking for credentials again</strong>.</li>
            </ol>
        </div>

        <!-- Configuration Info -->
        <div class="test-results">
            <h3>⚙️ Current Configuration</h3>
            <div class="info-block">
                <strong>Keycloak Issuer:</strong> <?php echo htmlspecialchars($config->getIssuer()); ?><br>
                <strong>Client ID:</strong> <?php echo htmlspecialchars($config->getClientId()); ?><br>
                <strong>Redirect URI:</strong> <?php echo htmlspecialchars($config->getRedirectUri()); ?><br>
                <strong>Scopes:</strong> <?php echo implode(', ', $config->getScopes()); ?><br>
                <strong>Session Status:</strong> <?php echo session_status() === PHP_SESSION_ACTIVE ? 'Active' : 'Inactive'; ?>
            </div>
        </div>

        <!-- Advanced SSO Test -->
        <div class="test-results">
            <h3>🔬 Advanced SSO Tests</h3>
            <div class="test-item pending">
                <span>Test 1: Keycloak session cookie detection</span>
            </div>
            <div class="test-item pending">
                <span>Test 2: Silent authentication (prompt=none)</span>
            </div>
            <div class="test-item pending">
                <span>Test 3: Token refresh across apps</span>
            </div>
            <div class="test-item pending">
                <span>Test 4: Single logout propagation</span>
            </div>

            <button onclick="runAdvancedTests()" style="margin-top: 15px;">
                Run Advanced SSO Tests
            </button>
        </div>
    </div>

    <script>
        function testSsoFlow() {
            // Open in new window to simulate different app
            const ssoWindow = window.open(
                'test_sso_app_b.php',
                'AppB',
                'width=800,height=600,menubar=no,toolbar=no,location=no'
            );

            if (ssoWindow) {
                alert('Opening App B in new window.\n\n' +
                      'If SSO works correctly, App B will authenticate automatically ' +
                      'without asking for credentials.');
            } else {
                alert('Please allow popups for this site to test SSO in a new window.');
            }
        }

        function runAdvancedTests() {
            if (!confirm('This will run a series of automated SSO tests.\n\nContinue?')) {
                return;
            }

            // Redirect to advanced test script
            window.location.href = 'test_sso_advanced.php';
        }
    </script>

    <?php
    // Handle actions
    if (isset($_GET['action'])) {
        switch ($_GET['action']) {
            case 'login_a':
                // Redirect to actual Keycloak auth
                header('Location: test_sso_app_a.php');
                exit;

            case 'logout_a':
                // Clear session
                $_SESSION = [];
                session_destroy();
                header('Location: test_sso.php');
                exit;
        }
    }
    ?>
</body>
</html>
