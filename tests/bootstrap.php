<?php

// Load Composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';

// Start session for tests
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Define test configuration
define('TEST_CONFIG', [
    'issuer' => 'https://keycloak.test.local/realms/simss',
    'client_id' => 'test-client',
    'client_secret' => 'test-secret',
    'redirect_uri' => 'http://localhost/auth/callback',
    'verify_peer' => false,
    'verify_host' => false,
]);
