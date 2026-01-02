<?php

namespace Simss\KeycloakAuth\Middleware;

use Simss\KeycloakAuth\Auth\SessionManager;
use Simss\KeycloakAuth\Config\KeycloakConfig;
/**
 * PermissionMiddleware - Role-Based Access Control (RBAC) for CodeIgniter 3
 *
 * Implements fine-grained endpoint access control using role-module-CRUD mappings.
 *
 * ## How It Works
 *
 * 1. Request arrives at endpoint (e.g., /ekspedisi/add)
 * 2. Middleware extracts user role(s) from session (via ID token)
 * 3. Loads required modules for endpoint from endpoint_permissions.json
 * 4. Loads user's module permissions from role_permissions.json
 * 5. Validates: User must have ALL required module permissions
 * 6. Result: Authorize (allow) or Reject (redirect with error)
 *
 * ## Configuration Schema
 *
 * **endpoint_permissions.json** - Maps endpoints to required modules/CRUD:
 * ```json
 * {
 *   "endpoints": {
 *     "ekspedisi/add": {
 *       "controller": "Ekspedisi",
 *       "modules": [
 *         { "name": "data ekspedisi", "permissions": ["C"] }
 *       ]
 *     },
 *     "requisisi/findbarang": {
 *       "modules": [
 *         { "name": "requisisi barang", "permissions": ["R"] },
 *         { "name": "data produk", "permissions": ["R"] }
 *       ]
 *     }
 *   }
 * }
 * ```
 *
 * **role_permissions.json** - Maps roles to their module permissions:
 * ```json
 * {
 *   "roles": {
 *     "administrator": {
 *       "display_name": "Administrator",
 *       "modules": {
 *         "data ekspedisi": ["C", "R", "U", "D"],
 *         "requisisi barang": ["C", "R", "U", "D"]
 *       }
 *     },
 *     "logistic_staff": {
 *       "modules": {
 *         "data ekspedisi": ["C", "R", "U"],
 *         "requisisi barang": ["R"]
 *       }
 *     }
 *   }
 * }
 * ```
 *
 * ## CRUD Permissions
 * - **C** = Create
 * - **R** = Read
 * - **U** = Update
 * - **D** = Delete
 *
 * ## Example Access Control Flow
 *
 * **Scenario 1: Access Granted**
 * - Endpoint: ekspedisi/add
 * - Required: data ekspedisi [C]
 * - User Role: logistic_staff
 * - Role Has: data ekspedisi [C, R, U]
 * - Result: ✓ Access granted (has "C")
 *
 * **Scenario 2: Access Denied**
 * - Endpoint: ekspedisi/delete
 * - Required: data ekspedisi [D]
 * - User Role: logistic_staff
 * - Role Has: data ekspedisi [C, R, U]
 * - Result: ✗ Access denied (missing "D")
 *
 * **Scenario 3: Multiple Modules**
 * - Endpoint: requisisi/findbarang
 * - Required: requisisi barang [R], data produk [R]
 * - User Role: logistic_staff
 * - Role Has: requisisi barang [R], data produk [R]
 * - Result: ✓ Access granted (has all required)
 *
 * ## Performance
 * - Config files loaded once per PHP process (static caching)
 * - Minimal overhead: typically < 5ms per request
 *
 * ## Configuration Files Location
 *
 * **Option 1: Custom Paths (Recommended)**
 * Configure paths in `application/config/keycloak.php`:
 * ```php
 * $config['keycloak']['access_control'] = [
 *     'endpoint_permissions' => APPPATH . 'third_party/keycloak-simss-connector/config/access_control/client_acme/endpoint_permissions.json',
 *     'role_permissions' => APPPATH . 'third_party/keycloak-simss-connector/config/access_control/client_acme/role_permissions.json'
 * ];
 * ```
 *
 * **Option 2: Default Paths**
 * If not configured, defaults to: `config/access_control/[client_id]/endpoint_permissions.json` and `role_permissions.json`
 * Relative to connector root directory.
 *
 * Uses static caching to load JSON configs only once per PHP process.
 */
class PermissionMiddleware
{
    /** @var array|null Cached endpoint permissions (loaded once) */
    private static $endpointPermissions = null;

    /** @var array|null Cached role permissions (loaded once) */
    private static $rolePermissions = null;

    /** @var string Config directory path */
    private static $configPath = null;

    /** @var SessionManager */
    protected $sessionManager;

    /** @var KeycloakConfig */
    protected $keycloakConfig;

    /** @var string Keycloak client ID */
    protected $keycloakClientId;

    /** @var array Paths excluded from permission checks */
    protected $excludedPaths;

    public function __construct(array $excludedPaths = [])
    {
        $this->keycloakConfig = KeycloakConfig::getInstance();
        $this->keycloakClientId = $this->keycloakConfig->getClientId();
        $this->sessionManager = new SessionManager();
        $this->excludedPaths = array_merge([
            '/auth',
            '/auth/login',
            '/auth/callback',
            '/auth/logout',
            '/auth/check',
            '/home',
        ], $excludedPaths);
    }

    /**
     * Check if user has permission to access current endpoint
     *
     * @return bool True if access granted
     */
    public function check()
    {
        $currentPath = $this->getCurrentPath();

        // Skip permission check for excluded paths
        if ($this->isExcludedPath($currentPath)) {
            return true;
        }

        // Load configs into memory (only once per process)
        $this->loadConfigs();

        // Get endpoint key (e.g., "btb/add")
        $endpointKey = $this->normalizeEndpoint($currentPath);

        // Get required permissions for this endpoint
        $requiredModules = $this->getRequiredPermissions($endpointKey);

        // If endpoint not registered, allow access (only restrict explicitly defined)
        if ($requiredModules === null) {
            $this->log("Endpoint not in config (allowing access): $endpointKey", 'debug');
            return true;
        }

        // Empty modules array means no restrictions
        if (empty($requiredModules)) {
            $this->log("Endpoint has no module restrictions: $endpointKey", 'debug');
            return true;
        }

        // Get user's roles from session
        $userRoles = $this->sessionManager->getRoles();

        // Check if any of user's roles satisfy the requirements
        $accessResult = $this->userHasPermissions($userRoles, $requiredModules);

        if ($accessResult['granted']) {
            $this->log("Access granted to $endpointKey for role: {$accessResult['role']}", 'info');
            return true;
        }

        // Access denied
        $this->handleUnauthorized($endpointKey, $userRoles, $requiredModules, $accessResult['reason']);
        return false;
    }

    /**
     * Load endpoint and role permission configs into static cache
     */
    protected function loadConfigs()
    {
        if (self::$endpointPermissions !== null && self::$rolePermissions !== null) {
            return; // Already loaded
        }

        // Check if custom paths are configured
        $accessControlConfig = $this->keycloakConfig->get('access_control', []);

        if (!empty($accessControlConfig['endpoint_permissions']) && !empty($accessControlConfig['role_permissions'])) {
            // Use custom configured paths
            $endpointFile = $accessControlConfig['endpoint_permissions'];
            $roleFile = $accessControlConfig['role_permissions'];
        } else {
            // Use default paths
            $configPath = $this->getConfigPath();
            $endpointFile = $configPath . '/endpoint_permissions.json';
            $roleFile = $configPath . '/role_permissions.json';
        }

        // Load endpoint permissions
        if (file_exists($endpointFile)) {
            $content = file_get_contents($endpointFile);
            $data = json_decode($content, true);
            self::$endpointPermissions = $data ?? [];
        } else {
            self::$endpointPermissions = [];
            $this->log("Endpoint permissions file not found: $endpointFile", 'warning');
        }

        // Load role permissions
        if (file_exists($roleFile)) {
            $content = file_get_contents($roleFile);
            $data = json_decode($content, true);
            self::$rolePermissions = $data['roles'] ?? [];
        } else {
            self::$rolePermissions = [];
            $this->log("Role permissions file not found: $roleFile", 'warning');
        }
    }

    /**
     * Get config directory path
     *
     * @return string
     */
    protected function getConfigPath()
    {
        if (self::$configPath !== null) {
            return self::$configPath;
        }

        // Default: config/access_control/[client_id] relative to connector root
        self::$configPath = dirname(__DIR__, 2) . '/config/access_control/' . $this->keycloakClientId;
      
        return self::$configPath;
    }

    /**
     * Set custom config path (for testing or alternative configs)
     *
     * @param string $path
     */
    public static function setConfigPath($path)
    {
        self::$configPath = $path;
        // Clear cached configs so they reload from new path
        self::$endpointPermissions = null;
        self::$rolePermissions = null;
    }

    /**
     * Clear cached configs (useful for testing)
     */
    public static function clearCache()
    {
        self::$endpointPermissions = null;
        self::$rolePermissions = null;
        self::$configPath = null;
    }

    /**
     * Normalize endpoint path to config key format
     *
     * @param string $path e.g., "/btb/add" or "/simadiskc/btb/add"
     * @return string e.g., "btb/add"
     */
    protected function normalizeEndpoint($path)
    {
        // Remove leading/trailing slashes
        $path = trim($path, '/');

        // Remove common base path prefixes if present
        $prefixes = ['simadiskc', 'simadis', 'index.php'];
        foreach ($prefixes as $prefix) {
            if (stripos($path, $prefix . '/') === 0) {
                $path = substr($path, strlen($prefix) + 1);
            }
        }

        // Convert to lowercase for case-insensitive matching
        return strtolower($path);
    }

    /**
     * Get required modules and permissions for an endpoint
     *
     * @param string $endpointKey
     * @return array|null Array of required modules, or null if endpoint not registered
     */
    protected function getRequiredPermissions($endpointKey)
    {
        if (!isset(self::$endpointPermissions[$endpointKey])) {
            return null; // Endpoint not registered
        }

        return self::$endpointPermissions[$endpointKey]['modules'] ?? [];
    }

    /**
     * Check if any of user's roles satisfy the required permissions
     *
     * @param array $userRoles User's roles from session
     * @param array $requiredModules Required modules with permissions
     * @return array ['granted' => bool, 'role' => string|null, 'reason' => string]
     */
    protected function userHasPermissions(array $userRoles, array $requiredModules)
    {
        if (empty($userRoles)) {
            return [
                'granted' => false,
                'role' => null,
                'reason' => 'User has no roles assigned'
            ];
        }

        $checkedRoles = [];
        $missingPermissions = [];

        // Check each user role
        foreach ($userRoles as $role) {
            $roleLower = strtolower($role);
            $checkedRoles[] = $role;

            if (!isset(self::$rolePermissions[$roleLower])) {
                $missingPermissions[$role] = "Role not found in configuration";
                continue; // Role not in config, try next
            }

            $roleModules = self::$rolePermissions[$roleLower]['modules'] ?? [];

            // Check if this role satisfies ALL required modules
            $satisfiesResult = $this->roleSatisfiesRequirements($roleModules, $requiredModules);

            if ($satisfiesResult['satisfied']) {
                return [
                    'granted' => true,
                    'role' => $role,
                    'reason' => ''
                ];
            }

            $missingPermissions[$role] = $satisfiesResult['reason'];
        }

        // Build detailed reason for denial
        $reason = "None of the user's roles have required permissions. ";
        $reason .= "Checked roles: " . implode(', ', $checkedRoles) . ". ";
        foreach ($missingPermissions as $role => $issue) {
            $reason .= "[$role: $issue] ";
        }

        return [
            'granted' => false,
            'role' => null,
            'reason' => trim($reason)
        ];
    }

    /**
     * Check if a role's module permissions satisfy all requirements
     *
     * @param array $roleModules Role's module permissions
     * @param array $requiredModules Required modules with permissions
     * @return array ['satisfied' => bool, 'reason' => string]
     */
    protected function roleSatisfiesRequirements(array $roleModules, array $requiredModules)
    {
        $missingDetails = [];

        foreach ($requiredModules as $requirement) {
            $moduleName = strtolower($requirement['name']);
            $requiredPerms = $requirement['permissions'] ?? [];

            // Check if role has this module
            if (!isset($roleModules[$moduleName])) {
                $missingDetails[] = "Missing module '{$requirement['name']}'";
                continue;
            }

            $rolePerms = $roleModules[$moduleName];
            $missingPerms = [];

            // Check if role has all required permissions for this module
            foreach ($requiredPerms as $perm) {
                if (!in_array(strtoupper($perm), array_map('strtoupper', $rolePerms))) {
                    $missingPerms[] = strtoupper($perm);
                }
            }

            if (!empty($missingPerms)) {
                $has = implode(',', array_map('strtoupper', $rolePerms));
                $missing = implode(',', $missingPerms);
                $missingDetails[] = "Module '{$requirement['name']}': has [$has], missing [$missing]";
            }
        }

        if (empty($missingDetails)) {
            return [
                'satisfied' => true,
                'reason' => ''
            ];
        }

        return [
            'satisfied' => false,
            'reason' => implode('; ', $missingDetails)
        ];
    }

    /**
     * Handle unauthorized access
     *
     * @param string $endpoint The endpoint that was denied
     * @param array $userRoles The roles the user has
     * @param array $requiredModules The modules/permissions required
     * @param string $reason Detailed reason for denial
     */
    protected function handleUnauthorized($endpoint, $userRoles, $requiredModules, $reason)
    {
        // Build detailed log message
        $logMessage = "Access denied to endpoint: $endpoint. ";
        $logMessage .= "User roles: [" . implode(', ', $userRoles) . "]. ";

        // Format required modules
        $reqModulesFormatted = [];
        foreach ($requiredModules as $module) {
            $perms = implode(',', $module['permissions']);
            $reqModulesFormatted[] = "{$module['name']}[$perms]";
        }
        $logMessage .= "Required: " . implode(', ', $reqModulesFormatted) . ". ";
        $logMessage .= "Reason: $reason";

        $this->log($logMessage, 'warning');

        // Development-mode detailed logging
        $this->logDevelopmentDetails($endpoint, $userRoles, $requiredModules);

        // Set flash message
        $this->setAccessDeniedNotice();

        // Redirect to previous page
        $this->redirectBack();
    }

    /**
     * Log detailed access denial information for development/debugging
     *
     * @param string $endpoint The endpoint that was denied
     * @param array $userRoles The roles the user has
     * @param array $requiredModules The modules/permissions required
     */
    protected function logDevelopmentDetails($endpoint, $userRoles, $requiredModules)
    {
        $details = "\n" . str_repeat('=', 80) . "\n";
        $details .= "ACCESS DENIED - Detailed Breakdown\n";
        $details .= str_repeat('=', 80) . "\n";
        $details .= "Endpoint: $endpoint\n";
        $details .= str_repeat('-', 80) . "\n";

        // Show required permissions
        $details .= "REQUIRED PERMISSIONS:\n";
        foreach ($requiredModules as $module) {
            $perms = implode(', ', array_map('strtoupper', $module['permissions']));
            $details .= "  - Module: '{$module['name']}' needs [$perms]\n";
        }
        $details .= str_repeat('-', 80) . "\n";

        // Show user's roles and their permissions
        $details .= "USER'S ROLES AND PERMISSIONS:\n";
        if (empty($userRoles)) {
            $details .= "  (No roles assigned to user)\n";
        } else {
            foreach ($userRoles as $role) {
                $roleLower = strtolower($role);
                $details .= "  Role: '$role'\n";

                if (!isset(self::$rolePermissions[$roleLower])) {
                    $details .= "    Status: NOT FOUND in role_permissions.json\n";
                    $details .= "    Permissions: (none - role not configured)\n";
                } else {
                    $roleConfig = self::$rolePermissions[$roleLower];
                    $details .= "    Status: Found in configuration\n";

                    if (empty($roleConfig['modules'])) {
                        $details .= "    Permissions: (no modules assigned)\n";
                    } else {
                        $details .= "    Permissions:\n";
                        foreach ($roleConfig['modules'] as $moduleName => $perms) {
                            $permsFormatted = implode(', ', array_map('strtoupper', $perms));
                            $details .= "      - Module: '$moduleName' has [$permsFormatted]\n";
                        }
                    }
                }
                $details .= "\n";
            }
        }
        $details .= str_repeat('-', 80) . "\n";

        // Show comparison for each required module
        $details .= "PERMISSION COMPARISON:\n";
        foreach ($requiredModules as $module) {
            $moduleName = strtolower($module['name']);
            $requiredPerms = array_map('strtoupper', $module['permissions']);
            $details .= "  Module: '{$module['name']}'\n";
            $details .= "    Required: [" . implode(', ', $requiredPerms) . "]\n";

            $hasAccess = false;
            foreach ($userRoles as $role) {
                $roleLower = strtolower($role);
                if (isset(self::$rolePermissions[$roleLower]['modules'][$moduleName])) {
                    $userPerms = array_map('strtoupper', self::$rolePermissions[$roleLower]['modules'][$moduleName]);
                    $missing = array_diff($requiredPerms, $userPerms);

                    $details .= "    User has (via '$role'): [" . implode(', ', $userPerms) . "]";
                    if (empty($missing)) {
                        $details .= " ✓ SUFFICIENT\n";
                        $hasAccess = true;
                    } else {
                        $details .= " ✗ Missing: [" . implode(', ', $missing) . "]\n";
                    }
                }
            }

            if (!$hasAccess) {
                // Check if any role has this module at all
                $hasModule = false;
                foreach ($userRoles as $role) {
                    $roleLower = strtolower($role);
                    if (isset(self::$rolePermissions[$roleLower]['modules'][$moduleName])) {
                        $hasModule = true;
                        break;
                    }
                }
                if (!$hasModule) {
                    $details .= "    User has: (module not assigned to any user role)\n";
                }
            }
            $details .= "\n";
        }

        $details .= str_repeat('=', 80) . "\n";

        $this->log($details, 'error');
    }

    /**
     * Set access denied notice
     */
    protected function setAccessDeniedNotice()
    {
        $message = 'Anda tidak memiliki izin untuk mengakses halaman tersebut.';

        if (function_exists('get_instance')) {
            $ci =& get_instance();
            $ci->load->library('session');
            $ci->session->set_flashdata('permission_denied', $message);
        } else {
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            $_SESSION['permission_denied'] = $message;
        }
    }

    /**
     * Redirect to previous page (referer) or home as fallback
     */
    protected function redirectBack()
    {
        // Get referer URL
        $referer = $_SERVER['HTTP_REFERER'] ?? null;
        
        // Validate referer is from same host (security)
        if ($referer) {
            $refererHost = parse_url($referer, PHP_URL_HOST);
            $currentHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
            
            if ($refererHost === $currentHost) {
                if (function_exists('redirect')) {
                    redirect($referer);
                } else {
                    header("Location: " . $referer);
                    exit;
                }
                return;
            }
        }

        // Fallback to home if no valid referer
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
     * Check if current path is excluded from permission checks
     *
     * @param string $path
     * @return bool
     */
    protected function isExcludedPath($path)
    {
        $path = '/' . trim($path, '/');

        foreach ($this->excludedPaths as $excludedPath) {
            $excludedPath = '/' . trim($excludedPath, '/');

            if ($path === $excludedPath) {
                return true;
            }

            if (strpos($path, $excludedPath . '/') === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get current request path
     *
     * @return string
     */
    protected function getCurrentPath()
    {
        if (function_exists('uri_string')) {
            return '/' . uri_string();
        }
        // does not eextract the query parameters or domain name
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
        return $path ?: '/';
    }

    /**
     * Get base URL
     *
     * @return string
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
     * Log message
     *
     * @param string $message
     * @param string $level Log level (debug, info, warning, error)
     */
    protected function log($message, $level = 'debug')
    {
        $formatted = "[PermissionMiddleware] $message";

        if (function_exists('log_message')) {
            // Map levels to CodeIgniter's log levels
            $ciLevel = $level;
            if (!in_array($level, ['error', 'debug', 'info'])) {
                $ciLevel = 'debug'; // CI3 doesn't have 'warning', use 'debug'
            }
            log_message($ciLevel, $formatted);
        } else {
            error_log("[$level] $formatted");
        }
    }

    /**
     * Get loaded endpoint permissions (for debugging/testing)
     *
     * @return array
     */
    public static function getEndpointPermissions()
    {
        return self::$endpointPermissions ?? [];
    }

    /**
     * Get loaded role permissions (for debugging/testing)
     *
     * @return array
     */
    public static function getRolePermissions()
    {
        return self::$rolePermissions ?? [];
    }
}

