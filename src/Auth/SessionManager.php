<?php

namespace Simss\KeycloakAuth\Auth;

/**
 * SessionManager - Manages server-side session for SSR OIDC authentication
 * This class is NOT exposed to the client, to be used internally by the connector.
 * 
 * For SSR applications, authentication state is managed via server-side sessions.
 * ID token is stored (for OIDC logout). Access token is stored for keycloak getuserinfo(). 
 * Session expiry is controlled by CodeIgniter's session configuration, not token expiration.
 * 
 * IMPORTANT: Uses native PHP $_SESSION to maintain compatibility with the
 * jumbojett OIDC library which stores state/nonce in $_SESSION.
 */
class SessionManager
{
    // keys for storing session data in session or $_SESSION
    const SESSION_KEY = 'keycloak_auth';
    const TOKEN_KEY = 'keycloak_id_token';
    const TOKENS_KEY = 'keycloak_tokens';

    public function __construct()
    {
        // Always use native PHP session for compatibility with OIDC library
        // The jumbojett OIDC library stores state/nonce in $_SESSION,
        // so we must use the same session storage for auth data
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Create a new authenticated session
     *
     * @param object $userInfo User info from Keycloak
     * @param array|string|null $tokens Tokens array or legacy ID token string
     * @return array User data stored in session
     */
    public function createSession($userInfo, $tokens = [])
    {
        // Backward compatibility: convert legacy string idToken to tokens array
        if (is_string($tokens)) {
            $tokens = ['id_token' => $tokens];
        }

        // Extract token claims (iat, exp, etc.) from JWT
        $tokenClaims = [];
        if (!empty($tokens['id_token'])) {
            $tokenClaims = $this->decodeJwtClaims($tokens['id_token']);
        } elseif (!empty($tokens['access_token'])) {
            $tokenClaims = $this->decodeJwtClaims($tokens['access_token']);
        }

        // Extract user attributes from Keycloak userInfo
        $roles = $this->extractRoles($userInfo);
        $groups = $this->extractGroups($userInfo);
        $userData = [
            'username' => $this->extractUsername($userInfo),
            // Backward compatibility: keep lvl as first available role/group
            'lvl' => $roles[0] ?? $groups[0] ?? $this->extractUserLevel($userInfo),
            'roles' => $roles,
            'groups' => $groups,
            'nama' => $this->extractFullName($userInfo),
            'kdcab' => $this->extractAttribute($userInfo, 'kdcab', ''),
            'inicab' => $this->extractAttribute($userInfo, 'inicab', ''),
            'email' => $this->extractAttribute($userInfo, 'email', ''),
            // Custom SIMSS organizational attributes (nested under 'simss' key)
            'simss' => [
                'cabang' => $this->extractSimssCabang($userInfo),
                'role' => $this->extractSimssRole($userInfo),
                'divisi' => $this->extractSimssDivisi($userInfo),
                'station' => $this->extractSimssStation($userInfo),
                'subdivisi' => $this->extractSimssSubdivisi($userInfo),
            ],
            // Token metadata (from JWT claims)
            'iat' => $tokenClaims['iat'] ?? null,
            'exp' => $tokenClaims['exp'] ?? null,
            'sub' => $tokenClaims['sub'] ?? null,
            'logged_in' => true,
        ];

        // Use native PHP session for compatibility with OIDC library
        $_SESSION[self::SESSION_KEY] = $userData;

        // Store tokens (access, refresh, ID tokens with expiry)
        if (!empty($tokens)) {
            $this->storeTokens($tokens);
        }

        return $userData;
    }

    /**
     * Check if user is authenticated via PHP session
     */
    public function isAuthenticated()
    {
        $sessionData = $this->getSessionData();
        return !empty($sessionData['logged_in']);
    }

    /**
     * Get session data
     */
    public function getSessionData()
    {
        return $_SESSION[self::SESSION_KEY] ?? [];
    }

    /**
     * Get ID token originally from Keycloak, stored in session when user is authenticated (needed for OIDC logout)
     */
    public function getIdToken()
    {
        return $_SESSION[self::TOKEN_KEY] ?? null;
    }

    /**
     * Get access token from session
     * @return string|null
     */
    public function getAccessToken()
    {
        $tokens = $_SESSION[self::TOKENS_KEY] ?? [];
        return $tokens['access_token'] ?? null;
    }

    /**
     * Get refresh token from session
     * @return string|null
     */
    public function getRefreshToken()
    {
        $tokens = $_SESSION[self::TOKENS_KEY] ?? [];
        return $tokens['refresh_token'] ?? null;
    }

    /**
     * Get all tokens as array
     * @return array
     */
    public function getTokens()
    {
        return $_SESSION[self::TOKENS_KEY] ?? [];
    }

    /**
     * Check if access token is expired or will expire soon
     *
     * @param int|null $bufferSeconds Seconds before expiry to consider token expired (default from config: 60)
     * @return bool True if expired or no expiry info available
     */
    public function isTokenExpired($bufferSeconds = null)
    {
        $tokens = $_SESSION[self::TOKENS_KEY] ?? [];

        // No expiry info = treat as expired (requires refresh)
        if (!isset($tokens['expires_at'])) {
            return true;
        }

        // Use config buffer if not provided
        if ($bufferSeconds === null) {
            try {
                $config = \Simss\KeycloakAuth\Config\KeycloakConfig::getInstance();
                $bufferSeconds = $config->getTokenRefreshBuffer();
            } catch (\Exception $e) {
                // Config not available (e.g., in tests) - use default
                $bufferSeconds = 60;
            }
        }

        // Check if expired or within buffer window
        $expiresAt = (int)$tokens['expires_at'];
        $now = time();

        return ($now + $bufferSeconds) >= $expiresAt;
    }

    /**
     * Update tokens after refresh (preserves user session data)
     *
     * @param array $newTokens New tokens from refresh response
     */
    public function updateTokens(array $newTokens)
    {
        $this->storeTokens($newTokens);
    }

    /**
     * Store OAuth2/OIDC tokens in session with expiry tracking
     *
     * @param array $tokens Token response from Keycloak
     *                      - access_token (required)
     *                      - refresh_token (optional)
     *                      - id_token (optional)
     *                      - expires_in (optional, in seconds)
     */
    private function storeTokens(array $tokens)
    {
        $tokenData = [];

        // Access token
        if (isset($tokens['access_token'])) {
            $tokenData['access_token'] = $tokens['access_token'];
        }

        // Refresh token
        if (isset($tokens['refresh_token'])) {
            $tokenData['refresh_token'] = $tokens['refresh_token'];
        }

        // ID token
        if (isset($tokens['id_token'])) {
            $tokenData['id_token'] = $tokens['id_token'];
            // IMPORTANT: Also store in legacy location for backward compatibility
            $_SESSION[self::TOKEN_KEY] = $tokens['id_token'];
        }

        // Calculate expiry timestamp
        if (isset($tokens['expires_in'])) {
            // expires_at = current_time + expires_in
            $tokenData['expires_at'] = time() + (int)$tokens['expires_in'];
        }

        // Store token data
        $_SESSION[self::TOKENS_KEY] = $tokenData;
    }

    /**
     * Destroy the session (logout)
     * 
     * Properly destroys the session by:
     * 1. Clearing all session variables from memory
     * 2. Deleting the session cookie from browser
     * 3. Destroying the session file on server
     */
    public function destroy()
    {
        // Clear all session variables from $_SESSION superglobal
        $_SESSION = [];
        
        // Delete the session cookie from browser
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }
        
        // Destroy the session file on server
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    /**
     * Get a specific user attribute from session
     */
    public function getUserAttribute($key, $default = null)
    {
        $sessionData = $this->getSessionData();
        return $sessionData[$key] ?? $default;
    }

    /**
     * Get all roles from session
     */
    public function getRoles()
    {
        $sessionData = $this->getSessionData();
        return $sessionData['roles'] ?? [];
    }

    /**
     * Get all groups from session
     */
    public function getGroups()
    {
        $sessionData = $this->getSessionData();
        return $sessionData['groups'] ?? [];
    }

    /**
     * Get all SIMSS organizational data
     *
     * @return array SIMSS data with keys: cabang, role, divisi, station, subdivisi
     */
    public function getSimssData()
    {
        $sessionData = $this->getSessionData();
        return $sessionData['simss'] ?? [
            'cabang' => [],
            'role' => [],
            'divisi' => [],
            'station' => [],
            'subdivisi' => [],
        ];
    }

    /**
     * Get a specific SIMSS attribute
     *
     * @param string $key SIMSS attribute key (cabang, role, divisi, station, subdivisi)
     * @param mixed $default Default value if not found
     * @return array|mixed
     */
    public function getSimssAttribute($key, $default = [])
    {
        $simssData = $this->getSimssData();
        return $simssData[$key] ?? $default;
    }

    /**
     * Check if user has a role (case-insensitive)
     */
    public function hasRole($role)
    {
        $role = strtolower($role);
        foreach ($this->getRoles() as $r) {
            if (strtolower($r) === $role) {
                return true;
            }
        }
        foreach ($this->getGroups() as $g) {
            if (strtolower($g) === $role) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if user has any of the provided roles
     */
    public function hasAnyRole(array $roles)
    {
        foreach ($roles as $role) {
            if ($this->hasRole($role)) {
                return true;
            }
        }
        return false;
    }

    private function extractUsername($userInfo)
    {
        return $userInfo->preferred_username
            ?? $userInfo->username
            ?? $userInfo->sub
            ?? '';
    }

    private function extractFullName($userInfo)
    {
        if (isset($userInfo->name)) {
            return $userInfo->name;
        }

        $firstName = $userInfo->given_name ?? '';
        $lastName = $userInfo->family_name ?? '';

        return trim($firstName . ' ' . $lastName);
    }

    private function extractUserLevel($userInfo)
    {
        // Try custom claim first
        if (isset($userInfo->lvl)) {
            return $userInfo->lvl;
        }

        // Try groups/roles
        if (isset($userInfo->groups) && is_array($userInfo->groups)) {
            return $userInfo->groups[0] ?? '';
        }

        if (isset($userInfo->roles) && is_array($userInfo->roles)) {
            return $userInfo->roles[0] ?? '';
        }

        return '';
    }

    private function extractAttribute($userInfo, $key, $default = null)
    {
        return $userInfo->{$key} ?? $default;
    }

    /**
     * Extract roles from Keycloak user info (realm or resource roles)
     */
    private function extractRoles($userInfo)
    {
        $roles = [];

        // Direct roles claim
        if (isset($userInfo->roles) && is_array($userInfo->roles)) {
            $roles = array_merge($roles, $userInfo->roles);
        }

        // realm_access.roles
        if (isset($userInfo->realm_access->roles) && is_array($userInfo->realm_access->roles)) {
            $roles = array_merge($roles, $userInfo->realm_access->roles);
        }

        // resource_access.*.roles
        if (isset($userInfo->resource_access) && is_object($userInfo->resource_access)) {
            foreach ($userInfo->resource_access as $resource) {
                if (isset($resource->roles) && is_array($resource->roles)) {
                    $roles = array_merge($roles, $resource->roles);
                }
            }
        }

        // Custom SIMSS roles (simss_role)
        if (isset($userInfo->simss_role) && is_array($userInfo->simss_role)) {
            $roles = array_merge($roles, $userInfo->simss_role);
        }

        // Ensure unique values
        return array_values(array_unique($roles));
    }

    /**
     * Extract groups from Keycloak user info
     * Also extracts SIMSS organizational attributes (cabang, divisi, station, subdivisi)
     */
    private function extractGroups($userInfo)
    {
        $groups = [];

        // Standard groups claim
        if (isset($userInfo->groups) && is_array($userInfo->groups)) {
            $groups = array_merge($groups, $userInfo->groups);
        }

        // Custom SIMSS organizational fields
        // These are included in groups for backward compatibility with hasRole() checks
        if (isset($userInfo->simss_cabang) && is_array($userInfo->simss_cabang)) {
            $groups = array_merge($groups, $userInfo->simss_cabang);
        }

        if (isset($userInfo->simss_divisi) && is_array($userInfo->simss_divisi)) {
            $groups = array_merge($groups, $userInfo->simss_divisi);
        }

        if (isset($userInfo->simss_station) && is_array($userInfo->simss_station)) {
            $groups = array_merge($groups, $userInfo->simss_station);
        }

        if (isset($userInfo->simss_subdivisi) && is_array($userInfo->simss_subdivisi)) {
            $groups = array_merge($groups, $userInfo->simss_subdivisi);
        }

        return array_values(array_unique($groups));
    }

    /**
     * Extract SIMSS cabang (branch) from token
     * @return array
     */
    private function extractSimssCabang($userInfo)
    {
        if (isset($userInfo->simss_cabang) && is_array($userInfo->simss_cabang)) {
            return $userInfo->simss_cabang;
        }
        return [];
    }

    /**
     * Extract SIMSS role from token
     * @return array
     */
    private function extractSimssRole($userInfo)
    {
        if (isset($userInfo->simss_role) && is_array($userInfo->simss_role)) {
            return $userInfo->simss_role;
        }
        return [];
    }

    /**
     * Extract SIMSS divisi (division) from token
     * @return array
     */
    private function extractSimssDivisi($userInfo)
    {
        if (isset($userInfo->simss_divisi) && is_array($userInfo->simss_divisi)) {
            return $userInfo->simss_divisi;
        }
        return [];
    }

    /**
     * Extract SIMSS station from token
     * @return array
     */
    private function extractSimssStation($userInfo)
    {
        if (isset($userInfo->simss_station) && is_array($userInfo->simss_station)) {
            return $userInfo->simss_station;
        }
        return [];
    }

    /**
     * Extract SIMSS subdivisi (subdivision) from token
     * @return array
     */
    private function extractSimssSubdivisi($userInfo)
    {
        if (isset($userInfo->simss_subdivisi) && is_array($userInfo->simss_subdivisi)) {
            return $userInfo->simss_subdivisi;
        }
        return [];
    }

    /**
     * Decode JWT token and extract claims (iat, exp, sub, etc.)
     *
     * @param string $jwt JWT token string
     * @return array Decoded claims from the token payload
     */
    private function decodeJwtClaims($jwt)
    {
        if (empty($jwt)) {
            return [];
        }

        try {
            // JWT has 3 parts separated by dots: header.payload.signature
            $parts = explode('.', $jwt);

            if (count($parts) !== 3) {
                return [];
            }

            // Decode the payload (second part)
            $payload = $parts[1];

            // JWT uses base64url encoding (not standard base64)
            // Replace URL-safe characters and add padding if needed
            $payload = str_replace(['-', '_'], ['+', '/'], $payload);
            $remainder = strlen($payload) % 4;
            if ($remainder) {
                $payload .= str_repeat('=', 4 - $remainder);
            }

            // Decode from base64
            $decoded = base64_decode($payload, true);

            if ($decoded === false) {
                return [];
            }

            // Parse JSON
            $claims = json_decode($decoded, true);

            return is_array($claims) ? $claims : [];

        } catch (\Exception $e) {
            // Silent fail - return empty array
            return [];
        }
    }
}
