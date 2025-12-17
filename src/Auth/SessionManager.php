<?php

namespace Simss\KeycloakAuth\Auth;

/**
 * SessionManager - Manages server-side session for SSR OIDC authentication
 * 
 * For SSR applications, authentication state is managed via server-side sessions.
 * Only the ID token is stored (for OIDC logout). Session expiry is controlled
 * by CodeIgniter's session configuration, not token expiration.
 * 
 * IMPORTANT: Uses native PHP $_SESSION to maintain compatibility with the
 * jumbojett OIDC library which stores state/nonce in $_SESSION.
 */
class SessionManager
{
    // keys for storing session data in session or $_SESSION   
    const SESSION_KEY = 'keycloak_auth';
    const TOKEN_KEY = 'keycloak_id_token';

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
     * @param string|null $idToken ID token for OIDC logout
     * @return array User data stored in session
     */
    public function createSession($userInfo, $idToken = null)
    {
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
            'logged_in' => true,
        ];

        // Use native PHP session for compatibility with OIDC library
        $_SESSION[self::SESSION_KEY] = $userData;
        if ($idToken) {
            $_SESSION[self::TOKEN_KEY] = $idToken;
        }

        return $userData;
    }

    /**
     * Check if user is authenticated via session
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

        // Ensure unique values
        return array_values(array_unique($roles));
    }

    /**
     * Extract groups from Keycloak user info
     */
    private function extractGroups($userInfo)
    {
        if (isset($userInfo->groups) && is_array($userInfo->groups)) {
            return array_values(array_unique($userInfo->groups));
        }
        return [];
    }
}
