<?php

namespace Simss\KeycloakAuth\Auth;

class SessionManager
{
    const SESSION_KEY = 'keycloak_auth';
    const TOKEN_KEY = 'keycloak_tokens';

    private $ci;
    private $useCodeIgniter;

    public function __construct()
    {
        $this->useCodeIgniter = function_exists('get_instance');

        if ($this->useCodeIgniter) {
            $this->ci =& get_instance();
            $this->ci->load->library('session');
        } else {
            // Ensure native PHP session is started
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
        }
    }

    public function createSession($userInfo, $tokens)
    {
        // Extract user attributes from Keycloak userInfo
        $userData = [
            'username' => $this->extractUsername($userInfo),
            'lvl' => $this->extractUserLevel($userInfo),
            'nama' => $this->extractUserName($userInfo),
            'kdcab' => $this->extractAttribute($userInfo, 'kdcab', ''),
            'inicab' => $this->extractAttribute($userInfo, 'inicab', ''),
            'email' => $this->extractAttribute($userInfo, 'email', ''),
            'logged_in' => true,
        ];

        // Store tokens separately
        $tokenData = [
            'access_token' => $tokens['access_token'] ?? null,
            'refresh_token' => $tokens['refresh_token'] ?? null,
            'id_token' => $tokens['id_token'] ?? null,
            'expires_at' => time() + ($tokens['expires_in'] ?? 3600),
        ];

        if ($this->useCodeIgniter) {
            $this->ci->session->set_userdata(self::SESSION_KEY, $userData);
            $this->ci->session->set_userdata(self::TOKEN_KEY, $tokenData);
        } else {
            $_SESSION[self::SESSION_KEY] = $userData;
            $_SESSION[self::TOKEN_KEY] = $tokenData;
        }

        return $userData;
    }

    public function isAuthenticated()
    {
        $sessionData = $this->getSessionData();
        return !empty($sessionData['logged_in']);
    }

    public function getSessionData()
    {
        if ($this->useCodeIgniter) {
            return $this->ci->session->userdata(self::SESSION_KEY) ?: [];
        } else {
            return $_SESSION[self::SESSION_KEY] ?? [];
        }
    }

    public function getTokens()
    {
        if ($this->useCodeIgniter) {
            return $this->ci->session->userdata(self::TOKEN_KEY) ?: [];
        } else {
            return $_SESSION[self::TOKEN_KEY] ?? [];
        }
    }

    public function getAccessToken()
    {
        $tokens = $this->getTokens();
        return $tokens['access_token'] ?? null;
    }

    public function getRefreshToken()
    {
        $tokens = $this->getTokens();
        return $tokens['refresh_token'] ?? null;
    }

    public function getIdToken()
    {
        $tokens = $this->getTokens();
        return $tokens['id_token'] ?? null;
    }

    public function isTokenExpired()
    {
        $tokens = $this->getTokens();

        if (empty($tokens['expires_at'])) {
            return true;
        }

        // Add 60 second buffer for token refresh
        return time() >= ($tokens['expires_at'] - 60);
    }

    public function updateTokens($tokens)
    {
        $tokenData = [
            'access_token' => $tokens['access_token'] ?? $this->getAccessToken(),
            'refresh_token' => $tokens['refresh_token'] ?? $this->getRefreshToken(),
            'id_token' => $tokens['id_token'] ?? $this->getIdToken(),
            'expires_at' => time() + ($tokens['expires_in'] ?? 3600),
        ];

        if ($this->useCodeIgniter) {
            $this->ci->session->set_userdata(self::TOKEN_KEY, $tokenData);
        } else {
            $_SESSION[self::TOKEN_KEY] = $tokenData;
        }
    }

    public function destroy()
    {
        if ($this->useCodeIgniter) {
            $this->ci->session->unset_userdata(self::SESSION_KEY);
            $this->ci->session->unset_userdata(self::TOKEN_KEY);
            $this->ci->session->sess_destroy();
        } else {
            unset($_SESSION[self::SESSION_KEY]);
            unset($_SESSION[self::TOKEN_KEY]);
            session_destroy();
        }
    }

    public function getUserAttribute($key, $default = null)
    {
        $sessionData = $this->getSessionData();
        return $sessionData[$key] ?? $default;
    }

    private function extractUsername($userInfo)
    {
        return $userInfo->preferred_username
            ?? $userInfo->username
            ?? $userInfo->sub
            ?? '';
    }

    private function extractUserName($userInfo)
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
}
