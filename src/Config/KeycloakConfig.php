<?php

namespace Simss\KeycloakAuth\Config;

class KeycloakConfig
{
    private $config;
    private static $instance;

    private function __construct(array $config = [])
    {
        if (empty($config)) {
            $config = $this->loadConfigFile();
        }
        $this->config = $config;
        $this->validate();
    }

    public static function getInstance(array $config = [])
    {
        if (self::$instance === null) {
            self::$instance = new self($config);
        }
        return self::$instance;
    }

    public static function reset()
    {
        self::$instance = null;
    }

    private function loadConfigFile()
    {
        // For CodeIgniter integration
        if (function_exists('config_item')) {
            $ci =& get_instance();
            $ci->load->config('keycloak', TRUE);
            $config = $ci->config->item('keycloak');

            // If CodeIgniter config loading failed, try direct file loading
            if (empty($config) && defined('APPPATH')) {
                $ciConfigPath = APPPATH . 'config/keycloak.php';
                if (file_exists($ciConfigPath)) {
                    $configData = require $ciConfigPath;
                    return $configData['keycloak'] ?? [];
                }
            }

            return $config ?: [];
        }

        // Standalone loading
        $configPath = dirname(dirname(__DIR__)) . '/config/keycloak.php';
        if (file_exists($configPath)) {
            return require $configPath;
        }

        return [];
    }

    private function validate()
    {
        $required = ['issuer', 'client_id', 'client_secret', 'redirect_uri'];

        foreach ($required as $field) {
            if (empty($this->config[$field])) {
                throw new \InvalidArgumentException("Missing required configuration: {$field}");
            }
        }

        // Validate URL format
        if (!filter_var($this->config['issuer'], FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("Invalid issuer URL");
        }

        if (!filter_var($this->config['redirect_uri'], FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("Invalid redirect_uri URL");
        }

        // Enforce HTTPS in production (security best practice)
        $allowHttp = $this->config['allow_http'] ?? false;
        if (!$allowHttp) {
            $issuerScheme = parse_url($this->config['issuer'], PHP_URL_SCHEME);
            if ($issuerScheme !== 'https') {
                throw new \InvalidArgumentException(
                    "HTTPS is required for issuer URL in production. " .
                    "Use HTTPS or set 'allow_http' => true for development only."
                );
            }

            $redirectScheme = parse_url($this->config['redirect_uri'], PHP_URL_SCHEME);
            if ($redirectScheme !== 'https') {
                throw new \InvalidArgumentException(
                    "HTTPS is required for redirect_uri in production. " .
                    "Use HTTPS or set 'allow_http' => true for development only."
                );
            }
        }
    }

    public function get($key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }

    public function getIssuer()
    {
        return $this->config['issuer'];
    }

    public function getClientId()
    {
        return $this->config['client_id'];
    }

    public function getClientSecret()
    {
        return $this->config['client_secret'];
    }

    public function getRedirectUri()
    {
        return $this->config['redirect_uri'];
    }

    public function getTokenEndpoint()
    {
        return $this->get('token_endpoint', $this->config['issuer'] . '/protocol/openid-connect/token');
    }

    public function getUserInfoEndpoint()
    {
        return $this->get('userinfo_endpoint', $this->config['issuer'] . '/protocol/openid-connect/userinfo');
    }

    public function getAuthorizationEndpoint()
    {
        return $this->get('authorization_endpoint', $this->config['issuer'] . '/protocol/openid-connect/auth');
    }

    public function getLogoutEndpoint()
    {
        return $this->get('logout_endpoint', $this->config['issuer'] . '/protocol/openid-connect/logout');
    }

    public function getScopes()
    {
        return $this->get('scopes', ['openid', 'profile', 'email']);
    }

    public function shouldVerifyPeer()
    {
        return $this->get('verify_peer', true);
    }

    public function shouldVerifyHost()
    {
        return $this->get('verify_host', true);
    }

    public function getCertPath()
    {
        return $this->get('cert_path', null);
    }

    public function getHttpProxy()
    {
        return $this->get('http_proxy', null);
    }

    public function getTokenRefreshBuffer()
    {
        return $this->get('token_refresh_buffer', 60);
    }

    public function getCurlTimeout()
    {
        return $this->get('curl_timeout', 30);
    }

    public function getCurlConnectTimeout()
    {
        return $this->get('curl_connect_timeout', 10);
    }

    public function toArray()
    {
        return $this->config;
    }
}