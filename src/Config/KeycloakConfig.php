<?php

namespace Simss\KeycloakAuth\Config;

class KeycloakConfig
{
    private $config;
    private $configLoaded = false;
    private static $instance;

    private function __construct(array $config = [])
    {
        if (!empty($config)) {
            $this->config = $config;
            $this->configLoaded = true;
            $this->validate();
        }
        // If config is empty, we'll lazy load it on first access
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

    private function ensureConfigLoaded()
    {
        if ($this->configLoaded) {
            return;
        }

        $this->config = $this->loadConfigFile();
        $this->configLoaded = true;
        $this->validate();
    }

    private function loadConfigFile()
    {
        // For CodeIgniter integration - CI should be ready by now
        if (function_exists('config_item')) {
            $ci =& get_instance();
            if ($ci !== null) {
                $ci->load->config('keycloak');
                $keycloakConfig = $ci->config->item('keycloak');
                if (is_array($keycloakConfig) && !empty($keycloakConfig)) {
                    return $keycloakConfig;
                }
            }
        }

        // Standalone loading fallback
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
    }

    public function get($key, $default = null)
    {
        $this->ensureConfigLoaded();
        return $this->config[$key] ?? $default;
    }

    public function getIssuer()
    {
        $this->ensureConfigLoaded();
        return $this->config['issuer'];
    }

    public function getClientId()
    {
        $this->ensureConfigLoaded();
        return $this->config['client_id'];
    }

    public function getClientSecret()
    {
        $this->ensureConfigLoaded();
        return $this->config['client_secret'];
    }

    public function getRedirectUri()
    {
        $this->ensureConfigLoaded();
        return $this->config['redirect_uri'];
    }

    public function getTokenEndpoint()
    {
        $this->ensureConfigLoaded();
        return $this->get('token_endpoint', $this->config['issuer'] . '/protocol/openid-connect/token');
    }

    public function getUserInfoEndpoint()
    {
        $this->ensureConfigLoaded();
        return $this->get('userinfo_endpoint', $this->config['issuer'] . '/protocol/openid-connect/userinfo');
    }

    public function getAuthorizationEndpoint()
    {
        $this->ensureConfigLoaded();
        return $this->get('authorization_endpoint', $this->config['issuer'] . '/protocol/openid-connect/auth');
    }

    public function getLogoutEndpoint()
    {
        $this->ensureConfigLoaded();
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

    public function toArray()
    {
        $this->ensureConfigLoaded();
        return $this->config;
    }
}