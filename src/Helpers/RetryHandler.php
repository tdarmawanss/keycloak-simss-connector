<?php

namespace Simss\KeycloakAuth\Helpers;

/**
 * RetryHandler - Provides resilient request handling with retry logic
 *
 * Prevents fatal errors when Keycloak is unreachable or slow by:
 * - Retrying failed requests with exponential backoff
 * - Extending PHP execution time for network operations
 * - Providing graceful fallback on persistent failures
 */
class RetryHandler
{
    /** @var int Maximum number of retry attempts */
    private $maxRetries;

    /** @var int Initial delay in milliseconds */
    private $initialDelay;

    /** @var float Backoff multiplier for each retry */
    private $backoffMultiplier;

    /**
     * @param int $maxRetries Maximum retry attempts (default: 3)
     * @param int $initialDelay Initial delay in milliseconds (default: 1000)
     * @param float $backoffMultiplier Delay multiplier for each retry (default: 2.0)
     */
    public function __construct($maxRetries = 3, $initialDelay = 1000, $backoffMultiplier = 2.0)
    {
        $this->maxRetries = $maxRetries;
        $this->initialDelay = $initialDelay;
        $this->backoffMultiplier = $backoffMultiplier;
    }

    /**
     * Execute a callable with retry logic
     *
     * @param callable $operation The operation to execute
     * @param callable|null $shouldRetry Optional: Custom retry condition (receives exception, returns bool)
     * @return mixed Result of the operation
     * @throws \Exception If all retries fail
     */
    public function execute(callable $operation, callable $shouldRetry = null)
    {
        $attempt = 0;
        $delay = $this->initialDelay;
        $lastException = null;

        // Temporarily extend PHP execution time to accommodate retries
        // Save original value to restore later
        $originalTimeout = ini_get('max_execution_time');
        $requiredTimeout = 120; // 2 minutes should be enough for retries

        if ($originalTimeout > 0 && $originalTimeout < $requiredTimeout) {
            set_time_limit($requiredTimeout);
        }

        while ($attempt <= $this->maxRetries) {
            try {
                $result = $operation();

                // Success! Restore original timeout and return
                if ($originalTimeout > 0) {
                    set_time_limit((int)$originalTimeout);
                }

                return $result;

            } catch (\Exception $e) {
                $lastException = $e;
                $attempt++;

                // Check if we should retry this exception
                $doRetry = $shouldRetry ? $shouldRetry($e) : $this->isRetryableException($e);

                // If not retryable or max retries reached, throw immediately
                if (!$doRetry || $attempt > $this->maxRetries) {
                    // Restore original timeout before throwing
                    if ($originalTimeout > 0) {
                        set_time_limit((int)$originalTimeout);
                    }
                    throw $e;
                }

                // Log retry attempt (if logger available)
                error_log(sprintf(
                    "[KeycloakAuth] Attempt %d/%d failed: %s. Retrying in %dms...",
                    $attempt,
                    $this->maxRetries + 1,
                    $e->getMessage(),
                    $delay
                ));

                // Wait before retrying (convert milliseconds to microseconds)
                usleep($delay * 1000);

                // Increase delay for next attempt (exponential backoff)
                $delay = (int)($delay * $this->backoffMultiplier);
            }
        }

        // Restore original timeout before final throw
        if ($originalTimeout > 0) {
            set_time_limit((int)$originalTimeout);
        }

        // All retries exhausted
        throw new \RuntimeException(
            "Operation failed after {$this->maxRetries} retries: " . $lastException->getMessage(),
            0,
            $lastException
        );
    }

    /**
     * Determine if an exception is retryable
     *
     * Retryable conditions:
     * - Network timeouts
     * - Connection refused/reset
     * - Temporary server errors (5xx)
     *
     * Not retryable:
     * - Authentication failures (401, 403)
     * - Bad requests (400)
     * - Not found (404)
     *
     * @param \Exception $e
     * @return bool
     */
    private function isRetryableException(\Exception $e)
    {
        $message = strtolower($e->getMessage());

        // Network/connection issues (retryable)
        $retryablePatterns = [
            'timeout',
            'timed out',
            'connection refused',
            'connection reset',
            'couldn\'t connect',
            'failed to connect',
            'network unreachable',
            'curl error: (6)',  // Could not resolve host
            'curl error: (7)',  // Failed to connect
            'curl error: (28)', // Operation timeout
            'curl error: (35)', // SSL connect error
            'curl error: (52)', // Empty reply from server
            'curl error: (56)', // Recv failure
            'http 500',
            'http 502',
            'http 503',
            'http 504',
        ];

        foreach ($retryablePatterns as $pattern) {
            if (strpos($message, $pattern) !== false) {
                return true;
            }
        }

        // Client errors (not retryable)
        $nonRetryablePatterns = [
            'http 400',
            'http 401',
            'http 403',
            'http 404',
            'state mismatch',
            'invalid_grant',
        ];

        foreach ($nonRetryablePatterns as $pattern) {
            if (strpos($message, $pattern) !== false) {
                return false;
            }
        }

        // Default: retry on RuntimeException
        return $e instanceof \RuntimeException;
    }

    /**
     * Execute a cURL request with retry logic
     *
     * Helper method for direct cURL operations
     *
     * @param resource $ch cURL handle
     * @param string $operationName Descriptive name for logging
     * @return string Response body
     * @throws \RuntimeException On failure after retries
     */
    public function executeCurl($ch, $operationName = 'cURL request')
    {
        return $this->execute(function() use ($ch, $operationName) {
            $result = curl_exec($ch);
            $error = curl_error($ch);
            $errno = curl_errno($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

            if ($errno !== 0) {
                throw new \RuntimeException("$operationName failed - curl error ($errno): $error");
            }

            if ($httpCode >= 500) {
                throw new \RuntimeException("$operationName failed - HTTP $httpCode: $result");
            }

            if ($httpCode >= 400) {
                // Client errors (4xx) - don't retry
                throw new \RuntimeException("$operationName failed - HTTP $httpCode: $result");
            }

            return $result;
        });
    }
}
