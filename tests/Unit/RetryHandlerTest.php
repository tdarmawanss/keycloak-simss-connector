<?php

namespace Simss\KeycloakAuth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Simss\KeycloakAuth\Helpers\RetryHandler;

/**
 * Unit tests for RetryHandler class
 *
 * Tests the retry logic with exponential backoff for handling transient failures
 * in network operations (Keycloak API calls, token exchange, etc.)
 */
class RetryHandlerTest extends TestCase
{
    /**
     * Test successful operation on first attempt (no retry needed)
     *
     * Verifies that:
     * - Operation executes successfully on first try
     * - Returns the expected result
     * - No retries are performed
     */
    public function testExecuteSucceedsOnFirstAttempt()
    {
        $retryHandler = new RetryHandler(3, 100, 2.0);

        $attemptCount = 0;
        $operation = function() use (&$attemptCount) {
            $attemptCount++;
            return 'success';
        };

        $result = $retryHandler->execute($operation);

        $this->assertEquals('success', $result);
        $this->assertEquals(1, $attemptCount, 'Should only attempt once on success');
    }

    /**
     * Test retry logic with eventual success
     *
     * Verifies that:
     * - Retries are performed when operation fails
     * - Eventually succeeds after configured failures
     * - Returns the expected result
     */
    public function testExecuteRetriesAndEventuallySucceeds()
    {
        $retryHandler = new RetryHandler(3, 10, 1.5); // Short delays for testing

        $attemptCount = 0;
        $operation = function() use (&$attemptCount) {
            $attemptCount++;
            // Fail on first 2 attempts, succeed on 3rd
            if ($attemptCount < 3) {
                throw new \RuntimeException('Temporary failure');
            }
            return 'success';
        };

        $result = $retryHandler->execute($operation);

        $this->assertEquals('success', $result);
        $this->assertEquals(3, $attemptCount, 'Should retry until success');
    }

    /**
     * Test max retries exhausted - should throw exception
     *
     * Verifies that:
     * - Retries up to maxRetries times
     * - Throws exception when all retries exhausted
     * - Exception message includes retry count
     */
    public function testExecuteThrowsAfterMaxRetries()
    {
        $retryHandler = new RetryHandler(2, 10, 1.5);

        $attemptCount = 0;
        $operation = function() use (&$attemptCount) {
            $attemptCount++;
            throw new \RuntimeException('Persistent failure');
        };

        try {
            $retryHandler->execute($operation);
            $this->fail('Expected RuntimeException to be thrown');
        } catch (\RuntimeException $e) {
            // When max retries exhausted, original exception is thrown
            $this->assertEquals('Persistent failure', $e->getMessage());

            // Initial attempt + 2 retries = 3 total attempts
            $this->assertEquals(3, $attemptCount, 'Should attempt 1 initial + 2 retries');
        }
    }

    /**
     * Test that non-retryable exceptions throw immediately
     *
     * Verifies that:
     * - Client errors (4xx) are not retried
     * - Invalid grant errors are not retried
     * - State mismatch errors are not retried
     */
    public function testNonRetryableExceptionsThrowImmediately()
    {
        $retryHandler = new RetryHandler(3, 10, 1.5);

        $testCases = [
            'HTTP 400' => 'Bad request - HTTP 400',
            'HTTP 401' => 'Unauthorized - HTTP 401',
            'HTTP 403' => 'Forbidden - HTTP 403',
            'HTTP 404' => 'Not found - HTTP 404',
            'invalid_grant' => 'Token exchange failed: invalid_grant',
            'State mismatch' => 'State mismatch - possible CSRF attack',
        ];

        foreach ($testCases as $pattern => $message) {
            $attemptCount = 0;
            $operation = function() use (&$attemptCount, $message) {
                $attemptCount++;
                throw new \RuntimeException($message);
            };

            try {
                $retryHandler->execute($operation);
                $this->fail("Expected exception for: $pattern");
            } catch (\RuntimeException $e) {
                $this->assertEquals(1, $attemptCount, "Should not retry for: $pattern");
                // Case-insensitive pattern matching
                $this->assertStringContainsString(strtolower($pattern), strtolower($e->getMessage()));
            }
        }
    }

    /**
     * Test that retryable exceptions are retried
     *
     * Verifies that:
     * - Network timeouts are retried
     * - Connection errors are retried
     * - Server errors (5xx) are retried
     * - cURL errors are retried
     */
    public function testRetryableExceptionsAreRetried()
    {
        $retryHandler = new RetryHandler(2, 10, 1.5);

        $testCases = [
            'timeout' => 'Operation timeout',
            'connection refused' => 'Connection refused',
            'HTTP 500' => 'Internal server error - HTTP 500',
            'HTTP 502' => 'Bad gateway - HTTP 502',
            'HTTP 503' => 'Service unavailable - HTTP 503',
            'curl error: (28)' => 'curl error: (28) Operation timed out',
        ];

        foreach ($testCases as $pattern => $message) {
            $attemptCount = 0;
            $operation = function() use (&$attemptCount, $message) {
                $attemptCount++;
                throw new \RuntimeException($message);
            };

            try {
                $retryHandler->execute($operation);
                $this->fail("Expected exception for: $pattern");
            } catch (\RuntimeException $e) {
                // Should retry 2 times, so 3 total attempts
                $this->assertEquals(3, $attemptCount, "Should retry for: $pattern");
            }
        }
    }

    /**
     * Test custom retry condition callback
     *
     * Verifies that:
     * - Custom shouldRetry callback is invoked
     * - Can control retry behavior based on custom logic
     */
    public function testCustomRetryCondition()
    {
        $retryHandler = new RetryHandler(3, 10, 1.5);

        $attemptCount = 0;
        $operation = function() use (&$attemptCount) {
            $attemptCount++;
            throw new \RuntimeException('Custom error');
        };

        // Custom condition: never retry
        $shouldRetry = function(\Exception $e) {
            return false;
        };

        try {
            $retryHandler->execute($operation, $shouldRetry);
            $this->fail('Expected exception');
        } catch (\RuntimeException $e) {
            $this->assertEquals(1, $attemptCount, 'Should not retry with custom condition');
        }
    }

    /**
     * Test exponential backoff delay calculation
     *
     * Verifies that:
     * - Delay increases exponentially between retries
     * - Backoff multiplier is applied correctly
     *
     * Note: We test timing indirectly by checking attempt counts over time
     */
    public function testExponentialBackoff()
    {
        $retryHandler = new RetryHandler(3, 50, 2.0); // 50ms initial, 2x backoff

        $attemptCount = 0;
        $attemptTimes = [];

        $operation = function() use (&$attemptCount, &$attemptTimes) {
            $attemptTimes[] = microtime(true);
            $attemptCount++;
            throw new \RuntimeException('Timeout');
        };

        $startTime = microtime(true);

        try {
            $retryHandler->execute($operation);
        } catch (\RuntimeException $e) {
            // Verify attempts happened
            $this->assertEquals(4, $attemptCount, 'Should have 1 initial + 3 retries');

            // Verify timing (rough check - at least some delay occurred)
            $totalTime = microtime(true) - $startTime;

            // Expected delays: 50ms, 100ms, 200ms = 350ms minimum
            // Add tolerance for test execution overhead
            $this->assertGreaterThan(0.3, $totalTime, 'Should have exponential backoff delays');
        }
    }

    /**
     * Test that original exception is thrown after max retries
     *
     * Verifies that:
     * - When max retries exhausted, original exception is thrown
     * - Exception is not wrapped, preserving stack trace
     */
    public function testOriginalExceptionIsPreserved()
    {
        $retryHandler = new RetryHandler(2, 10, 1.5);

        $operation = function() {
            throw new \RuntimeException('Original error message');
        };

        try {
            $retryHandler->execute($operation);
            $this->fail('Expected exception');
        } catch (\RuntimeException $e) {
            // Verify the original exception is thrown directly (not wrapped)
            $this->assertEquals('Original error message', $e->getMessage());

            // Original exception has no previous exception
            $this->assertNull($e->getPrevious(), 'Original exception should not be wrapped');
        }
    }

    /**
     * Test with zero retries (fail fast mode)
     *
     * Verifies that:
     * - Setting maxRetries to 0 means fail on first error
     * - No retry attempts are made
     */
    public function testZeroRetriesFailsFast()
    {
        $retryHandler = new RetryHandler(0, 10, 1.5);

        $attemptCount = 0;
        $operation = function() use (&$attemptCount) {
            $attemptCount++;
            throw new \RuntimeException('Error');
        };

        try {
            $retryHandler->execute($operation);
            $this->fail('Expected exception');
        } catch (\RuntimeException $e) {
            $this->assertEquals(1, $attemptCount, 'Should only attempt once with maxRetries=0');
        }
    }

    /**
     * Test retry with different exception types
     *
     * Verifies that:
     * - RuntimeException is retryable by default
     * - Other exception types use default behavior
     */
    public function testDifferentExceptionTypes()
    {
        $retryHandler = new RetryHandler(2, 10, 1.5);

        // RuntimeException should be retried
        $attemptCount = 0;
        $operation = function() use (&$attemptCount) {
            $attemptCount++;
            throw new \RuntimeException('Retryable error');
        };

        try {
            $retryHandler->execute($operation);
        } catch (\RuntimeException $e) {
            $this->assertEquals(3, $attemptCount, 'RuntimeException should be retried');
        }

        // Other exceptions should not be retried by default
        $attemptCount = 0;
        $operation2 = function() use (&$attemptCount) {
            $attemptCount++;
            throw new \InvalidArgumentException('Not retryable');
        };

        try {
            $retryHandler->execute($operation2);
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals(1, $attemptCount, 'InvalidArgumentException should not be retried');
        }
    }
}
