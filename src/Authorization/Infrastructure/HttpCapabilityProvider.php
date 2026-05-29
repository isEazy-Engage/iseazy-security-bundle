<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Infrastructure;

use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Service\CapabilityProvider;
use Iseazy\Security\Authorization\Domain\Service\JwtProvider;
use JsonException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpClient\Exception\TimeoutException;
use Symfony\Contracts\HttpClient\Exception\HttpExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * HTTP-based capability provider that fetches capabilities from Platform API.
 *
 * This implementation calls the Platform microservice's public endpoint
 * GET /api/v1/user/me/capabilities to retrieve user capabilities. It is designed
 * for use by Task and Supervisor microservices that don't have direct database access.
 *
 * Security Features:
 * - Fail-closed by default: any error throws CapabilityProviderUnavailableException
 * - JWT authentication with Authorization header
 * - Configurable timeout (default 3 seconds) to prevent blocking
 * - Single retry on timeout or 5xx errors with exponential backoff
 * - Secure logging (JWT is truncated to 10 chars to prevent token leakage)
 *
 * Configuration Example (services.yaml):
 * ```yaml
 * Iseazy\Security\Authorization\Infrastructure\HttpCapabilityProvider:
 *   arguments:
 *     $platformUrl: '%env(PLATFORM_URL)%'
 *     $jwtProvider: '@app.jwt_provider'
 *     $httpClient: '@http_client'
 *     $logger: '@logger'
 *     $timeoutSeconds: 3
 *     $failClosed: true
 * ```
 *
 * @see CapabilityProvider Port interface
 * @see JwtProvider For extracting JWT from current context
 */
final readonly class HttpCapabilityProvider implements CapabilityProvider
{
    private const int DEFAULT_TIMEOUT_SECONDS = 3;
    private const int RETRY_BACKOFF_MS = 500;
    private const int JWT_LOG_TRUNCATE_LENGTH = 10;

    /**
     * Creates a new HTTP capability provider.
     *
     * @param string $platformUrl Base URL of the Platform API (e.g., "https://platform.iseazy.com")
     * @param JwtProvider $jwtProvider Provider for extracting JWT from current context
     * @param HttpClientInterface $httpClient Symfony HTTP client for making requests
     * @param LoggerInterface $logger Logger for error tracking (defaults to NullLogger)
     * @param int $timeoutSeconds Request timeout in seconds (default: 3)
     * @param bool $failClosed Whether to fail closed on errors (default: true)
     */
    public function __construct(
        private string $platformUrl,
        private JwtProvider $jwtProvider,
        private HttpClientInterface $httpClient,
        private LoggerInterface $logger = new NullLogger(),
        private int $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
        private bool $failClosed = true,
    ) {
    }

    /**
     * Retrieves user capabilities from Platform API via HTTP.
     *
     * Makes a GET request to {platformUrl}/api/v1/user/me/capabilities?platformUid={platformId}
     * with JWT authentication. Implements retry logic for transient failures.
     *
     * Error Handling (Fail-Closed):
     * - 401/403: Throws exception (authentication/authorization failure)
     * - 4xx: Throws exception (client error)
     * - 5xx: Retries once, then throws exception (server error)
     * - Timeout: Retries once, then throws exception
     * - Invalid JSON: Throws exception (malformed response)
     *
     * @param string $userId The unique identifier of the user (from JWT)
     * @param string $platformId The unique identifier of the platform context
     * @param array<string> $roles Optional array of user roles (not used by HTTP provider)
     *
     * @return Capabilities The collection of capabilities from Platform API
     *
     * @throws CapabilityProviderUnavailableException On any error (fail-closed)
     */
    public function capabilities(string $userId, string $platformId, array $roles = []): Capabilities
    {
        $jwt = $this->jwtProvider->currentJwt();

        if ($jwt === null) {
            $this->logger->error('http_capability_provider_no_jwt', [
                'user_id' => $userId,
                'platform_id' => $platformId,
            ]);

            throw CapabilityProviderUnavailableException::unavailable();
        }

        $url = sprintf(
            '%s/api/v1/user/me/capabilities?platformUid=%s',
            rtrim($this->platformUrl, '/'),
            urlencode($platformId)
        );

        $attempt = 0;
        $maxAttempts = 2; // Original + 1 retry

        while ($attempt < $maxAttempts) {
            $attempt++;

            try {
                $response = $this->httpClient->request('GET', $url, [
                    'headers' => [
                        'Authorization' => sprintf('Bearer %s', $jwt),
                        'Accept' => 'application/json',
                    ],
                    'timeout' => $this->timeoutSeconds,
                ]);

                $statusCode = $response->getStatusCode();

                // Success: 200 OK
                if ($statusCode === 200) {
                    return $this->parseResponse($response->getContent());
                }

                // Client errors: 4xx (don't retry)
                if ($statusCode >= 400 && $statusCode < 500) {
                    $this->logClientError($statusCode, $userId, $platformId, $jwt);

                    throw CapabilityProviderUnavailableException::unavailable();
                }

                // Server errors: 5xx (retry once)
                if ($statusCode >= 500) {
                    $this->logger->error('http_capability_provider_server_error', [
                        'user_id' => $userId,
                        'platform_id' => $platformId,
                        'status_code' => $statusCode,
                        'attempt' => $attempt,
                        'max_attempts' => $maxAttempts,
                    ]);

                    if ($attempt < $maxAttempts) {
                        usleep(self::RETRY_BACKOFF_MS * 1000);
                        continue;
                    }

                    throw CapabilityProviderUnavailableException::unavailable();
                }
            } catch (TimeoutException $e) {
                $this->logger->error('http_capability_provider_timeout', [
                    'user_id' => $userId,
                    'platform_id' => $platformId,
                    'timeout_seconds' => $this->timeoutSeconds,
                    'attempt' => $attempt,
                    'max_attempts' => $maxAttempts,
                ]);

                if ($attempt < $maxAttempts) {
                    usleep(self::RETRY_BACKOFF_MS * 1000);
                    continue;
                }

                throw CapabilityProviderUnavailableException::unavailable(previous: $e);
            } catch (TransportExceptionInterface | HttpExceptionInterface $e) {
                $this->logger->error('http_capability_provider_transport_error', [
                    'user_id' => $userId,
                    'platform_id' => $platformId,
                    'error' => $e->getMessage(),
                ]);

                throw CapabilityProviderUnavailableException::unavailable(previous: $e);
            }
        }

        // Should never reach here, but fail-closed just in case
        throw CapabilityProviderUnavailableException::unavailable();
    }

    /**
     * Parses the JSON response and deserializes to Capabilities.
     *
     * @param string $content Raw JSON response content
     *
     * @return Capabilities Deserialized capabilities
     *
     * @throws CapabilityProviderUnavailableException If JSON is invalid or malformed
     */
    private function parseResponse(string $content): Capabilities
    {
        try {
            $data = json_decode($content, true, 512, JSON_THROW_ON_ERROR);

            if (!is_array($data) || !isset($data['capabilities']) || !is_array($data['capabilities'])) {
                $this->logger->error('http_capability_provider_malformed_response', [
                    'content_preview' => substr($content, 0, 200),
                ]);

                throw CapabilityProviderUnavailableException::unavailable();
            }

            return Capabilities::fromArray($data['capabilities']);
        } catch (JsonException $e) {
            $this->logger->error('http_capability_provider_json_error', [
                'error' => $e->getMessage(),
            ]);

            throw CapabilityProviderUnavailableException::unavailable(previous: $e);
        } catch (Throwable $e) {
            $this->logger->error('http_capability_provider_deserialization_error', [
                'error' => $e->getMessage(),
            ]);

            throw CapabilityProviderUnavailableException::unavailable(previous: $e);
        }
    }

    /**
     * Logs client errors (4xx) with appropriate severity.
     *
     * @param int $statusCode The HTTP status code
     * @param string $userId The user ID
     * @param string $platformId The platform ID
     * @param string $jwt The JWT token (will be truncated for logging)
     */
    private function logClientError(int $statusCode, string $userId, string $platformId, string $jwt): void
    {
        $jwtPreview = substr($jwt, 0, self::JWT_LOG_TRUNCATE_LENGTH) . '...';

        if ($statusCode === 401 || $statusCode === 403) {
            $this->logger->warning('http_capability_provider_auth_error', [
                'user_id' => $userId,
                'platform_id' => $platformId,
                'status_code' => $statusCode,
                'jwt_preview' => $jwtPreview,
            ]);
        } else {
            $this->logger->error('http_capability_provider_client_error', [
                'user_id' => $userId,
                'platform_id' => $platformId,
                'status_code' => $statusCode,
            ]);
        }
    }
}
