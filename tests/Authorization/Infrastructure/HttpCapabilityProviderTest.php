<?php

declare(strict_types=1);

namespace Tests\Authorization\Infrastructure;

use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Service\JwtProvider;
use Iseazy\Security\Authorization\Infrastructure\HttpCapabilityProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpClient\Exception\TimeoutException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Unit tests for HttpCapabilityProvider.
 *
 * Tests the HTTP capability provider's ability to:
 * - Successfully fetch and deserialize capabilities from Platform API
 * - Handle HTTP errors appropriately (401, 403, 4xx, 5xx)
 * - Implement retry logic for transient failures (timeout, 5xx)
 * - Validate and parse JSON responses
 * - Send correct headers (Authorization, Accept)
 * - Build correct URLs with query parameters
 * - Fail-closed on all error scenarios
 * - Log errors with appropriate severity (WARNING for 401/403, ERROR for others)
 * - Truncate JWT in logs to prevent token leakage
 *
 * Coverage target: >90%
 */
final class HttpCapabilityProviderTest extends TestCase
{
    private const string PLATFORM_URL = 'https://platform.iseazy.test';
    private const string USER_ID = 'user-123';
    private const string PLATFORM_ID = 'platform-456';
    private const string JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature';

    private JwtProvider $jwtProvider;
    private LoggerInterface $logger;

    protected function setUp(): void
    {
        $this->jwtProvider = $this->createMock(JwtProvider::class);
        $this->logger = $this->createMock(LoggerInterface::class);
    }

    #[Test]
    public function testReturnsCapabilitiesOn200Ok(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $responseBody = json_encode([
            'capabilities' => [
                [
                    'capability' => 'view_user',
                    'scope' => 'business',
                    'context' => ['biz-a', 'biz-b'],
                ],
                [
                    'capability' => 'edit_user',
                    'scope' => 'global',
                    'context' => ['*'],
                ],
            ],
        ]);

        $mockResponse = new MockResponse($responseBody, ['http_code' => 200]);
        $httpClient = new MockHttpClient($mockResponse);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ACT
        $capabilities = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $this->assertInstanceOf(Capabilities::class, $capabilities);
        $this->assertCount(2, $capabilities);
        $this->assertTrue($capabilities->has('view_user', \Iseazy\Security\Authorization\Domain\Model\Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($capabilities->has('edit_user', \Iseazy\Security\Authorization\Domain\Model\Scope::GLOBAL, '*'));
    }

    #[Test]
    public function testThrowsOn401(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $this->logger
            ->expects($this->once())
            ->method('warning')
            ->with(
                'http_capability_provider_auth_error',
                $this->callback(function (array $context) {
                    return $context['status_code'] === 401
                        && $context['user_id'] === self::USER_ID
                        && $context['platform_id'] === self::PLATFORM_ID
                        && str_starts_with($context['jwt_preview'], 'eyJhbGciOi');
                })
            );

        $mockResponse = new MockResponse('', ['http_code' => 401]);
        $httpClient = new MockHttpClient($mockResponse);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);
        $this->expectExceptionMessage('capability_provider_unavailable');

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testThrowsOn403(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $this->logger
            ->expects($this->once())
            ->method('warning')
            ->with('http_capability_provider_auth_error', $this->anything());

        $mockResponse = new MockResponse('', ['http_code' => 403]);
        $httpClient = new MockHttpClient($mockResponse);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testRetriesOnceOnTimeout(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $this->logger
            ->expects($this->exactly(2))
            ->method('error')
            ->with(
                'http_capability_provider_timeout',
                $this->callback(function (array $context) {
                    static $callCount = 0;
                    $callCount++;

                    return $context['attempt'] === $callCount
                        && $context['max_attempts'] === 2;
                })
            );

        // Create a mock that throws TimeoutException on both attempts
        $httpClient = $this->createMock(HttpClientInterface::class);
        $httpClient
            ->expects($this->exactly(2))
            ->method('request')
            ->willThrowException(new class ('Timeout') extends \RuntimeException implements TransportExceptionInterface {
                use TimeoutExceptionTrait;
            });

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testRetriesOnceOn500(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $this->logger
            ->expects($this->exactly(2))
            ->method('error')
            ->with(
                'http_capability_provider_server_error',
                $this->callback(function (array $context) {
                    static $callCount = 0;
                    $callCount++;

                    return $context['status_code'] === 500
                        && $context['attempt'] === $callCount
                        && $context['max_attempts'] === 2;
                })
            );

        // Both attempts return 500
        $mockResponse1 = new MockResponse('', ['http_code' => 500]);
        $mockResponse2 = new MockResponse('', ['http_code' => 500]);
        $httpClient = new MockHttpClient([$mockResponse1, $mockResponse2]);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testSucceedsOnSecondAttemptAfter500(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('http_capability_provider_server_error', $this->anything());

        $responseBody = json_encode(['capabilities' => []]);

        // First attempt: 500, second attempt: 200
        $mockResponse1 = new MockResponse('', ['http_code' => 500]);
        $mockResponse2 = new MockResponse($responseBody, ['http_code' => 200]);
        $httpClient = new MockHttpClient([$mockResponse1, $mockResponse2]);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ACT
        $capabilities = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $this->assertInstanceOf(Capabilities::class, $capabilities);
        $this->assertTrue($capabilities->isEmpty());
    }

    #[Test]
    public function testThrowsOnMalformedJson(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('http_capability_provider_json_error', $this->anything());

        $mockResponse = new MockResponse('{ invalid json', ['http_code' => 200]);
        $httpClient = new MockHttpClient($mockResponse);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testThrowsOnMissingCapabilitiesField(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('http_capability_provider_malformed_response', $this->anything());

        $mockResponse = new MockResponse(json_encode(['data' => 'wrong structure']), ['http_code' => 200]);
        $httpClient = new MockHttpClient($mockResponse);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testSendsJwtInAuthorizationHeader(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $requestCallback = function (string $method, string $url, array $options) {
            $this->assertArrayHasKey('headers', $options);
            $this->assertArrayHasKey('Authorization', $options['headers']);
            $this->assertEquals('Bearer ' . self::JWT_TOKEN, $options['headers']['Authorization']);
            $this->assertEquals('application/json', $options['headers']['Accept']);

            return new MockResponse(json_encode(['capabilities' => []]), ['http_code' => 200]);
        };

        $httpClient = new MockHttpClient($requestCallback);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT - verified by callback
    }

    #[Test]
    public function testSendsPlatformIdInQueryString(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $requestCallback = function (string $method, string $url, array $options) {
            $expectedUrl = self::PLATFORM_URL . '/api/v1/user/me/capabilities?platformUid=' . urlencode(self::PLATFORM_ID);
            $this->assertEquals($expectedUrl, $url);
            $this->assertEquals('GET', $method);

            return new MockResponse(json_encode(['capabilities' => []]), ['http_code' => 200]);
        };

        $httpClient = new MockHttpClient($requestCallback);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT - verified by callback
    }

    #[Test]
    public function testThrowsWhenNoJwtAvailable(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(null);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('http_capability_provider_no_jwt', $this->anything());

        $httpClient = $this->createMock(HttpClientInterface::class);
        $httpClient
            ->expects($this->never())
            ->method('request');

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testHandlesTrailingSlashInPlatformUrl(): void
    {
        // ARRANGE
        $this->jwtProvider
            ->method('currentJwt')
            ->willReturn(self::JWT_TOKEN);

        $requestCallback = function (string $method, string $url, array $options) {
            // URL should NOT have double slashes
            $this->assertStringNotContainsString('//', substr($url, 8)); // Skip https://
            $this->assertStringContainsString('/api/v1/user/me/capabilities', $url);

            return new MockResponse(json_encode(['capabilities' => []]), ['http_code' => 200]);
        };

        $httpClient = new MockHttpClient($requestCallback);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL . '/', // With trailing slash
            jwtProvider: $this->jwtProvider,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT - verified by callback
    }
}

/**
 * Trait to create a proper TimeoutException for testing.
 *
 * Symfony's TimeoutException requires implementing TransportExceptionInterface
 * and providing specific methods.
 */
trait TimeoutExceptionTrait
{
    public function getIdleTimeout(): float
    {
        return 3.0;
    }
}
