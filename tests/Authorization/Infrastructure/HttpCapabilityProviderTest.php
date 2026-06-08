<?php

declare(strict_types=1);

namespace Tests\Authorization\Infrastructure;

use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Infrastructure\HttpCapabilityProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpClient\Exception\TimeoutException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class HttpCapabilityProviderTest extends TestCase
{
    private const string PLATFORM_URL = 'https://platform.iseazy.test';
    private const string USER_ID = 'user-123';
    private const string PLATFORM_ID = 'platform-456';
    private const string SERVICE_API_KEY = 'test-service-api-key-12345';

    private LoggerInterface $logger;

    protected function setUp(): void
    {
        $this->logger = $this->createStub(LoggerInterface::class);
    }

    #[Test]
    public function testReturnsCapabilitiesOn200Ok(): void
    {
        // ARRANGE
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

        $httpClient = new MockHttpClient(new MockResponse($responseBody, ['http_code' => 200]));

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
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
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->logger
            ->expects($this->once())
            ->method('warning')
            ->with(
                'http_capability_provider_auth_error',
                $this->callback(function (array $context) {
                    return $context['status_code'] === 401
                        && $context['user_id'] === self::USER_ID
                        && $context['platform_id'] === self::PLATFORM_ID;
                })
            );

        $httpClient = new MockHttpClient(new MockResponse('', ['http_code' => 401]));

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
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
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->logger
            ->expects($this->once())
            ->method('warning')
            ->with('http_capability_provider_auth_error', $this->anything());

        $httpClient = new MockHttpClient(new MockResponse('', ['http_code' => 403]));

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
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
        $this->logger = $this->createMock(LoggerInterface::class);
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

        $httpClient = $this->createMock(HttpClientInterface::class);
        $httpClient
            ->expects($this->exactly(2))
            ->method('request')
            ->willThrowException(new TimeoutException('Timeout'));

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
            httpClient: $httpClient,
            logger: $this->logger,
            retryBackoffMs: 0,
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
        $this->logger = $this->createMock(LoggerInterface::class);
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

        $httpClient = new MockHttpClient([
            new MockResponse('', ['http_code' => 500]),
            new MockResponse('', ['http_code' => 500]),
        ]);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
            httpClient: $httpClient,
            logger: $this->logger,
            retryBackoffMs: 0,
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
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('http_capability_provider_server_error', $this->anything());

        $responseBody = json_encode(['capabilities' => []]);

        $httpClient = new MockHttpClient([
            new MockResponse('', ['http_code' => 500]),
            new MockResponse($responseBody, ['http_code' => 200]),
        ]);

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
            httpClient: $httpClient,
            logger: $this->logger,
            retryBackoffMs: 0,
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
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('http_capability_provider_json_error', $this->anything());

        $httpClient = new MockHttpClient(new MockResponse('{ invalid json', ['http_code' => 200]));

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
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
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('http_capability_provider_malformed_response', $this->anything());

        $httpClient = new MockHttpClient(new MockResponse(json_encode(['data' => 'wrong structure']), ['http_code' => 200]));

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
            httpClient: $httpClient,
            logger: $this->logger,
        );

        // ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testSendsApiKeyInHeader(): void
    {
        // ARRANGE
        $requestCallback = function (string $method, string $url, array $options) {
            $this->assertArrayHasKey('normalized_headers', $options);
            $this->assertArrayHasKey('x-service-api-key', $options['normalized_headers']);
            $this->assertStringContainsString(self::SERVICE_API_KEY, $options['normalized_headers']['x-service-api-key'][0]);
            $this->assertArrayHasKey('accept', $options['normalized_headers']);

            return new MockResponse(json_encode(['capabilities' => []]), ['http_code' => 200]);
        };

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
            httpClient: new MockHttpClient($requestCallback),
            logger: $this->logger,
        );

        // ACT & ASSERT - verified by callback
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testSendsUserIdInPathAndPlatformIdInQueryString(): void
    {
        // ARRANGE
        $requestCallback = function (string $method, string $url, array $options) {
            $expectedUrl = self::PLATFORM_URL . '/internal/api/v1/users/' . urlencode(self::USER_ID) . '/capabilities?platformUid=' . urlencode(self::PLATFORM_ID);
            $this->assertEquals($expectedUrl, $url);
            $this->assertEquals('GET', $method);

            return new MockResponse(json_encode(['capabilities' => []]), ['http_code' => 200]);
        };

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL,
            serviceApiKey: self::SERVICE_API_KEY,
            httpClient: new MockHttpClient($requestCallback),
            logger: $this->logger,
        );

        // ACT & ASSERT - verified by callback
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testHandlesTrailingSlashInPlatformUrl(): void
    {
        // ARRANGE
        $requestCallback = function (string $method, string $url, array $options) {
            $this->assertStringNotContainsString('//', substr($url, 8)); // Skip https://
            $this->assertStringContainsString('/internal/api/v1/users/', $url);

            return new MockResponse(json_encode(['capabilities' => []]), ['http_code' => 200]);
        };

        $provider = new HttpCapabilityProvider(
            platformUrl: self::PLATFORM_URL . '/',
            serviceApiKey: self::SERVICE_API_KEY,
            httpClient: new MockHttpClient($requestCallback),
            logger: $this->logger,
        );

        // ACT & ASSERT - verified by callback
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }
}
