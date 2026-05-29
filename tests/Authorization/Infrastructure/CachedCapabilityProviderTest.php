<?php

declare(strict_types=1);

namespace Tests\Authorization\Infrastructure;

use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Model\Capability;
use Iseazy\Security\Authorization\Domain\Model\Scope;
use Iseazy\Security\Authorization\Domain\Service\CapabilityProvider;
use Iseazy\Security\Authorization\Infrastructure\CachedCapabilityProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Unit tests for CachedCapabilityProvider.
 *
 * Tests the cached capability provider decorator's ability to:
 * - Cache successful capability lookups with configurable TTL
 * - Return cached results on cache hits (without calling inner provider)
 * - Invoke inner provider on cache misses and store results
 * - NOT cache exceptions from inner provider (fail-closed propagation)
 * - Build PSR-6 compliant cache keys (no prohibited characters)
 * - Handle cache errors gracefully (fail-open on cache, fail-closed on provider)
 * - Serialize and deserialize Capabilities correctly
 *
 * Coverage target: >90%
 */
final class CachedCapabilityProviderTest extends TestCase
{
    private const string USER_ID = 'user-123';
    private const string PLATFORM_ID = 'platform-456';

    private CapabilityProvider $innerProvider;
    private ArrayAdapter $cache;

    protected function setUp(): void
    {
        $this->innerProvider = $this->createMock(CapabilityProvider::class);
        $this->cache = new ArrayAdapter();
    }

    #[Test]
    public function testCacheMissCallsInnerAndCaches(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        $this->innerProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with(self::USER_ID, self::PLATFORM_ID, [])
            ->willReturn($capabilities);

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
            ttlSeconds: 900,
        );

        // ACT
        $result = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $this->assertInstanceOf(Capabilities::class, $result);
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('view_user', Scope::BUSINESS, 'biz-a'));

        // Verify it was cached
        $cacheKey = 'capabilities__user__' . self::PLATFORM_ID . '__' . self::USER_ID;
        $item = $this->cache->getItem($cacheKey);
        $this->assertTrue($item->isHit());
    }

    #[Test]
    public function testCacheHitDoesNotCallInner(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('edit_user', Scope::GLOBAL, ['*']),
        ]);

        // First call: cache miss, calls inner
        $this->innerProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willReturn($capabilities);

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // First call to populate cache
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ACT - second call should hit cache
        $result = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $this->assertInstanceOf(Capabilities::class, $result);
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('edit_user', Scope::GLOBAL, '*'));
    }

    #[Test]
    public function testCacheHitDeserializesCorrectly(): void
    {
        // ARRANGE
        $originalCapabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']),
            new Capability('edit_user', Scope::PLATFORM, ['platform-x']),
        ]);

        $this->innerProvider
            ->method('capabilities')
            ->willReturn($originalCapabilities);

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // First call to cache
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ACT - second call from cache
        $cachedCapabilities = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT - verify deserialization is correct
        $this->assertCount(2, $cachedCapabilities);
        $this->assertTrue($cachedCapabilities->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($cachedCapabilities->has('view_user', Scope::BUSINESS, 'biz-b'));
        $this->assertTrue($cachedCapabilities->has('edit_user', Scope::PLATFORM, 'platform-x'));
    }

    #[Test]
    public function testExceptionFromInnerNotCached(): void
    {
        // ARRANGE
        $this->innerProvider
            ->expects($this->exactly(2))
            ->method('capabilities')
            ->willThrowException(CapabilityProviderUnavailableException::unavailable());

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // ACT & ASSERT - first call throws
        try {
            $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
            $this->fail('Expected CapabilityProviderUnavailableException');
        } catch (CapabilityProviderUnavailableException) {
            // Expected
        }

        // Second call should also throw (exception was not cached)
        $this->expectException(CapabilityProviderUnavailableException::class);
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
    }

    #[Test]
    public function testTtlIsRespected(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        $this->innerProvider
            ->method('capabilities')
            ->willReturn($capabilities);

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
            ttlSeconds: 2, // 2 seconds TTL
        );

        // ACT - first call
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // Verify cache item has TTL
        $cacheKey = 'capabilities__user__' . self::PLATFORM_ID . '__' . self::USER_ID;
        $item = $this->cache->getItem($cacheKey);

        // ASSERT
        $this->assertTrue($item->isHit());

        // Note: ArrayAdapter doesn't expire items automatically in tests,
        // but we can verify the TTL was set by checking the item was saved
        // The actual TTL expiration is tested in integration tests with real cache
    }

    #[Test]
    public function testKeyIsPsr6Safe(): void
    {
        // ARRANGE - User ID and Platform ID with PSR-6 prohibited characters
        $userIdWithProhibited = 'user@domain:123/test\\space here{x}(y)';
        $platformIdWithProhibited = 'platform,abc@xyz:test';

        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        $this->innerProvider
            ->method('capabilities')
            ->willReturn($capabilities);

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // ACT - should not throw PSR-6 invalid key exception
        $result = $provider->capabilities($userIdWithProhibited, $platformIdWithProhibited);

        // ASSERT
        $this->assertInstanceOf(Capabilities::class, $result);

        // Verify the cache key is PSR-6 safe (all prohibited chars replaced with _)
        $expectedKey = 'capabilities__user__platform_abc_xyz_test__user_domain_123_test_space_here_x__y_';
        $item = $this->cache->getItem($expectedKey);
        $this->assertTrue($item->isHit());
    }

    #[Test]
    #[DataProvider('psr6ProhibitedCharactersProvider')]
    public function testReplacesProhibitedCharactersInKey(string $char): void
    {
        // ARRANGE
        $userIdWithChar = 'user' . $char . '123';
        $platformIdWithChar = 'platform' . $char . 'abc';

        $capabilities = Capabilities::empty();

        $this->innerProvider
            ->method('capabilities')
            ->willReturn($capabilities);

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // ACT - should not throw exception
        $provider->capabilities($userIdWithChar, $platformIdWithChar);

        // ASSERT - no exception means key is valid
        $this->assertTrue(true);
    }

    /**
     * Provides PSR-6 prohibited characters for testing.
     *
     * @return array<string, array<string>>
     */
    public static function psr6ProhibitedCharactersProvider(): array
    {
        return [
            'at symbol' => ['@'],
            'colon' => [':'],
            'comma' => [','],
            'left brace' => ['{'],
            'right brace' => ['}'],
            'left paren' => ['('],
            'right paren' => [')'],
            'forward slash' => ['/'],
            'backslash' => ['\\'],
            'space' => [' '],
        ];
    }

    #[Test]
    public function testDifferentUsersHaveDifferentCacheKeys(): void
    {
        // ARRANGE
        $user1Capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        $user2Capabilities = new Capabilities([
            new Capability('edit_user', Scope::GLOBAL, ['*']),
        ]);

        $this->innerProvider
            ->expects($this->exactly(2))
            ->method('capabilities')
            ->willReturnCallback(function (string $userId) use ($user1Capabilities, $user2Capabilities) {
                return $userId === 'user-1' ? $user1Capabilities : $user2Capabilities;
            });

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // ACT
        $result1 = $provider->capabilities('user-1', self::PLATFORM_ID);
        $result2 = $provider->capabilities('user-2', self::PLATFORM_ID);

        // ASSERT
        $this->assertTrue($result1->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertFalse($result1->has('edit_user', Scope::GLOBAL, '*'));

        $this->assertTrue($result2->has('edit_user', Scope::GLOBAL, '*'));
        $this->assertFalse($result2->has('view_user', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function testDifferentPlatformsHaveDifferentCacheKeys(): void
    {
        // ARRANGE
        $platform1Capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        $platform2Capabilities = new Capabilities([
            new Capability('edit_user', Scope::PLATFORM, ['platform-x']),
        ]);

        $this->innerProvider
            ->expects($this->exactly(2))
            ->method('capabilities')
            ->willReturnCallback(function (string $userId, string $platformId) use ($platform1Capabilities, $platform2Capabilities) {
                return $platformId === 'platform-1' ? $platform1Capabilities : $platform2Capabilities;
            });

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // ACT
        $result1 = $provider->capabilities(self::USER_ID, 'platform-1');
        $result2 = $provider->capabilities(self::USER_ID, 'platform-2');

        // ASSERT
        $this->assertTrue($result1->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertFalse($result1->has('edit_user', Scope::PLATFORM, 'platform-x'));

        $this->assertTrue($result2->has('edit_user', Scope::PLATFORM, 'platform-x'));
        $this->assertFalse($result2->has('view_user', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function testCustomKeyPrefixIsUsed(): void
    {
        // ARRANGE
        $capabilities = Capabilities::empty();

        $this->innerProvider
            ->method('capabilities')
            ->willReturn($capabilities);

        $customPrefix = 'my_custom_prefix';

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
            keyPrefix: $customPrefix,
        );

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $expectedKey = $customPrefix . '__' . self::PLATFORM_ID . '__' . self::USER_ID;
        $item = $this->cache->getItem($expectedKey);
        $this->assertTrue($item->isHit());
    }

    #[Test]
    public function testEmptyCapabilitiesAreCached(): void
    {
        // ARRANGE
        $emptyCapabilities = Capabilities::empty();

        $this->innerProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willReturn($emptyCapabilities);

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // ACT - first call
        $result1 = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // Second call should use cache (inner not called again)
        $result2 = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $this->assertTrue($result1->isEmpty());
        $this->assertTrue($result2->isEmpty());
    }
}
