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
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class CachedCapabilityProviderTest extends TestCase
{
    private const string USER_ID = 'user-123';
    private const string PLATFORM_ID = 'platform-456';

    private CapabilityProvider $innerProvider;
    private ArrayAdapter $cache;

    protected function setUp(): void
    {
        $this->innerProvider = $this->createStub(CapabilityProvider::class);
        $this->cache = new ArrayAdapter();
    }

    #[Test]
    public function testCacheMissCallsInnerAndCaches(): void
    {
        // ARRANGE
        $this->innerProvider = $this->createMock(CapabilityProvider::class);
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

        $cacheKey = 'capabilities__user__' . self::PLATFORM_ID . '__' . self::USER_ID;
        $item = $this->cache->getItem($cacheKey);
        $this->assertTrue($item->isHit());
    }

    #[Test]
    public function testCacheHitDoesNotCallInner(): void
    {
        // ARRANGE
        $this->innerProvider = $this->createMock(CapabilityProvider::class);
        $capabilities = new Capabilities([
            new Capability('edit_user', Scope::GLOBAL, ['*']),
        ]);

        $this->innerProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willReturn($capabilities);

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

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

        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ACT - second call from cache
        $cachedCapabilities = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $this->assertCount(2, $cachedCapabilities);
        $this->assertTrue($cachedCapabilities->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($cachedCapabilities->has('view_user', Scope::BUSINESS, 'biz-b'));
        $this->assertTrue($cachedCapabilities->has('edit_user', Scope::PLATFORM, 'platform-x'));
    }

    #[Test]
    public function testExceptionFromInnerNotCached(): void
    {
        // ARRANGE
        $this->innerProvider = $this->createMock(CapabilityProvider::class);
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
            ttlSeconds: 2,
        );

        // ACT
        $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $cacheKey = 'capabilities__user__' . self::PLATFORM_ID . '__' . self::USER_ID;
        $item = $this->cache->getItem($cacheKey);
        $this->assertTrue($item->isHit());
    }

    #[Test]
    public function testKeyIsPsr6Safe(): void
    {
        // ARRANGE
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

        // ACT
        $result = $provider->capabilities($userIdWithProhibited, $platformIdWithProhibited);

        // ASSERT
        $this->assertInstanceOf(Capabilities::class, $result);

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

        $this->innerProvider
            ->method('capabilities')
            ->willReturn(Capabilities::empty());

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // ACT & ASSERT - should not throw exception
        $provider->capabilities($userIdWithChar, $platformIdWithChar);
        $this->assertTrue(true);
    }

    /**
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
        $this->innerProvider = $this->createMock(CapabilityProvider::class);
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
        $this->innerProvider = $this->createMock(CapabilityProvider::class);
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
        $this->innerProvider
            ->method('capabilities')
            ->willReturn(Capabilities::empty());

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
        $this->innerProvider = $this->createMock(CapabilityProvider::class);
        $this->innerProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willReturn(Capabilities::empty());

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $this->cache,
        );

        // ACT
        $result1 = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);
        $result2 = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $this->assertTrue($result1->isEmpty());
        $this->assertTrue($result2->isEmpty());
    }

    #[Test]
    public function testInvalidCacheDataFallsBackToInnerProvider(): void
    {
        // ARRANGE — cache returns a HIT but with non-array data (corrupted entry)
        $this->innerProvider = $this->createMock(CapabilityProvider::class);
        $capabilities = new Capabilities([new Capability('view_user', Scope::BUSINESS, ['biz-a'])]);

        $this->innerProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willReturn($capabilities);

        $invalidItem = $this->createStub(CacheItemInterface::class);
        $invalidItem->method('isHit')->willReturn(true);
        $invalidItem->method('get')->willReturn('this-is-not-an-array');

        $writeItem = $this->createStub(CacheItemInterface::class);
        $writeItem->method('isHit')->willReturn(false);

        $cachePool = $this->createMock(CacheItemPoolInterface::class);
        $cachePool->expects($this->exactly(2))
            ->method('getItem')
            ->willReturnOnConsecutiveCalls($invalidItem, $writeItem);
        $cachePool->expects($this->once())
            ->method('deleteItem');

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $cachePool,
        );

        // ACT
        $result = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT
        $this->assertInstanceOf(Capabilities::class, $result);
        $this->assertTrue($result->has('view_user', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function testCacheReadErrorFallsBackToInnerProvider(): void
    {
        // ARRANGE — cache pool throws on getItem (e.g. Redis connection failure)
        $this->innerProvider = $this->createMock(CapabilityProvider::class);
        $capabilities = new Capabilities([new Capability('edit_user', Scope::GLOBAL, ['*'])]);

        $this->innerProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willReturn($capabilities);

        $cachePool = $this->createMock(CacheItemPoolInterface::class);
        $cachePool->method('getItem')
            ->willThrowException(new \RuntimeException('Cache connection failed'));

        $provider = new CachedCapabilityProvider(
            inner: $this->innerProvider,
            cache: $cachePool,
        );

        // ACT
        $result = $provider->capabilities(self::USER_ID, self::PLATFORM_ID);

        // ASSERT — inner provider result returned despite cache failure
        $this->assertInstanceOf(Capabilities::class, $result);
        $this->assertTrue($result->has('edit_user', Scope::GLOBAL, '*'));
    }
}
