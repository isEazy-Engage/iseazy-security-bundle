<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Infrastructure;

use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Service\CapabilityProvider;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;
use Throwable;

/**
 * Decorator that adds PSR-6 caching to any CapabilityProvider implementation.
 *
 * This decorator wraps another CapabilityProvider and caches successful results
 * to reduce load on the underlying provider (database, HTTP API, etc.).
 *
 * Cache Strategy:
 * - Cache keys are PSR-6 safe: no prohibited characters (@, :, {, }, (, ), /, \, space)
 * - Successful results are cached with configurable TTL (default: 900 seconds = 15 minutes)
 * - Exceptions are NOT cached (fail-closed propagation)
 * - Cache misses invoke the inner provider and store the result
 * - Cache hits return deserialized Capabilities directly
 *
 * Fail-Closed Behavior:
 * - If inner provider throws CapabilityProviderUnavailableException, it is propagated (not cached)
 * - If cache operations fail, the provider falls back to the inner provider
 * - Cache errors are logged but don't prevent capability resolution
 *
 * PSR-6 Cache Key Format:
 * - Pattern: {keyPrefix}__{platformId}__{userId}
 * - Prohibited characters are replaced with underscores
 * - Example: "capabilities__user__abc123-def456__user-789xyz"
 *
 * Configuration Example (services.yaml):
 * ```yaml
 * Iseazy\Security\Authorization\Infrastructure\CachedCapabilityProvider:
 *   decorates: Iseazy\Security\Authorization\Infrastructure\HttpCapabilityProvider
 *   arguments:
 *     $inner: '@.inner'
 *     $cache: '@cache.app'
 *     $ttlSeconds: 900  # 15 minutes
 *     $keyPrefix: 'capabilities__user'
 * ```
 *
 * @see CapabilityProvider Port interface
 * @see R-006 in TECHNICAL_ANALYSIS.md for PSR-6 key requirements
 */
final readonly class CachedCapabilityProvider implements CapabilityProvider
{
    private const int DEFAULT_TTL_SECONDS = 900; // 15 minutes
    private const string DEFAULT_KEY_PREFIX = 'capabilities__user';

    /**
     * PSR-6 prohibited characters that must be replaced in cache keys.
     *
     * @see https://www.php-fig.org/psr/psr-6/#definitions
     */
    private const array PSR6_PROHIBITED_CHARS = ['@', ':', ',', '{', '}', '(', ')', '/', '\\', ' '];

    /**
     * Creates a new cached capability provider decorator.
     *
     * @param CapabilityProvider $inner The underlying capability provider to decorate
     * @param CacheItemPoolInterface $cache PSR-6 cache pool for storing capabilities
     * @param int $ttlSeconds Cache time-to-live in seconds (default: 900 = 15 minutes)
     * @param string $keyPrefix Prefix for cache keys (default: 'capabilities__user')
     */
    public function __construct(
        private CapabilityProvider $inner,
        private CacheItemPoolInterface $cache,
        private int $ttlSeconds = self::DEFAULT_TTL_SECONDS,
        private string $keyPrefix = self::DEFAULT_KEY_PREFIX,
    ) {
    }

    /**
     * Retrieves user capabilities with caching.
     *
     * Cache Logic:
     * 1. Build PSR-6 safe cache key
     * 2. Check cache for hit
     * 3. On HIT: Deserialize and return Capabilities (inner provider not called)
     * 4. On MISS: Invoke inner provider
     *    - On success: Serialize, cache with TTL, return Capabilities
     *    - On exception: Propagate exception (do NOT cache errors)
     *
     * @param string $userId The unique identifier of the user
     * @param string $platformId The unique identifier of the platform context
     * @param array<string> $roles Optional array of user roles
     *
     * @return Capabilities The collection of capabilities (from cache or inner provider)
     *
     * @throws CapabilityProviderUnavailableException If inner provider fails (fail-closed)
     */
    public function capabilities(string $userId, string $platformId, array $roles = []): Capabilities
    {
        $cacheKey = $this->buildCacheKey($userId, $platformId);

        try {
            $item = $this->cache->getItem($cacheKey);

            // Cache HIT: deserialize and return
            if ($item->isHit()) {
                $cachedData = $item->get();

                if (is_array($cachedData)) {
                    return Capabilities::fromArray($cachedData);
                }

                // Invalid cache data: delete and fall through to MISS
                $this->cache->deleteItem($cacheKey);
            }
        } catch (InvalidArgumentException | Throwable) {
            // Cache read failed: fall through to invoke inner provider
            // (fail-open on cache errors, but inner provider will fail-closed)
        }

        // Cache MISS or cache error: invoke inner provider
        try {
            $capabilities = $this->inner->capabilities($userId, $platformId, $roles);

            // Cache the successful result
            $this->cacheCapabilities($cacheKey, $capabilities);

            return $capabilities;
        } catch (CapabilityProviderUnavailableException $e) {
            // DO NOT cache exceptions (fail-closed propagation)
            throw $e;
        }
    }

    /**
     * Stores capabilities in cache with configured TTL.
     *
     * If caching fails, the error is suppressed (fail-open on cache writes).
     *
     * @param string $cacheKey The PSR-6 safe cache key
     * @param Capabilities $capabilities The capabilities to cache
     */
    private function cacheCapabilities(string $cacheKey, Capabilities $capabilities): void
    {
        try {
            $item = $this->cache->getItem($cacheKey);
            $item->set($capabilities->toArray());
            $item->expiresAfter($this->ttlSeconds);

            $this->cache->save($item);
        } catch (InvalidArgumentException | Throwable) {
            // Cache write failed: suppress error (fail-open on cache writes)
            // The capability resolution succeeded, so we don't want to throw here
        }
    }

    /**
     * Builds a PSR-6 compliant cache key.
     *
     * Format: {keyPrefix}__{platformId}__{userId}
     *
     * PSR-6 prohibited characters (@, :, ,, {, }, (, ), /, \, space) are replaced
     * with underscores to ensure compatibility.
     *
     * @param string $userId The user ID
     * @param string $platformId The platform ID
     *
     * @return string A PSR-6 safe cache key
     */
    private function buildCacheKey(string $userId, string $platformId): string
    {
        $key = sprintf('%s__%s__%s', $this->keyPrefix, $platformId, $userId);

        // Replace PSR-6 prohibited characters with underscores
        return str_replace(self::PSR6_PROHIBITED_CHARS, '_', $key);
    }
}
