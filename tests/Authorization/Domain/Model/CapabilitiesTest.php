<?php

declare(strict_types=1);

namespace Iseazy\Security\Tests\Authorization\Model;

use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Model\Capability;
use Iseazy\Security\Authorization\Domain\Model\Scope;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the Capabilities collection.
 *
 * @covers \Iseazy\Security\Authorization\Model\Capabilities
 */
final class CapabilitiesTest extends TestCase
{
    #[Test]
    public function emptyReturnsEmptyCollection(): void
    {
        // ARRANGE & ACT
        $capabilities = Capabilities::empty();

        // ASSERT
        $this->assertTrue($capabilities->isEmpty());
        $this->assertCount(0, $capabilities);
    }

    #[Test]
    public function constructDeduplicatesAndMerges(): void
    {
        // ARRANGE
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-b']);
        $cap3 = new Capability('edit_user', Scope::PLATFORM, ['plt-1']);

        // ACT
        $capabilities = new Capabilities([$cap1, $cap2, $cap3]);

        // ASSERT
        $this->assertCount(2, $capabilities, 'Should merge view_user@business capabilities');

        // Verify merged capability contains both contexts
        $this->assertTrue($capabilities->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($capabilities->has('view_user', Scope::BUSINESS, 'biz-b'));
        $this->assertTrue($capabilities->has('edit_user', Scope::PLATFORM, 'plt-1'));
    }

    #[Test]
    public function addReturnsNewInstance(): void
    {
        // ARRANGE
        $original = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);
        $toAdd = new Capability('edit_user', Scope::PLATFORM, ['plt-1']);

        // ACT
        $updated = $original->add($toAdd);

        // ASSERT
        $this->assertNotSame($original, $updated, 'Should return new instance (immutability)');
        $this->assertCount(1, $original, 'Original should remain unchanged');
        $this->assertCount(2, $updated, 'Updated should have new capability');
    }

    #[Test]
    public function addMergesWhenSameActionScope(): void
    {
        // ARRANGE
        $original = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);
        $toAdd = new Capability('view_user', Scope::BUSINESS, ['biz-b']);

        // ACT
        $updated = $original->add($toAdd);

        // ASSERT
        $this->assertCount(1, $updated, 'Should merge instead of adding duplicate action@scope');
        $this->assertTrue($updated->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($updated->has('view_user', Scope::BUSINESS, 'biz-b'));
    }

    #[Test]
    public function hasFindsExactMatch(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']),
            new Capability('edit_user', Scope::PLATFORM, ['plt-1']),
        ]);

        // ACT & ASSERT
        $this->assertTrue($capabilities->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($capabilities->has('view_user', Scope::BUSINESS, 'biz-b'));
        $this->assertTrue($capabilities->has('edit_user', Scope::PLATFORM, 'plt-1'));
    }

    #[Test]
    public function hasReturnsFalseWhenContextMissing(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        // ACT & ASSERT
        $this->assertFalse($capabilities->has('view_user', Scope::BUSINESS, 'biz-b'));
        $this->assertFalse($capabilities->has('view_user', Scope::PLATFORM, 'biz-a')); // Wrong scope
        $this->assertFalse($capabilities->has('edit_user', Scope::BUSINESS, 'biz-a')); // Wrong action
    }

    #[Test]
    public function hasReturnsTrueWithWildcardContext(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::GLOBAL, ['*']),
        ]);

        // ACT & ASSERT
        $this->assertTrue($capabilities->has('view_user', Scope::GLOBAL, 'any-context'));
        $this->assertTrue($capabilities->has('view_user', Scope::GLOBAL, 'another-context'));
    }

    #[Test]
    public function hasAnyFindsCapabilityInCoveringScope(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::GLOBAL, ['*']),
        ]);

        // ACT & ASSERT
        // Global scope covers all scopes, so hasAny should find it
        $this->assertTrue($capabilities->hasAny('view_user', 'any-context'));
        $this->assertTrue($capabilities->hasAny('view_user', 'biz-a'));
    }

    #[Test]
    public function hasAnyFindsCapabilityInPlatformScope(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::PLATFORM, ['plt-1']),
        ]);

        // ACT & ASSERT
        // Platform scope covers business/hierarchy, so hasAny should find it
        $this->assertTrue($capabilities->hasAny('view_user', 'plt-1'));
    }

    #[Test]
    public function hasAnyReturnsFalseWhenNoMatch(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        // ACT & ASSERT
        $this->assertFalse($capabilities->hasAny('view_user', 'biz-b')); // Wrong context
        $this->assertFalse($capabilities->hasAny('edit_user', 'biz-a')); // Wrong action
    }

    #[Test]
    public function mergeWithOtherCollection(): void
    {
        // ARRANGE
        $caps1 = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);
        $caps2 = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-b']),
            new Capability('edit_user', Scope::PLATFORM, ['plt-1']),
        ]);

        // ACT
        $merged = $caps1->merge($caps2);

        // ASSERT
        $this->assertCount(1, $caps1, 'Original should remain unchanged');
        $this->assertCount(2, $caps2, 'Other should remain unchanged');
        $this->assertCount(2, $merged, 'Merged should have 2 unique action@scope keys');

        // Verify merged capability contains both contexts
        $this->assertTrue($merged->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($merged->has('view_user', Scope::BUSINESS, 'biz-b'));
        $this->assertTrue($merged->has('edit_user', Scope::PLATFORM, 'plt-1'));
    }

    #[Test]
    public function toArrayProducesFlatListOrderedByKey(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::PLATFORM, ['plt-1']),
            new Capability('edit_user', Scope::BUSINESS, ['biz-a']),
            new Capability('delete_user', Scope::GLOBAL, ['*']),
        ]);

        // ACT
        $array = $capabilities->toArray();

        // ASSERT
        $this->assertIsArray($array);
        $this->assertCount(3, $array);

        // Verify it's a flat list (numeric keys)
        $this->assertArrayHasKey(0, $array);
        $this->assertArrayHasKey(1, $array);
        $this->assertArrayHasKey(2, $array);

        // Verify ordering (sorted by action@scope)
        // delete_user@global < edit_user@business < view_user@platform (alphabetically)
        $this->assertSame('delete_user', $array[0]['capability']);
        $this->assertSame('edit_user', $array[1]['capability']);
        $this->assertSame('view_user', $array[2]['capability']);

        // Verify structure
        $this->assertArrayHasKey('capability', $array[0]);
        $this->assertArrayHasKey('scope', $array[0]);
        $this->assertArrayHasKey('context', $array[0]);
    }

    #[Test]
    public function fromArrayRoundTrip(): void
    {
        // ARRANGE
        $original = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']),
            new Capability('edit_user', Scope::PLATFORM, ['plt-1']),
        ]);

        // ACT
        $array = $original->toArray();
        $restored = Capabilities::fromArray($array);

        // ASSERT
        $this->assertCount(2, $restored);
        $this->assertTrue($restored->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($restored->has('view_user', Scope::BUSINESS, 'biz-b'));
        $this->assertTrue($restored->has('edit_user', Scope::PLATFORM, 'plt-1'));
    }

    #[Test]
    public function isEmptyAfterEmpty(): void
    {
        // ARRANGE
        $capabilities = Capabilities::empty();

        // ACT & ASSERT
        $this->assertTrue($capabilities->isEmpty());
    }

    #[Test]
    public function isEmptyReturnsFalseWhenNotEmpty(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        // ACT & ASSERT
        $this->assertFalse($capabilities->isEmpty());
    }

    #[Test]
    public function countReflectsUniqueActionScopes(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
            new Capability('view_user', Scope::BUSINESS, ['biz-b']), // Merged with above
            new Capability('view_user', Scope::PLATFORM, ['plt-1']), // Different scope
            new Capability('edit_user', Scope::BUSINESS, ['biz-a']), // Different action
        ]);

        // ACT & ASSERT
        $this->assertCount(3, $capabilities, 'Should have 3 unique action@scope combinations');
    }

    #[Test]
    public function getIteratorYieldsAllCapabilities(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']),
            new Capability('edit_user', Scope::PLATFORM, ['plt-1']),
        ]);

        // ACT
        $yielded = [];
        foreach ($capabilities as $capability) {
            $yielded[] = $capability;
        }

        // ASSERT
        $this->assertCount(2, $yielded);
        $this->assertContainsOnlyInstancesOf(Capability::class, $yielded);
    }

    #[Test]
    public function filterByActionsReturnsOnlyMatchingActions(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
            new Capability('edit_user', Scope::PLATFORM, ['plt-1']),
            new Capability('delete_user', Scope::GLOBAL, ['*']),
        ]);

        // ACT
        $filtered = $capabilities->filterByActions(['view_user', 'delete_user']);

        // ASSERT
        $this->assertCount(2, $filtered);
        $this->assertTrue($filtered->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($filtered->has('delete_user', Scope::GLOBAL, '*'));
        $this->assertFalse($filtered->has('edit_user', Scope::PLATFORM, 'plt-1'));
    }

    #[Test]
    public function filterByActionsReturnsEmptyWhenNoMatch(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        // ACT
        $filtered = $capabilities->filterByActions(['edit_user', 'delete_user']);

        // ASSERT
        $this->assertTrue($filtered->isEmpty());
        $this->assertCount(0, $filtered);
    }

    #[Test]
    public function filterByActionsIsImmutable(): void
    {
        // ARRANGE
        $original = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
            new Capability('edit_user', Scope::PLATFORM, ['plt-1']),
        ]);

        // ACT
        $filtered = $original->filterByActions(['view_user']);

        // ASSERT
        $this->assertNotSame($original, $filtered);
        $this->assertCount(2, $original, 'Original should remain unchanged');
        $this->assertCount(1, $filtered);
    }

    #[Test]
    public function fromArrayWithEmptyArrayReturnsEmptyCollection(): void
    {
        // ARRANGE & ACT
        $capabilities = Capabilities::fromArray([]);

        // ASSERT
        $this->assertTrue($capabilities->isEmpty());
        $this->assertCount(0, $capabilities);
    }

    #[Test]
    public function constructorWithEmptyArrayCreatesEmptyCollection(): void
    {
        // ARRANGE & ACT
        $capabilities = new Capabilities([]);

        // ASSERT
        $this->assertTrue($capabilities->isEmpty());
        $this->assertCount(0, $capabilities);
    }

    #[Test]
    public function mergeWithEmptyCollectionReturnsEquivalentCollection(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);
        $empty = Capabilities::empty();

        // ACT
        $merged = $capabilities->merge($empty);

        // ASSERT
        $this->assertCount(1, $merged);
        $this->assertTrue($merged->has('view_user', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function addToEmptyCollectionCreatesNewCollection(): void
    {
        // ARRANGE
        $empty = Capabilities::empty();
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a']);

        // ACT
        $updated = $empty->add($capability);

        // ASSERT
        $this->assertTrue($empty->isEmpty(), 'Original empty should remain unchanged');
        $this->assertCount(1, $updated);
        $this->assertTrue($updated->has('view_user', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function hasAnyWithMultipleCapabilitiesOfSameAction(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
            new Capability('view_user', Scope::PLATFORM, ['plt-1']),
        ]);

        // ACT & ASSERT
        $this->assertTrue($capabilities->hasAny('view_user', 'biz-a'));
        $this->assertTrue($capabilities->hasAny('view_user', 'plt-1'));
        $this->assertFalse($capabilities->hasAny('view_user', 'biz-b'));
    }

    #[Test]
    public function toArrayProducesEmptyArrayForEmptyCollection(): void
    {
        // ARRANGE
        $capabilities = Capabilities::empty();

        // ACT
        $array = $capabilities->toArray();

        // ASSERT
        $this->assertSame([], $array);
    }

    #[Test]
    public function getIteratorYieldsNothingForEmptyCollection(): void
    {
        // ARRANGE
        $capabilities = Capabilities::empty();

        // ACT
        $yielded = [];
        foreach ($capabilities as $capability) {
            $yielded[] = $capability;
        }

        // ASSERT
        $this->assertSame([], $yielded);
    }

    #[Test]
    public function constructorMergesMultipleCapabilitiesWithSameActionScope(): void
    {
        // ARRANGE
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-b']);
        $cap3 = new Capability('view_user', Scope::BUSINESS, ['biz-c']);

        // ACT
        $capabilities = new Capabilities([$cap1, $cap2, $cap3]);

        // ASSERT
        $this->assertCount(1, $capabilities, 'Should merge all three into one');
        $this->assertTrue($capabilities->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($capabilities->has('view_user', Scope::BUSINESS, 'biz-b'));
        $this->assertTrue($capabilities->has('view_user', Scope::BUSINESS, 'biz-c'));
    }

    #[Test]
    public function hasAnyWithGlobalWildcardMatchesAnyContext(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::GLOBAL, ['*']),
        ]);

        // ACT & ASSERT
        $this->assertTrue($capabilities->hasAny('view_user', 'any-random-context'));
        $this->assertTrue($capabilities->hasAny('view_user', ''));
        $this->assertTrue($capabilities->hasAny('view_user', 'biz-a'));
        $this->assertTrue($capabilities->hasAny('view_user', 'plt-1'));
    }

    #[Test]
    public function filterByActionsWithEmptyActionsArrayReturnsEmpty(): void
    {
        // ARRANGE
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
            new Capability('edit_user', Scope::PLATFORM, ['plt-1']),
        ]);

        // ACT
        $filtered = $capabilities->filterByActions([]);

        // ASSERT
        $this->assertTrue($filtered->isEmpty());
        $this->assertCount(0, $filtered);
    }

    #[Test]
    public function mergeCreatesNewInstanceWithCombinedCapabilities(): void
    {
        // ARRANGE
        $caps1 = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);
        $caps2 = new Capabilities([
            new Capability('edit_user', Scope::PLATFORM, ['plt-1']),
        ]);

        // ACT
        $merged = $caps1->merge($caps2);

        // ASSERT
        $this->assertNotSame($caps1, $merged);
        $this->assertNotSame($caps2, $merged);
        $this->assertCount(2, $merged);
    }
}
