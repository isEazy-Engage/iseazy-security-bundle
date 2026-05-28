<?php

declare(strict_types=1);

namespace Tests\Authorization\Domain\Model;

use Iseazy\Security\Authorization\Domain\Exception\InvalidCapabilityException;
use Iseazy\Security\Authorization\Domain\Model\Capability;
use Iseazy\Security\Authorization\Domain\Model\Scope;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for Capability value object.
 *
 * Tests cover:
 * - Construction validation (empty action, empty context, GLOBAL scope invariants)
 * - Context deduplication and reindexing
 * - Serialization methods (toString, toPsr6Key, toArray, fromArray)
 * - Comparison methods (matches, covers, isLessRestrictiveThan)
 * - Merge functionality
 * - Round-trip serialization/deserialization
 */
final class CapabilityTest extends TestCase
{
    // ========================================================================
    // Construction Tests
    // ========================================================================

    #[Test]
    public function testConstructWithValidData(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);

        $this->assertSame('view_user', $capability->action());
        $this->assertSame(Scope::BUSINESS, $capability->scope());
        $this->assertSame(['biz-a', 'biz-b'], $capability->context());
    }

    #[Test]
    public function testConstructWithEmptyActionThrows(): void
    {
        $this->expectException(InvalidCapabilityException::class);
        $this->expectExceptionMessage('action_cannot_be_empty');

        new Capability('', Scope::BUSINESS, ['biz-a']);
    }

    #[Test]
    public function testConstructWithEmptyContextThrows(): void
    {
        $this->expectException(InvalidCapabilityException::class);
        $this->expectExceptionMessage('context_cannot_be_empty');

        new Capability('view_user', Scope::BUSINESS, []);
    }

    #[Test]
    public function testConstructGlobalScopeRequiresStarContext(): void
    {
        $this->expectException(InvalidCapabilityException::class);
        $this->expectExceptionMessage('global_scope_requires_wildcard_context');

        new Capability('admin', Scope::GLOBAL, ['biz-a']);
    }

    #[Test]
    public function testConstructGlobalScopeWithStarContextSucceeds(): void
    {
        $capability = new Capability('admin', Scope::GLOBAL, ['*']);

        $this->assertSame('admin', $capability->action());
        $this->assertSame(Scope::GLOBAL, $capability->scope());
        $this->assertSame(['*'], $capability->context());
    }

    #[Test]
    public function testConstructDeduplicatesContext(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b', 'biz-a', 'biz-c', 'biz-b']);

        $this->assertSame(['biz-a', 'biz-b', 'biz-c'], $capability->context());
    }

    #[Test]
    public function testConstructReindexesContextAfterDeduplication(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b', 'biz-a']);

        $expected = ['biz-a', 'biz-b'];
        $this->assertSame($expected, $capability->context());
        // Verify it's zero-indexed
        $this->assertArrayHasKey(0, $capability->context());
        $this->assertArrayHasKey(1, $capability->context());
        $this->assertArrayNotHasKey(2, $capability->context());
    }

    // ========================================================================
    // Serialization Tests
    // ========================================================================

    #[Test]
    public function testToStringFormat(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);

        $this->assertSame('view_user@business:biz-a,biz-b', $capability->toString());
    }

    #[Test]
    public function testToStringWithSingleContext(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a']);

        $this->assertSame('view_user@business:biz-a', $capability->toString());
    }

    #[Test]
    public function testToStringWithGlobalScope(): void
    {
        $capability = new Capability('admin', Scope::GLOBAL, ['*']);

        $this->assertSame('admin@global:*', $capability->toString());
    }

    #[Test]
    public function testToPsr6KeyFormat(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);

        $this->assertSame('view_user___business__biz-a__biz-b', $capability->toPsr6Key());
    }

    #[Test]
    public function testToPsr6KeyWithSingleContext(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a']);

        $this->assertSame('view_user___business__biz-a', $capability->toPsr6Key());
    }

    #[Test]
    public function testToPsr6KeyWithGlobalScope(): void
    {
        $capability = new Capability('admin', Scope::GLOBAL, ['*']);

        $this->assertSame('admin___global__*', $capability->toPsr6Key());
    }

    #[Test]
    public function testToArrayStructure(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);

        $expected = [
            'capability' => 'view_user',
            'scope' => 'business',
            'context' => ['biz-a', 'biz-b'],
        ];

        $this->assertSame($expected, $capability->toArray());
    }

    #[Test]
    public function testFromArrayCreatesEquivalent(): void
    {
        $data = [
            'capability' => 'view_user',
            'scope' => 'business',
            'context' => ['biz-a', 'biz-b'],
        ];

        $capability = Capability::fromArray($data);

        $this->assertSame('view_user', $capability->action());
        $this->assertSame(Scope::BUSINESS, $capability->scope());
        $this->assertSame(['biz-a', 'biz-b'], $capability->context());
    }

    #[Test]
    public function testRoundTripToArrayAndFromArray(): void
    {
        $original = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);

        $array = $original->toArray();
        $restored = Capability::fromArray($array);

        $this->assertSame($original->action(), $restored->action());
        $this->assertSame($original->scope(), $restored->scope());
        $this->assertSame($original->context(), $restored->context());
        $this->assertSame($original->toString(), $restored->toString());
    }

    #[Test]
    public function testFromArrayMissingCapabilityFieldThrows(): void
    {
        $this->expectException(InvalidCapabilityException::class);
        $this->expectExceptionMessage('missing_capability_field');

        Capability::fromArray([
            'scope' => 'business',
            'context' => ['biz-a'],
        ]);
    }

    #[Test]
    public function testFromArrayMissingScopeFieldThrows(): void
    {
        $this->expectException(InvalidCapabilityException::class);
        $this->expectExceptionMessage('missing_scope_field');

        Capability::fromArray([
            'capability' => 'view_user',
            'context' => ['biz-a'],
        ]);
    }

    #[Test]
    public function testFromArrayMissingContextFieldThrows(): void
    {
        $this->expectException(InvalidCapabilityException::class);
        $this->expectExceptionMessage('missing_context_field');

        Capability::fromArray([
            'capability' => 'view_user',
            'scope' => 'business',
        ]);
    }

    #[Test]
    public function testFromArrayWithInvalidScopeThrows(): void
    {
        $this->expectException(\ValueError::class);

        Capability::fromArray([
            'capability' => 'view_user',
            'scope' => 'invalid_scope',
            'context' => ['biz-a'],
        ]);
    }

    // ========================================================================
    // matches() Method Tests
    // ========================================================================

    #[Test]
    public function testMatchesReturnsTrueWhenActionScopeAndContextIdMatch(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);

        $this->assertTrue($capability->matches('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($capability->matches('view_user', Scope::BUSINESS, 'biz-b'));
    }

    #[Test]
    public function testMatchesReturnsFalseWhenContextIdNotInContext(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);

        $this->assertFalse($capability->matches('view_user', Scope::BUSINESS, 'biz-z'));
    }

    #[Test]
    public function testMatchesReturnsFalseWhenActionDiffers(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a']);

        $this->assertFalse($capability->matches('edit_user', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function testMatchesReturnsFalseWhenScopeDoesNotCover(): void
    {
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a']);

        // BUSINESS does not cover PLATFORM
        $this->assertFalse($capability->matches('view_user', Scope::PLATFORM, 'biz-a'));
    }

    #[Test]
    public function testMatchesReturnsTrueWhenScopeCovers(): void
    {
        $capability = new Capability('view_user', Scope::GLOBAL, ['*']);

        // GLOBAL covers BUSINESS
        $this->assertTrue($capability->matches('view_user', Scope::BUSINESS, 'any-context'));
    }

    #[Test]
    public function testMatchesWithStarContextMatchesAnyContextId(): void
    {
        $capability = new Capability('admin', Scope::GLOBAL, ['*']);

        $this->assertTrue($capability->matches('admin', Scope::GLOBAL, 'any-context'));
        $this->assertTrue($capability->matches('admin', Scope::PLATFORM, 'plat-x'));
        $this->assertTrue($capability->matches('admin', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($capability->matches('admin', Scope::HIERARCHY, 'hier-1'));
    }

    #[Test]
    #[DataProvider('matchesWithScopeCoversProvider')]
    public function testMatchesWithVariousScopeCombinations(
        Scope $capabilityScope,
        Scope $requestedScope,
        bool $expectedToMatch
    ): void {
        // GLOBAL scope requires ['*'] as context
        $context = $capabilityScope === Scope::GLOBAL ? ['*'] : ['ctx-a'];
        $capability = new Capability('view_user', $capabilityScope, $context);

        $this->assertSame(
            $expectedToMatch,
            $capability->matches('view_user', $requestedScope, 'ctx-a'),
            sprintf(
                'Expected capability with scope %s to %s match request with scope %s',
                $capabilityScope->value,
                $expectedToMatch ? '' : 'NOT',
                $requestedScope->value
            )
        );
    }

    // ========================================================================
    // covers() Method Tests
    // ========================================================================

    #[Test]
    public function testCoversReturnsTrueWithSameActionScopeAndContext(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);

        $this->assertTrue($cap1->covers($cap2));
    }

    #[Test]
    public function testCoversReturnsTrueWhenContextIsSuperset(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b', 'biz-c']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);

        $this->assertTrue($cap1->covers($cap2));
    }

    #[Test]
    public function testCoversReturnsFalseWhenContextIsNotSuperset(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b', 'biz-c']);

        $this->assertFalse($cap1->covers($cap2));
    }

    #[Test]
    public function testCoversReturnsTrueWithStarContext(): void
    {
        $cap1 = new Capability('admin', Scope::GLOBAL, ['*']);
        $cap2 = new Capability('admin', Scope::GLOBAL, ['*']);

        $this->assertTrue($cap1->covers($cap2));
    }

    #[Test]
    public function testCoversReturnsFalseWithDifferentAction(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $cap2 = new Capability('edit_user', Scope::BUSINESS, ['biz-a']);

        $this->assertFalse($cap1->covers($cap2));
    }

    #[Test]
    public function testCoversReturnsFalseWhenScopeDoesNotCover(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $cap2 = new Capability('view_user', Scope::PLATFORM, ['biz-a']);

        // BUSINESS does not cover PLATFORM
        $this->assertFalse($cap1->covers($cap2));
    }

    #[Test]
    public function testCoversReturnsTrueWhenScopeCovers(): void
    {
        $cap1 = new Capability('view_user', Scope::GLOBAL, ['*']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);

        // GLOBAL covers BUSINESS and '*' covers any context
        $this->assertTrue($cap1->covers($cap2));
    }

    #[Test]
    public function testCoversWithStarContextCoversAnyContext(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['*']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b', 'biz-c']);

        $this->assertTrue($cap1->covers($cap2));
    }

    // ========================================================================
    // isLessRestrictiveThan() Method Tests
    // ========================================================================

    #[Test]
    public function testIsLessRestrictiveThanReturnsTrueWhenScopeIsLessRestrictive(): void
    {
        $cap1 = new Capability('view_user', Scope::GLOBAL, ['*']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);

        $this->assertTrue($cap1->isLessRestrictiveThan($cap2));
    }

    #[Test]
    public function testIsLessRestrictiveThanReturnsFalseWhenScopeIsMoreRestrictive(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $cap2 = new Capability('view_user', Scope::GLOBAL, ['*']);

        $this->assertFalse($cap1->isLessRestrictiveThan($cap2));
    }

    #[Test]
    public function testIsLessRestrictiveThanReturnsFalseWhenScopeIsSame(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-b']);

        $this->assertFalse($cap1->isLessRestrictiveThan($cap2));
    }

    #[Test]
    public function testIsLessRestrictiveThanReturnsFalseWhenActionDiffers(): void
    {
        $cap1 = new Capability('view_user', Scope::GLOBAL, ['*']);
        $cap2 = new Capability('edit_user', Scope::BUSINESS, ['biz-a']);

        $this->assertFalse($cap1->isLessRestrictiveThan($cap2));
    }

    #[Test]
    public function testIsLessRestrictiveThanIgnoresContext(): void
    {
        $cap1 = new Capability('view_user', Scope::GLOBAL, ['*']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b', 'biz-c']);

        // Only action and scope matter, not context
        $this->assertTrue($cap1->isLessRestrictiveThan($cap2));
    }

    // ========================================================================
    // merge() Method Tests
    // ========================================================================

    #[Test]
    public function testMergeWithSameActionAndScopeCombinesContexts(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-c', 'biz-d']);

        $merged = $cap1->merge($cap2);

        $this->assertSame('view_user', $merged->action());
        $this->assertSame(Scope::BUSINESS, $merged->scope());
        $this->assertSame(['biz-a', 'biz-b', 'biz-c', 'biz-d'], $merged->context());
    }

    #[Test]
    public function testMergeDeduplicatesContexts(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-b', 'biz-c']);

        $merged = $cap1->merge($cap2);

        $this->assertSame(['biz-a', 'biz-b', 'biz-c'], $merged->context());
    }

    #[Test]
    public function testMergeIsImmutable(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $cap2 = new Capability('view_user', Scope::BUSINESS, ['biz-b']);

        $merged = $cap1->merge($cap2);

        // Original capabilities unchanged
        $this->assertSame(['biz-a'], $cap1->context());
        $this->assertSame(['biz-b'], $cap2->context());
        // Merged has both
        $this->assertSame(['biz-a', 'biz-b'], $merged->context());
    }

    #[Test]
    public function testMergeWithDifferentActionThrows(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $cap2 = new Capability('edit_user', Scope::BUSINESS, ['biz-a']);

        $this->expectException(InvalidCapabilityException::class);
        $this->expectExceptionMessage('cannot_merge_different_action_or_scope');

        $cap1->merge($cap2);
    }

    #[Test]
    public function testMergeWithDifferentScopeThrows(): void
    {
        $cap1 = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $cap2 = new Capability('view_user', Scope::PLATFORM, ['plat-a']);

        $this->expectException(InvalidCapabilityException::class);
        $this->expectExceptionMessage('cannot_merge_different_action_or_scope');

        $cap1->merge($cap2);
    }

    // ========================================================================
    // Data Providers
    // ========================================================================

    /**
     * Provides test cases for matches() with various scope combinations.
     *
     * Tests that scope coverage is properly respected by matches().
     *
     * @return array<string, array{capabilityScope: Scope, requestedScope: Scope, expectedToMatch: bool}>
     */
    public static function matchesWithScopeCoversProvider(): array
    {
        return [
            // GLOBAL capability covers all scopes
            'GLOBAL capability matches GLOBAL request' => [
                'capabilityScope' => Scope::GLOBAL,
                'requestedScope' => Scope::GLOBAL,
                'expectedToMatch' => true,
            ],
            'GLOBAL capability matches PLATFORM request' => [
                'capabilityScope' => Scope::GLOBAL,
                'requestedScope' => Scope::PLATFORM,
                'expectedToMatch' => true,
            ],
            'GLOBAL capability matches BUSINESS request' => [
                'capabilityScope' => Scope::GLOBAL,
                'requestedScope' => Scope::BUSINESS,
                'expectedToMatch' => true,
            ],
            'GLOBAL capability matches HIERARCHY request' => [
                'capabilityScope' => Scope::GLOBAL,
                'requestedScope' => Scope::HIERARCHY,
                'expectedToMatch' => true,
            ],

            // PLATFORM capability covers PLATFORM, BUSINESS, HIERARCHY (but not GLOBAL)
            'PLATFORM capability does not match GLOBAL request' => [
                'capabilityScope' => Scope::PLATFORM,
                'requestedScope' => Scope::GLOBAL,
                'expectedToMatch' => false,
            ],
            'PLATFORM capability matches PLATFORM request' => [
                'capabilityScope' => Scope::PLATFORM,
                'requestedScope' => Scope::PLATFORM,
                'expectedToMatch' => true,
            ],
            'PLATFORM capability matches BUSINESS request' => [
                'capabilityScope' => Scope::PLATFORM,
                'requestedScope' => Scope::BUSINESS,
                'expectedToMatch' => true,
            ],
            'PLATFORM capability matches HIERARCHY request' => [
                'capabilityScope' => Scope::PLATFORM,
                'requestedScope' => Scope::HIERARCHY,
                'expectedToMatch' => true,
            ],

            // BUSINESS capability only covers BUSINESS
            'BUSINESS capability does not match GLOBAL request' => [
                'capabilityScope' => Scope::BUSINESS,
                'requestedScope' => Scope::GLOBAL,
                'expectedToMatch' => false,
            ],
            'BUSINESS capability does not match PLATFORM request' => [
                'capabilityScope' => Scope::BUSINESS,
                'requestedScope' => Scope::PLATFORM,
                'expectedToMatch' => false,
            ],
            'BUSINESS capability matches BUSINESS request' => [
                'capabilityScope' => Scope::BUSINESS,
                'requestedScope' => Scope::BUSINESS,
                'expectedToMatch' => true,
            ],
            'BUSINESS capability does not match HIERARCHY request' => [
                'capabilityScope' => Scope::BUSINESS,
                'requestedScope' => Scope::HIERARCHY,
                'expectedToMatch' => false,
            ],

            // HIERARCHY capability only covers HIERARCHY
            'HIERARCHY capability does not match GLOBAL request' => [
                'capabilityScope' => Scope::HIERARCHY,
                'requestedScope' => Scope::GLOBAL,
                'expectedToMatch' => false,
            ],
            'HIERARCHY capability does not match PLATFORM request' => [
                'capabilityScope' => Scope::HIERARCHY,
                'requestedScope' => Scope::PLATFORM,
                'expectedToMatch' => false,
            ],
            'HIERARCHY capability does not match BUSINESS request' => [
                'capabilityScope' => Scope::HIERARCHY,
                'requestedScope' => Scope::BUSINESS,
                'expectedToMatch' => false,
            ],
            'HIERARCHY capability matches HIERARCHY request' => [
                'capabilityScope' => Scope::HIERARCHY,
                'requestedScope' => Scope::HIERARCHY,
                'expectedToMatch' => true,
            ],
        ];
    }
}
