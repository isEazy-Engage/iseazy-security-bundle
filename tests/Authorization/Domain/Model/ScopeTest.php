<?php

declare(strict_types=1);

namespace Tests\Authorization\Domain\Model;

use Iseazy\Security\Authorization\Domain\Model\Scope;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for Scope enum.
 *
 * Tests cover:
 * - All 16 combinations of Scope × Scope for isLessRestrictiveThan()
 * - All 16 combinations of Scope × Scope for covers()
 * - Instantiation from string values (from/tryFrom)
 */
final class ScopeTest extends TestCase
{
    #[Test]
    public function testGlobalIsLessRestrictiveThanPlatform(): void
    {
        $this->assertTrue(Scope::GLOBAL->isLessRestrictiveThan(Scope::PLATFORM));
    }

    #[Test]
    public function testGlobalIsLessRestrictiveThanBusiness(): void
    {
        $this->assertTrue(Scope::GLOBAL->isLessRestrictiveThan(Scope::BUSINESS));
    }

    #[Test]
    public function testGlobalIsLessRestrictiveThanHierarchy(): void
    {
        $this->assertTrue(Scope::GLOBAL->isLessRestrictiveThan(Scope::HIERARCHY));
    }

    #[Test]
    public function testGlobalIsNotLessRestrictiveThanItself(): void
    {
        $this->assertFalse(Scope::GLOBAL->isLessRestrictiveThan(Scope::GLOBAL));
    }

    #[Test]
    public function testPlatformIsLessRestrictiveThanBusiness(): void
    {
        $this->assertTrue(Scope::PLATFORM->isLessRestrictiveThan(Scope::BUSINESS));
    }

    #[Test]
    public function testPlatformIsLessRestrictiveThanHierarchy(): void
    {
        $this->assertTrue(Scope::PLATFORM->isLessRestrictiveThan(Scope::HIERARCHY));
    }

    #[Test]
    public function testPlatformIsNotLessRestrictiveThanGlobal(): void
    {
        $this->assertFalse(Scope::PLATFORM->isLessRestrictiveThan(Scope::GLOBAL));
    }

    #[Test]
    public function testPlatformIsNotLessRestrictiveThanItself(): void
    {
        $this->assertFalse(Scope::PLATFORM->isLessRestrictiveThan(Scope::PLATFORM));
    }

    #[Test]
    public function testBusinessIsNotLessRestrictiveThanAnyScope(): void
    {
        $this->assertFalse(Scope::BUSINESS->isLessRestrictiveThan(Scope::GLOBAL));
        $this->assertFalse(Scope::BUSINESS->isLessRestrictiveThan(Scope::PLATFORM));
        $this->assertFalse(Scope::BUSINESS->isLessRestrictiveThan(Scope::BUSINESS));
        $this->assertFalse(Scope::BUSINESS->isLessRestrictiveThan(Scope::HIERARCHY));
    }

    #[Test]
    public function testHierarchyIsNotLessRestrictiveThanAnyScope(): void
    {
        $this->assertFalse(Scope::HIERARCHY->isLessRestrictiveThan(Scope::GLOBAL));
        $this->assertFalse(Scope::HIERARCHY->isLessRestrictiveThan(Scope::PLATFORM));
        $this->assertFalse(Scope::HIERARCHY->isLessRestrictiveThan(Scope::BUSINESS));
        $this->assertFalse(Scope::HIERARCHY->isLessRestrictiveThan(Scope::HIERARCHY));
    }

    #[Test]
    public function testGlobalCoversAllScopes(): void
    {
        $this->assertTrue(Scope::GLOBAL->covers(Scope::GLOBAL));
        $this->assertTrue(Scope::GLOBAL->covers(Scope::PLATFORM));
        $this->assertTrue(Scope::GLOBAL->covers(Scope::BUSINESS));
        $this->assertTrue(Scope::GLOBAL->covers(Scope::HIERARCHY));
    }

    #[Test]
    public function testPlatformCoversItselfBusinessAndHierarchyButNotGlobal(): void
    {
        $this->assertFalse(Scope::PLATFORM->covers(Scope::GLOBAL));
        $this->assertTrue(Scope::PLATFORM->covers(Scope::PLATFORM));
        $this->assertTrue(Scope::PLATFORM->covers(Scope::BUSINESS));
        $this->assertTrue(Scope::PLATFORM->covers(Scope::HIERARCHY));
    }

    #[Test]
    public function testBusinessOnlyCoversItself(): void
    {
        $this->assertFalse(Scope::BUSINESS->covers(Scope::GLOBAL));
        $this->assertFalse(Scope::BUSINESS->covers(Scope::PLATFORM));
        $this->assertTrue(Scope::BUSINESS->covers(Scope::BUSINESS));
        $this->assertFalse(Scope::BUSINESS->covers(Scope::HIERARCHY));
    }

    #[Test]
    public function testHierarchyOnlyCoversItself(): void
    {
        $this->assertFalse(Scope::HIERARCHY->covers(Scope::GLOBAL));
        $this->assertFalse(Scope::HIERARCHY->covers(Scope::PLATFORM));
        $this->assertFalse(Scope::HIERARCHY->covers(Scope::BUSINESS));
        $this->assertTrue(Scope::HIERARCHY->covers(Scope::HIERARCHY));
    }

    /**
     * Tests all 16 pairs (Scope × Scope) for isLessRestrictiveThan using a data provider.
     */
    #[Test]
    #[DataProvider('isLessRestrictiveThanProvider')]
    public function testIsLessRestrictiveThanWithAllPairs(
        Scope $scope,
        Scope $other,
        bool $expected
    ): void {
        $this->assertSame(
            $expected,
            $scope->isLessRestrictiveThan($other),
            sprintf(
                'Expected %s->isLessRestrictiveThan(%s) to be %s',
                $scope->value,
                $other->value,
                $expected ? 'true' : 'false'
            )
        );
    }

    /**
     * Tests all 16 pairs (Scope × Scope) for covers using a data provider.
     */
    #[Test]
    #[DataProvider('coversProvider')]
    public function testCoversWithAllPairs(
        Scope $scope,
        Scope $other,
        bool $expected
    ): void {
        $this->assertSame(
            $expected,
            $scope->covers($other),
            sprintf(
                'Expected %s->covers(%s) to be %s',
                $scope->value,
                $other->value,
                $expected ? 'true' : 'false'
            )
        );
    }

    #[Test]
    public function testFromValidString(): void
    {
        $this->assertSame(Scope::GLOBAL, Scope::from('global'));
        $this->assertSame(Scope::PLATFORM, Scope::from('platform'));
        $this->assertSame(Scope::BUSINESS, Scope::from('business'));
        $this->assertSame(Scope::HIERARCHY, Scope::from('hierarchy'));
    }

    #[Test]
    public function testFromInvalidStringThrowsException(): void
    {
        $this->expectException(\ValueError::class);
        Scope::from('invalid');
    }

    #[Test]
    public function testTryFromValidString(): void
    {
        $this->assertSame(Scope::GLOBAL, Scope::tryFrom('global'));
        $this->assertSame(Scope::PLATFORM, Scope::tryFrom('platform'));
        $this->assertSame(Scope::BUSINESS, Scope::tryFrom('business'));
        $this->assertSame(Scope::HIERARCHY, Scope::tryFrom('hierarchy'));
    }

    #[Test]
    public function testTryFromInvalidStringReturnsNull(): void
    {
        $this->assertNull(Scope::tryFrom('invalid'));
        $this->assertNull(Scope::tryFrom(''));
        $this->assertNull(Scope::tryFrom('GLOBAL'));
    }

    #[Test]
    public function testEnumValueAccessor(): void
    {
        $this->assertSame('global', Scope::GLOBAL->value);
        $this->assertSame('platform', Scope::PLATFORM->value);
        $this->assertSame('business', Scope::BUSINESS->value);
        $this->assertSame('hierarchy', Scope::HIERARCHY->value);
    }

    #[Test]
    public function testEnumNameAccessor(): void
    {
        $this->assertSame('GLOBAL', Scope::GLOBAL->name);
        $this->assertSame('PLATFORM', Scope::PLATFORM->name);
        $this->assertSame('BUSINESS', Scope::BUSINESS->name);
        $this->assertSame('HIERARCHY', Scope::HIERARCHY->name);
    }

    /**
     * Data provider for all 16 Scope × Scope pairs for isLessRestrictiveThan.
     *
     * @return array<string, array{scope: Scope, other: Scope, expected: bool}>
     */
    public static function isLessRestrictiveThanProvider(): array
    {
        return [
            // GLOBAL comparisons
            'GLOBAL vs GLOBAL' => ['scope' => Scope::GLOBAL, 'other' => Scope::GLOBAL, 'expected' => false],
            'GLOBAL vs PLATFORM' => ['scope' => Scope::GLOBAL, 'other' => Scope::PLATFORM, 'expected' => true],
            'GLOBAL vs BUSINESS' => ['scope' => Scope::GLOBAL, 'other' => Scope::BUSINESS, 'expected' => true],
            'GLOBAL vs HIERARCHY' => ['scope' => Scope::GLOBAL, 'other' => Scope::HIERARCHY, 'expected' => true],

            // PLATFORM comparisons
            'PLATFORM vs GLOBAL' => ['scope' => Scope::PLATFORM, 'other' => Scope::GLOBAL, 'expected' => false],
            'PLATFORM vs PLATFORM' => ['scope' => Scope::PLATFORM, 'other' => Scope::PLATFORM, 'expected' => false],
            'PLATFORM vs BUSINESS' => ['scope' => Scope::PLATFORM, 'other' => Scope::BUSINESS, 'expected' => true],
            'PLATFORM vs HIERARCHY' => ['scope' => Scope::PLATFORM, 'other' => Scope::HIERARCHY, 'expected' => true],

            // BUSINESS comparisons (parallel to HIERARCHY - same restriction level)
            'BUSINESS vs GLOBAL' => ['scope' => Scope::BUSINESS, 'other' => Scope::GLOBAL, 'expected' => false],
            'BUSINESS vs PLATFORM' => ['scope' => Scope::BUSINESS, 'other' => Scope::PLATFORM, 'expected' => false],
            'BUSINESS vs BUSINESS' => ['scope' => Scope::BUSINESS, 'other' => Scope::BUSINESS, 'expected' => false],
            'BUSINESS vs HIERARCHY' => ['scope' => Scope::BUSINESS, 'other' => Scope::HIERARCHY, 'expected' => false],

            // HIERARCHY comparisons (parallel to BUSINESS - same restriction level)
            'HIERARCHY vs GLOBAL' => ['scope' => Scope::HIERARCHY, 'other' => Scope::GLOBAL, 'expected' => false],
            'HIERARCHY vs PLATFORM' => ['scope' => Scope::HIERARCHY, 'other' => Scope::PLATFORM, 'expected' => false],
            'HIERARCHY vs BUSINESS' => ['scope' => Scope::HIERARCHY, 'other' => Scope::BUSINESS, 'expected' => false],
            'HIERARCHY vs HIERARCHY' => ['scope' => Scope::HIERARCHY, 'other' => Scope::HIERARCHY, 'expected' => false],
        ];
    }

    /**
     * Data provider for all 16 Scope × Scope pairs for covers.
     *
     * @return array<string, array{scope: Scope, other: Scope, expected: bool}>
     */
    public static function coversProvider(): array
    {
        return [
            // GLOBAL covers all
            'GLOBAL covers GLOBAL' => ['scope' => Scope::GLOBAL, 'other' => Scope::GLOBAL, 'expected' => true],
            'GLOBAL covers PLATFORM' => ['scope' => Scope::GLOBAL, 'other' => Scope::PLATFORM, 'expected' => true],
            'GLOBAL covers BUSINESS' => ['scope' => Scope::GLOBAL, 'other' => Scope::BUSINESS, 'expected' => true],
            'GLOBAL covers HIERARCHY' => ['scope' => Scope::GLOBAL, 'other' => Scope::HIERARCHY, 'expected' => true],

            // PLATFORM covers itself, BUSINESS, HIERARCHY (but not GLOBAL)
            'PLATFORM does not cover GLOBAL' => [
                'scope' => Scope::PLATFORM,
                'other' => Scope::GLOBAL,
                'expected' => false,
            ],
            'PLATFORM covers PLATFORM' => [
                'scope' => Scope::PLATFORM,
                'other' => Scope::PLATFORM,
                'expected' => true,
            ],
            'PLATFORM covers BUSINESS' => [
                'scope' => Scope::PLATFORM,
                'other' => Scope::BUSINESS,
                'expected' => true,
            ],
            'PLATFORM covers HIERARCHY' => [
                'scope' => Scope::PLATFORM,
                'other' => Scope::HIERARCHY,
                'expected' => true,
            ],

            // BUSINESS only covers itself (parallel to HIERARCHY)
            'BUSINESS does not cover GLOBAL' => [
                'scope' => Scope::BUSINESS,
                'other' => Scope::GLOBAL,
                'expected' => false,
            ],
            'BUSINESS does not cover PLATFORM' => [
                'scope' => Scope::BUSINESS,
                'other' => Scope::PLATFORM,
                'expected' => false,
            ],
            'BUSINESS covers BUSINESS' => [
                'scope' => Scope::BUSINESS,
                'other' => Scope::BUSINESS,
                'expected' => true,
            ],
            'BUSINESS does not cover HIERARCHY' => [
                'scope' => Scope::BUSINESS,
                'other' => Scope::HIERARCHY,
                'expected' => false,
            ],

            // HIERARCHY only covers itself (parallel to BUSINESS)
            'HIERARCHY does not cover GLOBAL' => [
                'scope' => Scope::HIERARCHY,
                'other' => Scope::GLOBAL,
                'expected' => false,
            ],
            'HIERARCHY does not cover PLATFORM' => [
                'scope' => Scope::HIERARCHY,
                'other' => Scope::PLATFORM,
                'expected' => false,
            ],
            'HIERARCHY does not cover BUSINESS' => [
                'scope' => Scope::HIERARCHY,
                'other' => Scope::BUSINESS,
                'expected' => false,
            ],
            'HIERARCHY covers HIERARCHY' => [
                'scope' => Scope::HIERARCHY,
                'other' => Scope::HIERARCHY,
                'expected' => true,
            ],
        ];
    }
}
