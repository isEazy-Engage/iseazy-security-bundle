<?php

declare(strict_types=1);

namespace Tests\Authorization\Domain\Service;

use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Model\Capability;
use Iseazy\Security\Authorization\Domain\Model\Scope;
use Iseazy\Security\Authorization\Domain\Service\CapabilityFilter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for CapabilityFilter service.
 *
 * Tests the filtering algorithm that removes restrictive capabilities when
 * less restrictive ones exist for the same action.
 */
final class CapabilityFilterTest extends TestCase
{
    private CapabilityFilter $filter;

    protected function setUp(): void
    {
        $this->filter = new CapabilityFilter();
    }

    #[Test]
    public function testShouldReturnEmptyWhenInputIsEmpty(): void
    {
        // ARRANGE
        $input = Capabilities::empty();

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertTrue($result->isEmpty());
        $this->assertCount(0, $result);
    }

    #[Test]
    public function testShouldReturnSameCapabilityWhenInputHasOnlyOne(): void
    {
        // ARRANGE
        $capability = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $input = new Capabilities([$capability]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('view_user', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function testShouldKeepGlobalAndRemoveAllOtherScopesForSameAction(): void
    {
        // ARRANGE - global covers platform, business, and hierarchy
        $global = new Capability('view_user', Scope::GLOBAL, ['*']);
        $platform = new Capability('view_user', Scope::PLATFORM, ['plat-123']);
        $business = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $hierarchy = new Capability('view_user', Scope::HIERARCHY, ['hier-x']);
        $input = new Capabilities([$global, $platform, $business, $hierarchy]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('view_user', Scope::GLOBAL, '*'));
        $this->assertFalse($result->has('view_user', Scope::PLATFORM, 'plat-123'));
        $this->assertFalse($result->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertFalse($result->has('view_user', Scope::HIERARCHY, 'hier-x'));
    }

    #[Test]
    public function testShouldKeepPlatformWithWildcardAndRemoveBusinessForSameAction(): void
    {
        // ARRANGE - platform with wildcard context covers business with specific context
        $platform = new Capability('manage_business', Scope::PLATFORM, ['*']);
        $business = new Capability('manage_business', Scope::BUSINESS, ['biz-a']);
        $input = new Capabilities([$platform, $business]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('manage_business', Scope::PLATFORM, '*'));
        $this->assertFalse($result->has('manage_business', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function testShouldKeepPlatformAndRemoveBusinessOfTheSamePlatformForSameAction(): void
    {
        // ARRANGE - real model: platform context is the platform id, business context the business ids.
        // Contexts are not compared: the collection always belongs to a single platform.
        $platform = new Capability('manage_business', Scope::PLATFORM, ['plat-123']);
        $business = new Capability('manage_business', Scope::BUSINESS, ['biz-a']);
        $input = new Capabilities([$platform, $business]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('manage_business', Scope::PLATFORM, 'plat-123'));
        $this->assertFalse($result->has('manage_business', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function testShouldKeepPlatformAndRemoveHierarchyOfTheSamePlatformForSameAction(): void
    {
        // ARRANGE
        $platform = new Capability('view_user', Scope::PLATFORM, ['plat-123']);
        $hierarchy = new Capability('view_user', Scope::HIERARCHY, ['hier-x']);
        $input = new Capabilities([$platform, $hierarchy]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('view_user', Scope::PLATFORM, 'plat-123'));
        $this->assertFalse($result->has('view_user', Scope::HIERARCHY, 'hier-x'));
    }

    #[Test]
    public function testShouldKeepPlatformWithWildcardAndRemoveHierarchyForSameAction(): void
    {
        // ARRANGE - platform with wildcard context covers hierarchy with specific context
        $platform = new Capability('view_reports', Scope::PLATFORM, ['*']);
        $hierarchy = new Capability('view_reports', Scope::HIERARCHY, ['hier-x']);
        $input = new Capabilities([$platform, $hierarchy]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('view_reports', Scope::PLATFORM, '*'));
        $this->assertFalse($result->has('view_reports', Scope::HIERARCHY, 'hier-x'));
    }

    #[Test]
    public function testShouldKeepBothBusinessAndHierarchyWhenTheyDoNotCoverEachOther(): void
    {
        // ARRANGE - business and hierarchy are parallel branches, they don't cover each other
        $business = new Capability('edit_content', Scope::BUSINESS, ['biz-a']);
        $hierarchy = new Capability('edit_content', Scope::HIERARCHY, ['hier-x']);
        $input = new Capabilities([$business, $hierarchy]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(2, $result);
        $this->assertTrue($result->has('edit_content', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($result->has('edit_content', Scope::HIERARCHY, 'hier-x'));
    }

    #[Test]
    public function testShouldKeepBothCapabilitiesWhenActionsAreDifferent(): void
    {
        // ARRANGE - different actions are never filtered, regardless of scope
        $viewGlobal = new Capability('view_user', Scope::GLOBAL, ['*']);
        $editBusiness = new Capability('edit_user', Scope::BUSINESS, ['biz-a']);
        $input = new Capabilities([$viewGlobal, $editBusiness]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(2, $result);
        $this->assertTrue($result->has('view_user', Scope::GLOBAL, '*'));
        $this->assertTrue($result->has('edit_user', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    #[DataProvider('mixedScenariosProvider')]
    public function testShouldHandleMixedScenariosCorrectly(
        array $inputCapabilities,
        array $expectedActions,
        int $expectedCount
    ): void {
        // ARRANGE
        $capabilities = [];
        foreach ($inputCapabilities as $capData) {
            $capabilities[] = new Capability($capData['action'], $capData['scope'], $capData['context']);
        }
        $input = new Capabilities($capabilities);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount($expectedCount, $result);

        foreach ($expectedActions as $expectedAction) {
            $this->assertTrue(
                $result->has($expectedAction['action'], $expectedAction['scope'], $expectedAction['context']),
                sprintf(
                    'Expected capability %s@%s:%s to be present',
                    $expectedAction['action'],
                    $expectedAction['scope']->value,
                    $expectedAction['context']
                )
            );
        }
    }

    /**
     * Data provider for mixed scenarios tests.
     *
     * @return array<string, array{inputCapabilities: array, expectedActions: array, expectedCount: int}>
     */
    public static function mixedScenariosProvider(): array
    {
        return [
            'multiple actions with different scopes - only least restrictive per action' => [
                'inputCapabilities' => [
                    ['action' => 'view_user', 'scope' => Scope::GLOBAL, 'context' => ['*']],
                    ['action' => 'view_user', 'scope' => Scope::BUSINESS, 'context' => ['biz-a']],
                    ['action' => 'edit_user', 'scope' => Scope::PLATFORM, 'context' => ['*']],
                    ['action' => 'edit_user', 'scope' => Scope::BUSINESS, 'context' => ['biz-a']],
                ],
                'expectedActions' => [
                    ['action' => 'view_user', 'scope' => Scope::GLOBAL, 'context' => '*'],
                    ['action' => 'edit_user', 'scope' => Scope::PLATFORM, 'context' => '*'],
                ],
                'expectedCount' => 2,
            ],
            'platform with wildcard covers both business and hierarchy' => [
                'inputCapabilities' => [
                    ['action' => 'manage_business', 'scope' => Scope::PLATFORM, 'context' => ['*']],
                    ['action' => 'manage_business', 'scope' => Scope::BUSINESS, 'context' => ['biz-a']],
                    ['action' => 'manage_business', 'scope' => Scope::HIERARCHY, 'context' => ['hier-x']],
                ],
                'expectedActions' => [
                    ['action' => 'manage_business', 'scope' => Scope::PLATFORM, 'context' => '*'],
                ],
                'expectedCount' => 1,
            ],
            'complex scenario with all scope levels and multiple actions' => [
                'inputCapabilities' => [
                    ['action' => 'view_reports', 'scope' => Scope::GLOBAL, 'context' => ['*']],
                    ['action' => 'view_reports', 'scope' => Scope::PLATFORM, 'context' => ['plat-123']],
                    ['action' => 'view_reports', 'scope' => Scope::BUSINESS, 'context' => ['biz-a']],
                    ['action' => 'view_reports', 'scope' => Scope::HIERARCHY, 'context' => ['hier-x']],
                    ['action' => 'delete_reports', 'scope' => Scope::BUSINESS, 'context' => ['biz-a']],
                    ['action' => 'delete_reports', 'scope' => Scope::HIERARCHY, 'context' => ['hier-y']],
                ],
                'expectedActions' => [
                    ['action' => 'view_reports', 'scope' => Scope::GLOBAL, 'context' => '*'],
                    ['action' => 'delete_reports', 'scope' => Scope::BUSINESS, 'context' => 'biz-a'],
                    ['action' => 'delete_reports', 'scope' => Scope::HIERARCHY, 'context' => 'hier-y'],
                ],
                'expectedCount' => 3,
            ],
            'no filtering when all capabilities have same scope but different contexts' => [
                'inputCapabilities' => [
                    ['action' => 'view_content', 'scope' => Scope::BUSINESS, 'context' => ['biz-a']],
                    ['action' => 'view_content', 'scope' => Scope::BUSINESS, 'context' => ['biz-b']],
                    ['action' => 'view_content', 'scope' => Scope::BUSINESS, 'context' => ['biz-c']],
                ],
                'expectedActions' => [
                    ['action' => 'view_content', 'scope' => Scope::BUSINESS, 'context' => 'biz-a'],
                    // Note: Capabilities constructor will merge these into one capability with all contexts
                ],
                'expectedCount' => 1, // They get merged by Capabilities constructor
            ],
            'all different actions kept regardless of scopes' => [
                'inputCapabilities' => [
                    ['action' => 'view', 'scope' => Scope::GLOBAL, 'context' => ['*']],
                    ['action' => 'edit', 'scope' => Scope::PLATFORM, 'context' => ['plat-123']],
                    ['action' => 'delete', 'scope' => Scope::BUSINESS, 'context' => ['biz-a']],
                    ['action' => 'create', 'scope' => Scope::HIERARCHY, 'context' => ['hier-x']],
                ],
                'expectedActions' => [
                    ['action' => 'view', 'scope' => Scope::GLOBAL, 'context' => '*'],
                    ['action' => 'edit', 'scope' => Scope::PLATFORM, 'context' => 'plat-123'],
                    ['action' => 'delete', 'scope' => Scope::BUSINESS, 'context' => 'biz-a'],
                    ['action' => 'create', 'scope' => Scope::HIERARCHY, 'context' => 'hier-x'],
                ],
                'expectedCount' => 4,
            ],
        ];
    }

    #[Test]
    public function testShouldNotLetPlatformOfOneActionAbsorbBusinessOfAnotherAction(): void
    {
        // ARRANGE
        $platform = new Capability('view_business', Scope::PLATFORM, ['plat-123']);
        $business = new Capability('manage_enrollment_application', Scope::BUSINESS, ['biz-a']);
        $input = new Capabilities([$platform, $business]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(2, $result);
        $this->assertTrue($result->has('view_business', Scope::PLATFORM, 'plat-123'));
        $this->assertTrue($result->has('manage_enrollment_application', Scope::BUSINESS, 'biz-a'));
    }

    #[Test]
    public function testShouldKeepOnlyGlobalOverPlatformAndBusinessOfTheSamePlatform(): void
    {
        // ARRANGE
        $input = new Capabilities([
            new Capability('view_user', Scope::GLOBAL, ['*']),
            new Capability('view_user', Scope::PLATFORM, ['plat-123']),
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('view_user', Scope::GLOBAL, '*'));
    }

    #[Test]
    public function testShouldMergeBusinessesOfTheSameActionIntoOneItem(): void
    {
        // ARRANGE
        $input = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
            new Capability('view_user', Scope::BUSINESS, ['biz-b']),
        ]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('view_user', Scope::BUSINESS, 'biz-a'));
        $this->assertTrue($result->has('view_user', Scope::BUSINESS, 'biz-b'));
    }

    #[Test]
    public function testShouldHandleWildcardContextCorrectly(): void
    {
        // ARRANGE - platform with wildcard context should cover business with specific context
        $platformWildcard = new Capability('manage_users', Scope::PLATFORM, ['*']);
        $businessSpecific = new Capability('manage_users', Scope::BUSINESS, ['biz-a']);
        $input = new Capabilities([$platformWildcard, $businessSpecific]);

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT
        // Platform with wildcard at a less restrictive scope should cover business with specific context
        $this->assertCount(1, $result);
        $this->assertTrue($result->has('manage_users', Scope::PLATFORM, '*'));
    }

    #[Test]
    public function testShouldBeIdempotent(): void
    {
        // ARRANGE
        $global = new Capability('view_user', Scope::GLOBAL, ['*']);
        $platform = new Capability('view_user', Scope::PLATFORM, ['plat-123']);
        $business = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $input = new Capabilities([$global, $platform, $business]);

        // ACT - filter twice
        $firstPass = $this->filter->filterRestrictive($input);
        $secondPass = $this->filter->filterRestrictive($firstPass);

        // ASSERT - should produce the same result
        $this->assertCount($firstPass->count(), $secondPass);
        $this->assertTrue($secondPass->has('view_user', Scope::GLOBAL, '*'));
    }

    #[Test]
    public function testShouldNotModifyOriginalCollection(): void
    {
        // ARRANGE
        $global = new Capability('view_user', Scope::GLOBAL, ['*']);
        $business = new Capability('view_user', Scope::BUSINESS, ['biz-a']);
        $input = new Capabilities([$global, $business]);
        $originalCount = $input->count();

        // ACT
        $result = $this->filter->filterRestrictive($input);

        // ASSERT - original should remain unchanged
        $this->assertCount($originalCount, $input);
        $this->assertNotSame($input, $result);
        $this->assertTrue($input->has('view_user', Scope::GLOBAL, '*'));
        $this->assertTrue($input->has('view_user', Scope::BUSINESS, 'biz-a'));
    }
}
