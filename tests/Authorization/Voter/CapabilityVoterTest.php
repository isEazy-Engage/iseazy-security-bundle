<?php

declare(strict_types=1);

namespace Tests\Authorization\Voter;

use Iseazy\Security\Authorization\Domain\Service\AuthorizationUser;
use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Model\Capability;
use Iseazy\Security\Authorization\Domain\Model\Scope;
use Iseazy\Security\Authorization\Domain\Service\CapabilityProvider;
use Iseazy\Security\Authorization\UI\Voter\CapabilityVoter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

/**
 * Unit tests for CapabilityVoter.
 *
 * Tests the voter's ability to:
 * - Support capability attributes
 * - Parse attribute strings correctly
 * - Query CapabilityProvider and match capabilities
 * - Handle scope coverage (global covers business, etc.)
 * - Fail-closed on errors (provider unavailable, malformed attributes, etc.)
 * - Log appropriate warnings and errors
 *
 * Coverage target: >90%
 */
final class CapabilityVoterTest extends TestCase
{
    private CapabilityProvider $capabilityProvider;
    private LoggerInterface $logger;
    private CapabilityVoter $voter;

    protected function setUp(): void
    {
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->voter = new CapabilityVoter($this->capabilityProvider, $this->logger);
    }

    #[Test]
    public function testSupportsReturnsTrueForCapabilityAttribute(): void
    {
        // ARRANGE
        $attribute = 'capability:view_user@business:biz-a';

        // ACT
        $result = $this->voter->vote(
            $this->createMockToken(),
            null,
            [$attribute]
        );

        // ASSERT - voter should process this attribute (not abstain)
        $this->assertNotEquals(VoterInterface::ACCESS_ABSTAIN, $result);
    }

    #[Test]
    public function testSupportsReturnsFalseForOtherAttributes(): void
    {
        // ARRANGE
        $attribute = 'ROLE_USER';

        // ACT
        $result = $this->voter->vote(
            $this->createMockToken(),
            null,
            [$attribute]
        );

        // ASSERT - voter should abstain from non-capability attributes
        $this->assertEquals(VoterInterface::ACCESS_ABSTAIN, $result);
    }

    #[Test]
    public function testGrantsAccessWhenCapabilityMatches(): void
    {
        // ARRANGE
        $attribute = 'capability:view_user@business:biz-a';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testDeniesAccessWhenCapabilityMissing(): void
    {
        // ARRANGE
        $attribute = 'capability:edit_user@business:biz-a';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']), // Different action
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testGrantsWithCoveringScope(): void
    {
        // ARRANGE - user has global capability, attribute requests business
        $attribute = 'capability:view_user@business:biz-a';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_ADMIN']);
        $token = $this->createMockToken($user);

        $capabilities = new Capabilities([
            new Capability('view_user', Scope::GLOBAL, ['*']), // Global covers business
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_ADMIN'])
            ->willReturn($capabilities);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testDeniesWhenProviderThrowsUnavailable(): void
    {
        // ARRANGE
        $attribute = 'capability:view_user@business:biz-a';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willThrowException(new CapabilityProviderUnavailableException('database_connection_failed'));

        $this->logger
            ->expects($this->once())
            ->method('warning')
            ->with('capability_voter_provider_unavailable', $this->anything());

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - fail-closed
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testDeniesWhenProviderThrowsAnyError(): void
    {
        // ARRANGE
        $attribute = 'capability:view_user@business:biz-a';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willThrowException(new \RuntimeException('Unexpected database error'));

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_unexpected_error', $this->anything());

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - fail-closed
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    /**
     * @param array{attribute: string, expected_action: string, expected_scope: string, expected_contexts: string[]} $data
     */
    #[Test]
    #[DataProvider('validAttributeProvider')]
    public function testParsesAttributeCorrectly(
        string $attribute,
        string $expectedAction,
        string $expectedScope,
        array $expectedContexts
    ): void {
        // ARRANGE
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        // Verify parsing by checking the capability provider is called correctly
        // (implicitly tests parseAttribute internal method)
        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willReturnCallback(function ($userId, $platformId, $roles) use ($expectedAction, $expectedScope, $expectedContexts) {
                // Return a capability that matches the expected parsing
                return new Capabilities([
                    new Capability($expectedAction, Scope::from($expectedScope), $expectedContexts),
                ]);
            });

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - if parsing was correct, access should be granted
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    /**
     * @return array<string, array{attribute: string, expected_action: string, expected_scope: string, expected_contexts: string[]}>
     */
    public static function validAttributeProvider(): array
    {
        return [
            'simple_business_single_context' => [
                'attribute' => 'capability:view_user@business:biz-a',
                'expected_action' => 'view_user',
                'expected_scope' => 'business',
                'expected_contexts' => ['biz-a'],
            ],
            'global_wildcard' => [
                'attribute' => 'capability:manage_platform@global:*',
                'expected_action' => 'manage_platform',
                'expected_scope' => 'global',
                'expected_contexts' => ['*'],
            ],
            'platform_scope' => [
                'attribute' => 'capability:edit_task@platform:plat-123',
                'expected_action' => 'edit_task',
                'expected_scope' => 'platform',
                'expected_contexts' => ['plat-123'],
            ],
            'hierarchy_scope' => [
                'attribute' => 'capability:view_hierarchy@hierarchy:hier-x',
                'expected_action' => 'view_hierarchy',
                'expected_scope' => 'hierarchy',
                'expected_contexts' => ['hier-x'],
            ],
            'multiple_contexts' => [
                'attribute' => 'capability:view_user@business:biz-a,biz-b,biz-c',
                'expected_action' => 'view_user',
                'expected_scope' => 'business',
                'expected_contexts' => ['biz-a', 'biz-b', 'biz-c'],
            ],
        ];
    }

    #[Test]
    public function testHandlesMalformedAttribute(): void
    {
        // ARRANGE
        $attribute = 'capability:invalid-format-without-scope-and-context';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_malformed_attribute', ['attribute' => $attribute]);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - fail-closed
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    /**
     * @param array{attribute: string}
     */
    #[Test]
    #[DataProvider('malformedAttributeProvider')]
    public function testHandlesVariousMalformedAttributes(string $attribute): void
    {
        // ARRANGE
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_malformed_attribute', ['attribute' => $attribute]);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - fail-closed
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    /**
     * @return array<string, array{attribute: string}>
     */
    public static function malformedAttributeProvider(): array
    {
        return [
            'missing_scope_and_context' => [
                'attribute' => 'capability:view_user',
            ],
            'missing_context' => [
                'attribute' => 'capability:view_user@business',
            ],
            'missing_action' => [
                'attribute' => 'capability:@business:biz-a',
            ],
            'empty_context' => [
                'attribute' => 'capability:view_user@business:',
            ],
            'invalid_scope' => [
                'attribute' => 'capability:view_user@invalid_scope:biz-a',
            ],
            'no_prefix' => [
                'attribute' => 'view_user@business:biz-a',
            ],
        ];
    }

    #[Test]
    public function testWorksWithMultipleContextIdsInAttribute(): void
    {
        // ARRANGE - attribute requests access to multiple contexts
        $attribute = 'capability:view_user@business:biz-a,biz-b,biz-c';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        // User only has capability for biz-b
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-b']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - should grant because user has capability for at least one of the requested contexts
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testDeniesWhenUserNotAuthorizationUser(): void
    {
        // ARRANGE - user does not implement AuthorizationUser interface
        $attribute = 'capability:view_user@business:biz-a';
        $invalidUser = new \stdClass();
        $token = $this->createMockToken($invalidUser);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_user_not_authorization_user', $this->callback(function ($context) {
                return $context['attribute'] === 'capability:view_user@business:biz-a'
                    && $context['user_class'] === 'stdClass';
            }));

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - fail-closed
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testDeniesWhenUserIsNull(): void
    {
        // ARRANGE - token has null user (not authenticated)
        $attribute = 'capability:view_user@business:biz-a';
        $token = $this->createMockToken(null);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_user_not_authorization_user', $this->callback(function ($context) {
                return $context['attribute'] === 'capability:view_user@business:biz-a'
                    && $context['user_class'] === 'null';
            }));

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - fail-closed
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testDeniesWhenNoCapabilityMatchesAnyContext(): void
    {
        // ARRANGE - user has capability for different contexts
        $attribute = 'capability:view_user@business:biz-a,biz-b';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        // User has capability for completely different contexts
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-x', 'biz-y']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testGrantsWithWildcardContextInCapability(): void
    {
        // ARRANGE - user has wildcard capability
        $attribute = 'capability:view_user@business:biz-a';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_ADMIN']);
        $token = $this->createMockToken($user);

        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['*']), // Wildcard context
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_ADMIN'])
            ->willReturn($capabilities);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - wildcard should match any context
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testDeniesWhenScopeDoesNotCover(): void
    {
        // ARRANGE - user has business scope, attribute requests platform scope
        $attribute = 'capability:view_user@platform:plat-123';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        // User only has business scope (which does NOT cover platform)
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - business does not cover platform
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testGrantsWhenEmptyCapabilitiesCollection(): void
    {
        // ARRANGE - user has no capabilities
        $attribute = 'capability:view_user@business:biz-a';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $token = $this->createMockToken($user);

        $capabilities = Capabilities::empty();

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT
        $result = $this->voter->vote($token, null, [$attribute]);

        // ASSERT - no capabilities means no access
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testVoterConstructorWithDefaultLogger(): void
    {
        // ARRANGE - create voter without logger (should use NullLogger)
        $voter = new CapabilityVoter($this->capabilityProvider);

        // ACT & ASSERT - should not throw exception
        $this->assertInstanceOf(CapabilityVoter::class, $voter);
    }

    #[Test]
    public function testAttributePrefixConstantIsCorrect(): void
    {
        // ASSERT
        $this->assertEquals('capability:', CapabilityVoter::ATTRIBUTE_PREFIX);
    }

    // ========== Helper Methods ==========

    /**
     * Creates a mock TokenInterface with an optional user.
     *
     * @param AuthorizationUser|object|null $user The user to return from getUser()
     *
     * @return TokenInterface
     */
    private function createMockToken(mixed $user = null): TokenInterface
    {
        $token = $this->createMock(TokenInterface::class);
        $token->method('getUser')->willReturn($user);

        return $token;
    }

    /**
     * Creates a mock AuthorizationUser.
     *
     * @param string $userId The user ID to return
     * @param string $platformId The platform ID to return
     * @param string[] $roles The roles to return
     *
     * @return AuthorizationUser
     */
    private function createMockAuthorizationUser(string $userId, string $platformId, array $roles): AuthorizationUser
    {
        $user = $this->createMock(AuthorizationUser::class);
        $user->method('userId')->willReturn($userId);
        $user->method('platformId')->willReturn($platformId);
        $user->method('roles')->willReturn($roles);

        return $user;
    }
}
