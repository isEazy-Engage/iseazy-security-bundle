<?php

declare(strict_types=1);

namespace Tests\Authorization\Voter;

use Iseazy\Security\Authorization\Domain\Service\AuthorizationUser;
use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Model\Capability;
use Iseazy\Security\Authorization\Domain\Model\Scope;
use Iseazy\Security\Authorization\Domain\Service\CapabilityProvider;
use Iseazy\Security\Authorization\Domain\Service\InternalServiceUser;
use Iseazy\Security\Authorization\UI\Voter\CapabilityVoter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class CapabilityVoterTest extends TestCase
{
    private CapabilityProvider $capabilityProvider;
    private LoggerInterface $logger;
    private CapabilityVoter $voter;

    protected function setUp(): void
    {
        $this->capabilityProvider = $this->createStub(CapabilityProvider::class);
        $this->logger = $this->createStub(LoggerInterface::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );
    }

    #[Test]
    public function testSupportsReturnsTrueForCapabilityAttribute(): void
    {
        $result = $this->voter->vote(
            $this->createMockToken(),
            null,
            ['capability:view_user@business:biz-a']
        );

        $this->assertNotEquals(VoterInterface::ACCESS_ABSTAIN, $result);
    }

    #[Test]
    public function testSupportsReturnsFalseForOtherAttributes(): void
    {
        $result = $this->voter->vote(
            $this->createMockToken(),
            null,
            ['ROLE_USER']
        );

        $this->assertEquals(VoterInterface::ACCESS_ABSTAIN, $result);
    }

    #[Test]
    public function testGrantsAccessWhenCapabilityMatches(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:view_user@business:biz-a']);
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testDeniesAccessWhenCapabilityMissing(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:edit_user@business:biz-a']);
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testGrantsWithCoveringScope(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_ADMIN']);
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::GLOBAL, ['*']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_ADMIN'])
            ->willReturn($capabilities);

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:view_user@business:biz-a']);
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testDeniesWhenProviderThrowsUnavailable(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willThrowException(new CapabilityProviderUnavailableException('database_connection_failed'));

        $this->logger
            ->expects($this->once())
            ->method('warning')
            ->with('capability_voter_provider_unavailable', $this->anything());

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:view_user@business:biz-a']);
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testDeniesWhenProviderThrowsAnyError(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willThrowException(new \RuntimeException('Unexpected database error'));

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_unexpected_error', $this->anything());

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:view_user@business:biz-a']);
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
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->willReturnCallback(function ($userId, $platformId, $roles) use ($expectedAction, $expectedScope, $expectedContexts) {
                return new Capabilities([
                    new Capability($expectedAction, Scope::from($expectedScope), $expectedContexts),
                ]);
            });

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, [$attribute]);
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
                'expectedAction' => 'view_user',
                'expectedScope' => 'business',
                'expectedContexts' => ['biz-a'],
            ],
            'global_wildcard' => [
                'attribute' => 'capability:manage_platform@global:*',
                'expectedAction' => 'manage_platform',
                'expectedScope' => 'global',
                'expectedContexts' => ['*'],
            ],
            'platform_scope' => [
                'attribute' => 'capability:edit_task@platform:plat-123',
                'expectedAction' => 'edit_task',
                'expectedScope' => 'platform',
                'expectedContexts' => ['plat-123'],
            ],
            'hierarchy_scope' => [
                'attribute' => 'capability:view_hierarchy@hierarchy:hier-x',
                'expectedAction' => 'view_hierarchy',
                'expectedScope' => 'hierarchy',
                'expectedContexts' => ['hier-x'],
            ],
            'multiple_contexts' => [
                'attribute' => 'capability:view_user@business:biz-a,biz-b,biz-c',
                'expectedAction' => 'view_user',
                'expectedScope' => 'business',
                'expectedContexts' => ['biz-a', 'biz-b', 'biz-c'],
            ],
        ];
    }

    #[Test]
    public function testHandlesMalformedAttribute(): void
    {
        // ARRANGE
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $attribute = 'capability:invalid-format-without-scope-and-context';
        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_malformed_attribute', ['attribute' => $attribute]);

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, [$attribute]);
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
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_malformed_attribute', ['attribute' => $attribute]);

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, [$attribute]);
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
        ];
    }

    #[Test]
    public function testWorksWithMultipleContextIdsInAttribute(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-b']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:view_user@business:biz-a,biz-b,biz-c']);
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testDeniesWhenUserNotAuthorizationUser(): void
    {
        // ARRANGE
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $attribute = 'capability:view_user@business:biz-a';
        $invalidUser = $this->createStub(UserInterface::class);

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_user_not_authorization_user', $this->callback(function ($context) use ($attribute) {
                return $context['attribute'] === $attribute
                    && isset($context['user_class']);
            }));

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($invalidUser), null, [$attribute]);
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testDeniesWhenUserIsNull(): void
    {
        // ARRANGE
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with('capability_voter_user_not_authorization_user', $this->callback(function ($context) {
                return $context['attribute'] === 'capability:view_user@business:biz-a'
                    && $context['user_class'] === 'null';
            }));

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken(null), null, ['capability:view_user@business:biz-a']);
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testDeniesWhenNoCapabilityMatchesAnyContext(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-x', 'biz-y']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:view_user@business:biz-a,biz-b']);
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testGrantsWithWildcardContextInCapability(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_ADMIN']);
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['*']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_ADMIN'])
            ->willReturn($capabilities);

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:view_user@business:biz-a']);
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testDeniesWhenScopeDoesNotCover(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $capabilities = new Capabilities([
            new Capability('view_user', Scope::BUSINESS, ['biz-a']),
        ]);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn($capabilities);

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:view_user@platform:plat-123']);
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testDeniesWhenEmptyCapabilitiesCollection(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);

        $this->capabilityProvider
            ->expects($this->once())
            ->method('capabilities')
            ->with('user-123', 'plat-456', ['ROLE_USER'])
            ->willReturn(Capabilities::empty());

        // ACT & ASSERT
        $result = $this->voter->vote($this->createMockToken($user), null, ['capability:view_user@business:biz-a']);
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $result);
    }

    #[Test]
    public function testGrantsAccessWithUppercaseScopeInAttribute(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $user = $this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER']);
        $this->capabilityProvider->expects($this->once())
            ->method('capabilities')
            ->willReturn(new Capabilities([new Capability('view_user', Scope::BUSINESS, ['biz-a'])]));

        // ACT — scope en mayúsculas, el regex acepta esto por el flag /i
        $result = $this->voter->vote(
            $this->createMockToken($user),
            null,
            ['capability:view_user@BUSINESS:biz-a']
        );

        // ASSERT
        $this->assertSame(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testInternalServiceUserBypassIsLogged(): void
    {
        // ARRANGE
        $this->logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        $this->logger->expects($this->once())
            ->method('debug')
            ->with(
                'capability_voter_internal_service_granted',
                ['attribute' => 'capability:admin@global:*']
            );
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $serviceUser = $this->createStub(InternalServiceUser::class);

        // ACT
        $this->voter->vote(
            $this->createMockToken($serviceUser),
            null,
            ['capability:admin@global:*']
        );
    }

    #[Test]
    public function testGrantsAccessToInternalServiceUserWithoutCheckingCapabilities(): void
    {
        // ARRANGE
        $this->capabilityProvider = $this->createMock(CapabilityProvider::class);
        $this->voter = new CapabilityVoter(
            capabilityProvider: $this->capabilityProvider,
            logger: $this->logger,
        );

        $serviceUser = $this->createStub(InternalServiceUser::class);

        $this->capabilityProvider
            ->expects($this->never())
            ->method('capabilities');

        // ACT & ASSERT
        $result = $this->voter->vote(
            $this->createMockToken($serviceUser),
            null,
            ['capability:view_user@business:biz-a']
        );
        $this->assertSame(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testVoterConstructorWithDefaultLogger(): void
    {
        $voter = new CapabilityVoter(capabilityProvider: $this->capabilityProvider);
        $this->assertInstanceOf(CapabilityVoter::class, $voter);
    }

    #[Test]
    public function testGrantsAccessWhenProviderIsNull(): void
    {
        // ARRANGE — simulates authorization.enabled: false (no CapabilityProvider registered)
        $voter = new CapabilityVoter(capabilityProvider: null);

        // ACT & ASSERT
        $result = $voter->vote(
            $this->createMockToken($this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER'])),
            null,
            ['capability:view_user@business:biz-a']
        );
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testGrantsAccessWhenVoterDisabledWithExistingProvider(): void
    {
        // ARRANGE — authorization.enabled: true but authorization.voter_enabled: false
        // Capabilities infrastructure is up, but enforcement is bypassed
        $provider = $this->createMock(CapabilityProvider::class);
        $provider->expects($this->never())->method('capabilities');

        $voter = new CapabilityVoter(capabilityProvider: $provider, voterEnabled: false);

        // ACT & ASSERT
        $result = $voter->vote(
            $this->createMockToken($this->createMockAuthorizationUser('user-123', 'plat-456', ['ROLE_USER'])),
            null,
            ['capability:view_user@business:biz-a']
        );
        $this->assertEquals(VoterInterface::ACCESS_GRANTED, $result);
    }

    #[Test]
    public function testAttributePrefixConstantIsCorrect(): void
    {
        $this->assertEquals('capability:', CapabilityVoter::ATTRIBUTE_PREFIX);
    }

    // ========== Helper Methods ==========

    private function createMockToken(mixed $user = null): TokenInterface
    {
        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($user);

        return $token;
    }

    private function createMockAuthorizationUser(string $userId, string $platformId, array $roles): AuthorizationUser
    {
        $user = $this->createStub(AuthorizationUser::class);
        $user->method('userId')->willReturn($userId);
        $user->method('platformId')->willReturn($platformId);
        $user->method('getRoles')->willReturn($roles);

        return $user;
    }
}
