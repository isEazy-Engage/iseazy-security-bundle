<?php

declare(strict_types=1);

namespace Iseazy\Security\Tests\Authorization\Port;

use Iseazy\Security\Authorization\Model\Capabilities;
use Iseazy\Security\Authorization\Port\CapabilityProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for CapabilityProvider interface.
 *
 * These tests verify that the CapabilityProvider interface can be implemented
 * and that mock implementations work correctly for testing purposes.
 */
final class CapabilityProviderTest extends TestCase
{
    /**
     * Tests that a dummy implementation of CapabilityProvider can be created
     * and returns an empty Capabilities collection.
     *
     * This test validates:
     * - The interface can be implemented
     * - A minimal implementation can return Capabilities::empty()
     * - The method signature is correct
     */
    public function testCapabilityProviderInterfaceCanBeImplementedAndReturnsEmptyCapabilities(): void
    {
        // ARRANGE
        $provider = new class implements CapabilityProvider {
            public function getUserCapabilities(string $userId, string $platformId, array $roles = []): Capabilities
            {
                return Capabilities::empty();
            }
        };

        // ACT
        $capabilities = $provider->getUserCapabilities(
            '550e8400-e29b-41d4-a716-446655440000',
            '660e8400-e29b-41d4-a716-446655440000',
            ['ROLE_USER']
        );

        // ASSERT
        $this->assertInstanceOf(Capabilities::class, $capabilities);
        $this->assertTrue($capabilities->isEmpty());
        $this->assertSame(0, $capabilities->count());
    }

    /**
     * Tests that a mock implementation can return non-empty Capabilities.
     *
     * This test validates:
     * - The interface supports returning populated Capabilities
     * - Mock implementations can be used in tests
     */
    public function testCapabilityProviderInterfaceCanReturnNonEmptyCapabilities(): void
    {
        // ARRANGE
        $expectedCapabilities = Capabilities::fromArray([
            [
                'capability' => 'view_user',
                'scope' => 'global',
                'context' => ['*'],
            ],
        ]);

        $provider = new class($expectedCapabilities) implements CapabilityProvider {
            public function __construct(private readonly Capabilities $capabilities)
            {
            }

            public function getUserCapabilities(string $userId, string $platformId, array $roles = []): Capabilities
            {
                return $this->capabilities;
            }
        };

        // ACT
        $capabilities = $provider->getUserCapabilities(
            '550e8400-e29b-41d4-a716-446655440000',
            '660e8400-e29b-41d4-a716-446655440000',
            ['ROLE_USER']
        );

        // ASSERT
        $this->assertInstanceOf(Capabilities::class, $capabilities);
        $this->assertFalse($capabilities->isEmpty());
        $this->assertSame(1, $capabilities->count());
    }
}
