<?php

declare(strict_types=1);

namespace Iseazy\Security\Tests\Authorization\Domain\Exception;

use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Tests for CapabilityProviderUnavailableException.
 *
 * These tests verify that the exception can be instantiated, thrown,
 * caught, and that it maintains the correct inheritance chain.
 */
final class CapabilityProviderUnavailableExceptionTest extends TestCase
{
    /**
     * Tests that CapabilityProviderUnavailableException can be instantiated and thrown using named constructor.
     *
     * This test validates:
     * - The exception can be created with unavailable() named constructor
     * - The exception can be thrown and caught
     * - The exception message is always snake_case
     */
    public function testCapabilityProviderUnavailableExceptionCanBeInstantiatedAndThrown(): void
    {
        // ARRANGE
        $expectedMessage = 'capability_provider_unavailable';

        // ACT & ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);
        $this->expectExceptionMessage($expectedMessage);

        throw CapabilityProviderUnavailableException::unavailable();
    }

    /**
     * Tests that the exception extends RuntimeException.
     *
     * This test validates:
     * - The exception is a RuntimeException
     * - The exception can be caught as RuntimeException
     */
    public function testCapabilityProviderUnavailableExceptionExtendsRuntimeException(): void
    {
        // ARRANGE
        $exception = CapabilityProviderUnavailableException::unavailable();

        // ACT & ASSERT
        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    /**
     * Tests that the exception can wrap a previous exception using named constructor.
     *
     * This test validates:
     * - The exception supports the $previous parameter in named constructor
     * - The previous exception is preserved in the chain
     */
    public function testCapabilityProviderUnavailableExceptionCanWrapPreviousException(): void
    {
        // ARRANGE
        $previousException = new RuntimeException('database_connection_failed');

        // ACT
        $exception = CapabilityProviderUnavailableException::unavailable($previousException);

        // ASSERT
        $this->assertSame($previousException, $exception->getPrevious());
        $this->assertSame('database_connection_failed', $exception->getPrevious()->getMessage());
    }

    /**
     * Tests that the exception can be caught and inspected.
     *
     * This test validates:
     * - The exception can be caught in a try-catch block
     * - Exception properties are accessible after catching
     * - Message is always snake_case from named constructor
     */
    public function testCapabilityProviderUnavailableExceptionCanBeCaughtAndInspected(): void
    {
        // ARRANGE
        $expectedMessage = 'capability_provider_unavailable';
        $caughtException = null;

        // ACT
        try {
            throw CapabilityProviderUnavailableException::unavailable();
        } catch (CapabilityProviderUnavailableException $exception) {
            $caughtException = $exception;
        }

        // ASSERT
        $this->assertNotNull($caughtException);
        $this->assertSame($expectedMessage, $caughtException->getMessage());
        $this->assertSame(0, $caughtException->getCode());
    }
}
