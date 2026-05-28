<?php

declare(strict_types=1);

namespace Iseazy\Security\Tests\Authorization\Exception;

use Iseazy\Security\Authorization\Exception\CapabilityProviderUnavailableException;
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
     * Tests that CapabilityProviderUnavailableException can be instantiated and thrown.
     *
     * This test validates:
     * - The exception can be created with a message
     * - The exception can be thrown and caught
     * - The exception message is preserved
     */
    public function testCapabilityProviderUnavailableExceptionCanBeInstantiatedAndThrown(): void
    {
        // ARRANGE
        $message = 'capability_provider_unavailable';

        // ACT & ASSERT
        $this->expectException(CapabilityProviderUnavailableException::class);
        $this->expectExceptionMessage($message);

        throw new CapabilityProviderUnavailableException($message);
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
        $exception = new CapabilityProviderUnavailableException('capability_provider_unavailable');

        // ACT & ASSERT
        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    /**
     * Tests that the exception can wrap a previous exception.
     *
     * This test validates:
     * - The exception supports the $previous parameter
     * - The previous exception is preserved in the chain
     */
    public function testCapabilityProviderUnavailableExceptionCanWrapPreviousException(): void
    {
        // ARRANGE
        $previousException = new RuntimeException('database_connection_failed');

        // ACT
        $exception = new CapabilityProviderUnavailableException(
            'capability_provider_unavailable',
            0,
            $previousException
        );

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
     */
    public function testCapabilityProviderUnavailableExceptionCanBeCaughtAndInspected(): void
    {
        // ARRANGE
        $message = 'capability_provider_unavailable';
        $code = 500;
        $caughtException = null;

        // ACT
        try {
            throw new CapabilityProviderUnavailableException($message, $code);
        } catch (CapabilityProviderUnavailableException $exception) {
            $caughtException = $exception;
        }

        // ASSERT
        $this->assertNotNull($caughtException);
        $this->assertSame($message, $caughtException->getMessage());
        $this->assertSame($code, $caughtException->getCode());
    }
}
