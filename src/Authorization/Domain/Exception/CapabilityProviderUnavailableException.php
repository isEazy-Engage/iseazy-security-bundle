<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Exception;

use RuntimeException;

/**
 * Exception thrown when a CapabilityProvider cannot retrieve user capabilities.
 *
 * This exception implements a fail-closed security model: when the capability
 * provider cannot determine capabilities with certainty (e.g., database connection
 * failure, HTTP timeout, invalid response from remote service), it MUST throw this
 * exception rather than returning an empty or partial set of capabilities.
 *
 * Fail-closed ensures that users are denied access when the authorization system
 * cannot make a confident decision, preventing potential security vulnerabilities
 * from temporary failures or degraded services.
 *
 * Common scenarios that should trigger this exception:
 * - Database connection failures in DatabaseCapabilityProvider
 * - HTTP timeouts or 5xx errors in HttpCapabilityProvider
 * - Invalid or malformed responses from remote capability services
 * - Cache failures when cache is the primary source
 * - Any other condition where capability determination is unreliable
 *
 * Example usage:
 * ```php
 * throw CapabilityProviderUnavailableException::unavailable(
 *     previous: $httpException
 * );
 * ```
 */
final class CapabilityProviderUnavailableException extends RuntimeException
{
    /**
     * Creates exception for when capability provider cannot determine capabilities.
     *
     * @param \Throwable|null $previous The underlying exception that caused the failure
     *
     * @return self
     */
    public static function unavailable(?\Throwable $previous = null): self
    {
        return new self(
            message: 'capability_provider_unavailable',
            code: 0,
            previous: $previous
        );
    }
}
