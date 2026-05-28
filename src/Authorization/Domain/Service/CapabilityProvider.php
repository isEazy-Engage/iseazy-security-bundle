<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Service;

use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use Iseazy\Security\Authorization\Domain\Model\Capabilities;

/**
 * Port interface for providing user capabilities from different sources.
 *
 * This interface defines the contract for capability providers that fetch
 * user capabilities from various sources (database, HTTP API, cache, etc.).
 *
 * Implementations must follow a fail-closed security model: if capabilities
 * cannot be determined with certainty, the provider MUST throw an exception
 * rather than returning an empty or partial set of capabilities.
 *
 * Example implementations:
 * - DatabaseCapabilityProvider: Fetches capabilities from local database (Platform microservice)
 * - HttpCapabilityProvider: Fetches capabilities from Platform API (Task/Supervisor microservices)
 */
interface CapabilityProvider
{
    /**
     * Retrieves the capabilities for a given user in a specific platform context.
     *
     * This method fetches all capabilities that the user has in the given platform.
     * The roles parameter is optional and can be used by implementations to optimize
     * capability resolution or apply role-based filtering.
     *
     * FAIL-CLOSED CONTRACT:
     * Implementations MUST throw CapabilityProviderUnavailableException if they cannot
     * determine capabilities with certainty (e.g., database connection failure, HTTP
     * timeout, invalid response). Returning an empty Capabilities set MUST only be done
     * when the provider is certain that the user genuinely has no capabilities.
     *
     * @param string $userId The unique identifier of the user (typically UUID from JWT)
     * @param string $platformId The unique identifier of the platform context (UUID)
     * @param array<string> $roles Optional array of user roles from JWT (e.g., ['ROLE_USER', 'ROLE_PLATFORM_MANAGER'])
     *
     * @return Capabilities The collection of capabilities the user has in this platform
     *
     * @throws CapabilityProviderUnavailableException If capabilities cannot be determined (fail-closed)
     */
    public function getUserCapabilities(string $userId, string $platformId, array $roles = []): Capabilities;
}
