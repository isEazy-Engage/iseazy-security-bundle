<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Service;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Contract for user objects that can be authorized via the CapabilityVoter.
 *
 * This interface defines the minimum information required from a user object
 * to perform capability-based authorization. Each consuming microservice must
 * ensure their User entity (or User adapter) implements this interface.
 *
 * The interface is intentionally minimal and decoupled from any specific
 * authentication mechanism or user storage implementation, making the voter
 * portable across different microservices.
 *
 * Example implementation:
 * ```php
 * final readonly class User implements AuthorizationUser
 * {
 *     public function userId(): string
 *     {
 *         return $this->id;
 *     }
 *
 *     public function platformId(): string
 *     {
 *         return $this->platform;
 *     }
 *
 *     public function roles(): array
 *     {
 *         return $this->userRoles;
 *     }
 * }
 * ```
 */
interface AuthorizationUser extends UserInterface
{
    /**
     * Returns the unique identifier of the user.
     *
     * This is typically a UUID extracted from the JWT token.
     *
     * @return string The user's unique identifier
     */
    public function userId(): string;

    /**
     * Returns the unique identifier of the platform context.
     *
     * This represents the platform/tenant scope in which the user operates.
     * Typically a UUID extracted from the JWT token or user entity.
     *
     * @return string The platform's unique identifier
     */
    public function platformId(): string;

    /**
     * Returns the roles assigned to this user.
     *
     * These roles can be used by CapabilityProvider implementations to
     * optimize capability resolution or apply role-based filtering.
     *
     * Examples: ['ROLE_USER', 'ROLE_PLATFORM_MANAGER', 'ROLE_ADMIN']
     *
     * @return string[] Array of role identifiers
     */
    public function roles(): array;
}
