<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Service;

/**
 * Port interface for providing JWT tokens from the current authentication context.
 *
 * This interface defines the contract for JWT token providers that extract the
 * JWT token from the current request or security context. Different implementations
 * can provide tokens from various sources (Symfony TokenStorage, request headers,
 * session, etc.).
 *
 * Implementations are environment-specific and reside in the Infrastructure layer
 * of the consuming application, not in this bundle.
 *
 * Example implementation (in consuming app):
 * ```php
 * final class SymfonyJwtProvider implements JwtProvider
 * {
 *     public function __construct(
 *         private readonly TokenStorageInterface $tokenStorage,
 *     ) {}
 *
 *     public function currentJwt(): ?string
 *     {
 *         $token = $this->tokenStorage->getToken();
 *         if ($token === null) {
 *             return null;
 *         }
 *
 *         return $token->getCredentials(); // or extract from attributes
 *     }
 * }
 * ```
 */
interface JwtProvider
{
    /**
     * Returns the JWT token of the currently authenticated user.
     *
     * This method extracts the JWT token from the current authentication context
     * (e.g., Symfony TokenStorage, request headers, session). It returns null if
     * no authentication is present (anonymous request).
     *
     * The returned token is the raw JWT string (without "Bearer " prefix).
     *
     * @return string|null The raw JWT token, or null if not authenticated
     */
    public function currentJwt(): ?string;
}
