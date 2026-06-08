<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\UI\Voter;

use Iseazy\Security\Authorization\Domain\Service\AuthorizationUser;
use Iseazy\Security\Authorization\Domain\Exception\CapabilityProviderUnavailableException;
use Iseazy\Security\Authorization\Domain\Model\Scope;
use Iseazy\Security\Authorization\Domain\Service\CapabilityProvider;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Throwable;

/**
 * Symfony Voter that validates capability-based authorization attributes.
 *
 * This voter handles attributes of the format: 'capability:{action}@{scope}:{context}'
 * where:
 * - {action} is the capability action (e.g., 'view_user', 'edit_task')
 * - {scope} is the scope level ('global', 'platform', 'business', 'hierarchy')
 * - {context} is a comma-separated list of context IDs (e.g., 'biz-a', 'biz-a,biz-b')
 *
 * The voter queries the CapabilityProvider to fetch the user's capabilities
 * and checks if any capability matches the requested action, scope, and context.
 *
 * Security Model: FAIL-CLOSED
 * - If the CapabilityProvider is unavailable → DENY access (log warning)
 * - If any other error occurs → DENY access (log error)
 * - If the attribute is malformed → DENY access (log error)
 * - If the user doesn't implement AuthorizationUser → DENY access (log error)
 *
 * Example usage in controllers:
 * ```php
 * $this->denyAccessUnlessGranted('capability:view_user@business:biz-123');
 * $this->denyAccessUnlessGranted('capability:edit_task@platform:plat-456');
 * $this->denyAccessUnlessGranted('capability:manage_business@global:*');
 * ```
 *
 * Scope Coverage:
 * The voter delegates scope coverage logic to the Capability::matches() method.
 * For example, if a user has 'view_user@global:*', they are automatically granted
 * 'view_user@business:biz-a' because GLOBAL scope covers BUSINESS scope.
 */
final class CapabilityVoter extends Voter
{
    public const ATTRIBUTE_PREFIX = 'capability:';

    /**
     * Regex pattern for parsing capability attributes.
     *
     * Format: capability:{action}@{scope}:{context1,context2,...}
     * - action: alphanumeric with underscores
     * - scope: global|platform|business|hierarchy
     * - context: comma-separated alphanumeric IDs with hyphens, underscores, or wildcard (*)
     */
    private const ATTRIBUTE_PATTERN = '/^capability:([a-z_]+)@(global|platform|business|hierarchy):(.+)$/i';

    public function __construct(
        private readonly CapabilityProvider $capabilityProvider,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    /**
     * Determines if this voter supports the given attribute.
     *
     * Returns true only if the attribute is a string starting with 'capability:'.
     * The subject is ignored as capability authorization is user-based, not resource-based
     * (the resource context is encoded in the attribute itself).
     *
     * @param string $attribute The security attribute to check
     * @param mixed $subject The subject being voted on (ignored)
     *
     * @return bool True if the attribute starts with 'capability:'
     */
    protected function supports(string $attribute, mixed $subject): bool
    {
        return str_starts_with($attribute, self::ATTRIBUTE_PREFIX);
    }

    /**
     * Performs the actual authorization check for the capability attribute.
     *
     * Algorithm:
     * 1. Parse the attribute to extract action, scope, and contextIds
     * 2. Extract userId, platformId, and roles from the security token
     * 3. Query the CapabilityProvider for the user's capabilities
     * 4. Check if any capability matches the requested action, scope, and ANY of the contextIds
     * 5. Return true if a match is found, false otherwise
     *
     * Error Handling (FAIL-CLOSED):
     * - CapabilityProviderUnavailableException → log WARNING, return false
     * - Any other Throwable → log ERROR, return false
     * - Malformed attribute → log ERROR, return false
     * - User not AuthorizationUser → log ERROR, return false
     *
     * @param string $attribute The capability attribute to check
     * @param mixed $subject The subject (ignored)
     * @param TokenInterface $token The security token containing the user
     *
     * @return bool True if access is granted, false otherwise
     */
    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        try {
            // Parse the attribute to extract action, scope, and context IDs
            $parsed = $this->parseAttribute($attribute);
            if ($parsed === null) {
                $this->logger->error('capability_voter_malformed_attribute', ['attribute' => $attribute]);
                return false;
            }

            ['action' => $action, 'scope' => $scope, 'contextIds' => $contextIds] = $parsed;

            // Extract user information from token
            $user = $token->getUser();
            if (!$user instanceof AuthorizationUser) {
                $this->logger->error('capability_voter_user_not_authorization_user', [
                    'attribute' => $attribute,
                    'user_class' => $user === null ? 'null' : $user::class,
                ]);
                return false;
            }

            // Query the capability provider for user's capabilities
            $capabilities = $this->capabilityProvider->capabilities(
                $user->userId(),
                $user->platformId(),
                $user->getRoles()
            );

            // Check if any capability matches the requested action, scope, and any of the context IDs
            foreach ($capabilities as $capability) {
                foreach ($contextIds as $contextId) {
                    if ($capability->matches($action, $scope, $contextId)) {
                        return true;
                    }
                }
            }

            // No matching capability found
            return false;
        } catch (CapabilityProviderUnavailableException $e) {
            // Fail-closed: capability provider is unavailable, deny access
            $this->logger->warning('capability_voter_provider_unavailable', [
                'attribute' => $attribute,
                'exception' => $e->getMessage(),
            ]);
            return false;
        } catch (Throwable $e) {
            // Fail-closed: unexpected error, deny access
            $this->logger->error('capability_voter_unexpected_error', [
                'attribute' => $attribute,
                'exception' => $e->getMessage(),
                'exception_class' => $e::class,
            ]);
            return false;
        }
    }

    /**
     * Parses a capability attribute into its components.
     *
     * Expected format: 'capability:{action}@{scope}:{context1,context2,...}'
     *
     * @param string $attribute The attribute to parse
     *
     * @return array{action: string, scope: Scope, contextIds: string[]}|null
     *         Returns null if parsing fails or scope is invalid
     */
    private function parseAttribute(string $attribute): ?array
    {
        if (preg_match(self::ATTRIBUTE_PATTERN, $attribute, $matches) !== 1) {
            return null;
        }

        $action = $matches[1];
        $scopeValue = strtolower($matches[2]);
        $contextString = $matches[3];

        // Parse scope enum
        try {
            $scope = Scope::from($scopeValue);
        } catch (\ValueError) {
            return null;
        }

        // Parse context IDs (comma-separated)
        $contextIds = array_filter(
            array_map('trim', explode(',', $contextString)),
            static fn(string $id): bool => $id !== ''
        );

        if ($contextIds === []) {
            return null;
        }

        return [
            'action' => $action,
            'scope' => $scope,
            'contextIds' => array_values($contextIds), // Reindex after filter
        ];
    }
}
