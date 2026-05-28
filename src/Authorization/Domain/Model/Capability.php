<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Model;

use Iseazy\Security\Authorization\Domain\Exception\InvalidCapabilityException;

/**
 * Value Object representing a capability with an action, scope, and context.
 *
 * A capability defines what action can be performed, at what scope level,
 * and in which contexts. It is immutable and validates all invariants on construction.
 *
 * Invariants:
 * - Action cannot be empty
 * - Context cannot be empty
 * - If scope is GLOBAL, context must be exactly ['*']
 * - Context is automatically deduplicated and reindexed
 *
 * Example:
 * ```php
 * $cap = new Capability('view_user', Scope::BUSINESS, ['biz-a', 'biz-b']);
 * echo $cap->toString(); // 'view_user@business:biz-a,biz-b'
 * ```
 */
final readonly class Capability
{
    /** @var string[] Deduplicated and reindexed context identifiers */
    private array $context;

    /**
     * Creates a new Capability instance.
     *
     * @param string $action The action name (cannot be empty)
     * @param Scope $scope The scope level
     * @param string[] $context Array of context identifiers (cannot be empty)
     *
     * @throws InvalidCapabilityException If action is empty
     * @throws InvalidCapabilityException If context is empty
     * @throws InvalidCapabilityException If scope is GLOBAL and context is not ['*']
     */
    public function __construct(
        private string $action,
        private Scope $scope,
        array $context,
    ) {
        if ($action === '') {
            throw new InvalidCapabilityException('action_cannot_be_empty');
        }

        if ($context === []) {
            throw new InvalidCapabilityException('context_cannot_be_empty');
        }

        if ($scope === Scope::GLOBAL && $context !== ['*']) {
            throw new InvalidCapabilityException('global_scope_requires_wildcard_context');
        }

        // Deduplicate and reindex context
        $this->context = array_values(array_unique($context));
    }

    /**
     * Returns the action name.
     *
     * @return string The action name
     */
    public function action(): string
    {
        return $this->action;
    }

    /**
     * Returns the scope level.
     *
     * @return Scope The scope
     */
    public function scope(): Scope
    {
        return $this->scope;
    }

    /**
     * Returns the context identifiers.
     *
     * @return string[] Deduplicated array of context identifiers
     */
    public function context(): array
    {
        return $this->context;
    }

    /**
     * Returns the canonical string representation of this capability.
     *
     * Format: {action}@{scope}:{context0,context1,...}
     *
     * Example: 'view_user@business:biz-a,biz-b'
     *
     * @return string The canonical string representation
     */
    public function toString(): string
    {
        return sprintf('%s@%s:%s', $this->action, $this->scope->value, implode(',', $this->context));
    }

    /**
     * Converts the capability to a PSR-6 compatible cache key format.
     *
     * Replaces @ with ___ (triple underscore) and : and , with __ (double underscore)
     * to ensure compatibility with PSR-6 cache key restrictions.
     *
     * Format: action___scope__ctx1__ctx2
     *
     * Example: 'view_user@business:biz-a,biz-b' → 'view_user___business__biz-a__biz-b'
     *
     * @see R-006 in TECHNICAL_ANALYSIS.md
     *
     * @return string The PSR-6 compatible cache key
     */
    public function toPsr6Key(): string
    {
        return sprintf('%s___%s__%s', $this->action, $this->scope->value, implode('__', $this->context));
    }

    /**
     * Checks if this capability authorizes the given action on the given resource.
     *
     * This method is used by the CapabilityVoter to determine if a capability
     * grants access to perform a specific action on a specific resource.
     *
     * The capability matches if:
     * 1. The action names are identical
     * 2. This capability's scope covers the requested scope (via Scope::covers())
     * 3. The contextId is in this capability's context array OR context contains '*'
     *
     * @param string $action The action to check
     * @param Scope $scope The scope level to check
     * @param string $contextId The context identifier to check
     *
     * @return bool True if this capability authorizes the operation
     */
    public function matches(string $action, Scope $scope, string $contextId): bool
    {
        if ($this->action !== $action) {
            return false;
        }

        if (!$this->scope->covers($scope)) {
            return false;
        }

        // If the scope covers the requested one, check if context contains '*' or the specific contextId
        return in_array('*', $this->context, true) || in_array($contextId, $this->context, true);
    }

    /**
     * Checks if this capability covers (subsumes) another capability.
     *
     * A capability covers another if:
     * 1. They have the same action
     * 2. This capability's scope covers the other's scope (via Scope::covers())
     * 3. This capability's context covers the other's context:
     *    - Either this context contains '*' (wildcard)
     *    - Or this context is a superset of the other's context
     *
     * This implements the "least restrictive capability wins" rule (BR-CAP-008).
     *
     * @param self $other The capability to check coverage against
     *
     * @return bool True if this capability covers the other
     */
    public function covers(self $other): bool
    {
        return $this->action === $other->action
            && $this->scope->covers($other->scope)
            && (in_array('*', $this->context, true)
                || array_diff($other->context, $this->context) === []);
    }

    /**
     * Checks if this capability is less restrictive than another capability.
     *
     * A capability is less restrictive than another if:
     * 1. They have the same action
     * 2. This capability's scope is less restrictive than the other's scope
     *
     * This does NOT consider context - only action and scope hierarchy.
     *
     * @param self $other The capability to compare against
     *
     * @return bool True if this capability is less restrictive
     */
    public function isLessRestrictiveThan(self $other): bool
    {
        return $this->action === $other->action
            && $this->scope->isLessRestrictiveThan($other->scope);
    }

    /**
     * Merges this capability with another by combining their contexts.
     *
     * This method is immutable - it returns a new Capability instance with
     * the combined contexts. The original capabilities are not modified.
     *
     * The capabilities must have the same action and scope to be mergeable.
     * The resulting capability will have all unique context identifiers from both.
     *
     * @param self $other The capability to merge with
     *
     * @return self A new Capability with merged contexts
     *
     * @throws InvalidCapabilityException If actions differ
     * @throws InvalidCapabilityException If scopes differ
     */
    public function merge(self $other): self
    {
        if ($this->action !== $other->action || $this->scope !== $other->scope) {
            throw new InvalidCapabilityException('cannot_merge_different_action_or_scope');
        }

        // Constructor will deduplicate and reindex
        return new self($this->action, $this->scope, array_merge($this->context, $other->context));
    }

    /**
     * Converts this capability to an array representation.
     *
     * Returns an array with keys:
     * - 'capability': The action name
     * - 'scope': The scope value as a string
     * - 'context': Array of context identifiers
     *
     * This format is used for serialization (e.g., in HTTP responses or cache storage).
     *
     * @return array{capability: string, scope: string, context: string[]}
     */
    public function toArray(): array
    {
        return [
            'capability' => $this->action,
            'scope' => $this->scope->value,
            'context' => $this->context,
        ];
    }

    /**
     * Creates a Capability instance from an array representation.
     *
     * The array must contain:
     * - 'capability': The action name
     * - 'scope': The scope value as a string
     * - 'context': Array of context identifiers
     *
     * This is the inverse of toArray() and is used for deserialization.
     *
     * @param array<string, mixed> $data The array data to deserialize
     *
     * @return self A new Capability instance
     *
     * @throws InvalidCapabilityException If 'capability' key is missing
     * @throws InvalidCapabilityException If 'scope' key is missing
     * @throws InvalidCapabilityException If 'context' key is missing
     * @throws \ValueError If scope value is invalid
     */
    public static function fromArray(array $data): self
    {
        return new self(
            action: $data['capability'] ?? throw new InvalidCapabilityException('missing_capability_field'),
            scope: Scope::from($data['scope'] ?? throw new InvalidCapabilityException('missing_scope_field')),
            context: $data['context'] ?? throw new InvalidCapabilityException('missing_context_field'),
        );
    }
}
