<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Model;

use Countable;
use IteratorAggregate;
use Traversable;

/**
 * Immutable collection of Capability objects.
 *
 * This collection is used to represent the set of capabilities that a user has.
 * It provides methods for querying, filtering, and merging capabilities while
 * maintaining immutability - all modification methods return new instances.
 *
 * The collection is indexed internally by "action@scope" for efficient lookups
 * and automatic merging of capabilities with the same action and scope.
 *
 * Example:
 * ```php
 * $caps = new Capabilities([
 *     new Capability('view_user', Scope::BUSINESS, ['biz-a']),
 *     new Capability('view_user', Scope::BUSINESS, ['biz-b']),
 * ]);
 * // Automatically merged to: view_user@business:biz-a,biz-b
 *
 * if ($caps->has('view_user', Scope::BUSINESS, 'biz-a')) {
 *     // User can view users in business biz-a
 * }
 * ```
 */
final readonly class Capabilities implements IteratorAggregate, Countable
{
    /**
     * @var array<string, Capability> Capabilities indexed by "action@scope"
     */
    private array $items;

    /**
     * Creates a new Capabilities collection.
     *
     * If multiple capabilities have the same action and scope, they are
     * automatically merged using Capability::merge() to combine their contexts.
     *
     * @param Capability[] $capabilities Array of capabilities to include
     */
    public function __construct(array $capabilities)
    {
        $items = [];
        foreach ($capabilities as $capability) {
            $key = $this->makeKey($capability->action(), $capability->scope());

            if (isset($items[$key])) {
                $items[$key] = $items[$key]->merge($capability);
            } else {
                $items[$key] = $capability;
            }
        }

        $this->items = $items;
    }

    /**
     * Creates an empty Capabilities collection.
     *
     * @return self An empty collection
     */
    public static function empty(): self
    {
        return new self([]);
    }

    /**
     * Creates a Capabilities collection from an array representation.
     *
     * This is the inverse of toArray() and is used for deserialization
     * (e.g., from HTTP responses or cache storage).
     *
     * @param array<int, array<string, mixed>> $data Array of capability data
     *
     * @return self A new Capabilities instance
     */
    public static function fromArray(array $data): self
    {
        $capabilities = array_map(
            static fn(array $item): Capability => Capability::fromArray($item),
            $data
        );

        return new self($capabilities);
    }

    /**
     * Checks if a capability exists that exactly matches the given criteria.
     *
     * This method looks for an exact match: the capability must have the exact
     * action, scope, and the contextId must be in the capability's context array.
     *
     * @param string $action The action to check
     * @param Scope $scope The scope to check
     * @param string $contextId The context identifier to check
     *
     * @return bool True if an exact match is found
     */
    public function has(string $action, Scope $scope, string $contextId): bool
    {
        $key = $this->makeKey($action, $scope);

        if (!isset($this->items[$key])) {
            return false;
        }

        return in_array($contextId, $this->items[$key]->context(), true)
            || in_array('*', $this->items[$key]->context(), true);
    }

    /**
     * Checks if any capability matches the given action and context, regardless of scope.
     *
     * This method searches for a capability with the given action that covers the
     * contextId in ANY scope. It delegates to Capability::matches() which implements
     * the scope coverage logic.
     *
     * For example, if a user has 'view_user@global:*', this will return true for
     * hasAny('view_user', 'any-context-id') even though there's no business-scoped capability.
     *
     * @param string $action The action to check
     * @param string $contextId The context identifier to check
     *
     * @return bool True if any capability matches
     */
    public function hasAny(string $action, string $contextId): bool
    {
        foreach ($this->items as $capability) {
            if ($capability->action() !== $action) {
                continue;
            }

            if ($capability->matches($action, $capability->scope(), $contextId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the number of unique capabilities in this collection.
     *
     * Each unique action@scope combination counts as one capability,
     * regardless of how many context identifiers it has.
     *
     * @return int The number of capabilities
     */
    public function count(): int
    {
        return count($this->items);
    }

    /**
     * Checks if this collection is empty.
     *
     * @return bool True if the collection has no capabilities
     */
    public function isEmpty(): bool
    {
        return $this->items === [];
    }

    /**
     * Adds a capability to this collection.
     *
     * This method is immutable - it returns a new Capabilities instance.
     * If a capability with the same action and scope already exists, they
     * are merged using Capability::merge().
     *
     * @param Capability $capability The capability to add
     *
     * @return self A new Capabilities instance with the capability added
     */
    public function add(Capability $capability): self
    {
        $key = $this->makeKey($capability->action(), $capability->scope());

        $newItems = $this->items;
        if (isset($newItems[$key])) {
            $newItems[$key] = $newItems[$key]->merge($capability);
        } else {
            $newItems[$key] = $capability;
        }

        return new self(array_values($newItems));
    }

    /**
     * Merges this collection with another Capabilities collection.
     *
     * This method is immutable - it returns a new Capabilities instance.
     * Capabilities with the same action and scope are merged automatically.
     *
     * @param self $other The collection to merge with
     *
     * @return self A new Capabilities instance with all capabilities from both collections
     */
    public function merge(self $other): self
    {
        $allCapabilities = array_merge(
            array_values($this->items),
            array_values($other->items)
        );

        return new self($allCapabilities);
    }

    /**
     * Filters this collection to include only capabilities with allowed actions.
     *
     * This method is useful for splitting capabilities by microservice, where each
     * microservice maintains its own list of actions it supports.
     *
     * This method is immutable - it returns a new Capabilities instance.
     *
     * @param string[] $actions Array of allowed action names
     *
     * @return self A new Capabilities instance with only the allowed actions
     */
    public function filterByActions(array $actions): self
    {
        $filtered = array_filter(
            $this->items,
            static fn(Capability $capability): bool => in_array($capability->action(), $actions, true)
        );

        return new self(array_values($filtered));
    }

    /**
     * Converts this collection to an array representation.
     *
     * Returns a flat list (not associative array) of capability data,
     * ordered by action@scope key for deterministic output.
     *
     * This format is used for serialization (e.g., in HTTP responses or cache storage).
     *
     * @return array<int, array{capability: string, scope: string, context: string[]}>
     */
    public function toArray(): array
    {
        $items = $this->items;
        ksort($items); // Sort by key (action@scope) for determinism

        return array_values(array_map(
            static fn(Capability $capability): array => $capability->toArray(),
            $items
        ));
    }

    /**
     * Returns an iterator for traversing all capabilities in this collection.
     *
     * This allows the collection to be used in foreach loops:
     *
     * ```php
     * foreach ($capabilities as $capability) {
     *     echo $capability->toString();
     * }
     * ```
     *
     * @return Traversable<Capability>
     */
    public function getIterator(): Traversable
    {
        yield from array_values($this->items);
    }

    /**
     * Creates the internal index key for a capability.
     *
     * Format: "{action}@{scope}"
     *
     * @param string $action The action name
     * @param Scope $scope The scope
     *
     * @return string The index key
     */
    private function makeKey(string $action, Scope $scope): string
    {
        return sprintf('%s@%s', $action, $scope->value);
    }
}
