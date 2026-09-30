<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Service;

use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Model\Capability;

/**
 * Service that filters out restrictive capabilities when less restrictive ones exist.
 *
 * This service implements the "least restrictive capability wins" rule (BR-CAP-008).
 * When a user has multiple capabilities for the same action but with different scopes,
 * this filter removes the more restrictive ones to simplify the response for frontend consumers.
 *
 * Rule: a capability is removed when another capability of the same action has a less
 * restrictive scope that covers its scope (see Scope::isLessRestrictiveThan() and
 * Scope::covers()). With the current scopes:
 * - GLOBAL absorbs every other scope of that action
 * - PLATFORM absorbs BUSINESS and HIERARCHY of that action
 * - BUSINESS and HIERARCHY do not cover each other, so without GLOBAL or PLATFORM both are kept
 * A new scope only needs to be declared in Scope (restriction level and coverage) to be absorbed
 * by the scopes that cover it; this filter does not need to change.
 *
 * Contexts are NOT compared. A PLATFORM capability has the platform id as context and a BUSINESS
 * one has business ids, so they can never be compared id by id. That is why the collection to
 * filter MUST belong to a single platform: the capabilities of one user in one platform, as the
 * Platform microservice computes them for a given platformId. Do not use this filter on
 * capabilities of several platforms mixed together.
 *
 * Capabilities with the same action and scope are merged by Capabilities itself.
 *
 * Example scenarios:
 * - Input: [manage_business@platform:[plat-123], manage_business@business:[biz-a]]
 *   Output: [manage_business@platform:[plat-123]] (business scope is more restrictive)
 *
 * - Input: [view_user@global:*, view_user@business:[biz-a]]
 *   Output: [view_user@global:*] (global covers everything)
 *
 * - Input: [view_user@business:[biz-a], view_user@business:[biz-b]]
 *   Output: Both merged as [view_user@business:[biz-a,biz-b]] (same scope, different contexts)
 *
 * - Input: [view_user@business:[biz-a], view_user@hierarchy:[hier-x]]
 *   Output: both kept (business and hierarchy do not cover each other)
 *
 * Note: This service is stateless and has no mutable properties.
 */
final class CapabilityFilter implements CapabilityFilterInterface
{
    /**
     * Filters out restrictive capabilities when less restrictive ones exist.
     *
     * For each capability, checks if there's another capability with:
     * 1. The same action
     * 2. A less restrictive scope (via Capability::isLessRestrictiveThan())
     * 3. Whose scope covers the current capability's scope (via Scope::covers())
     *
     * If all conditions are met, the more restrictive capability is excluded.
     *
     * @param Capabilities $capabilities The input collection to filter (a single platform)
     *
     * @return Capabilities A new collection with restrictive capabilities removed
     */
    public function filterRestrictive(Capabilities $capabilities): Capabilities
    {
        if ($capabilities->isEmpty()) {
            return Capabilities::empty();
        }

        $items = iterator_to_array($capabilities->getIterator(), false);
        $result = [];

        foreach ($items as $capability) {
            if (!$this->isAbsorbedByAnother($capability, $items)) {
                $result[] = $capability;
            }
        }

        return new Capabilities($result);
    }

    /**
     * @param Capability[] $items
     */
    private function isAbsorbedByAnother(Capability $capability, array $items): bool
    {
        foreach ($items as $other) {
            if ($other === $capability) {
                continue;
            }

            if ($other->isLessRestrictiveThan($capability) && $other->scope()->covers($capability->scope())) {
                return true;
            }
        }

        return false;
    }
}
