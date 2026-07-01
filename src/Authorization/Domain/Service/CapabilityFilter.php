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
 * Algorithm:
 * 1. For each capability in the input collection
 * 2. Check if there exists another capability with the same action and a less restrictive scope
 * 3. If such a capability exists AND it covers the current one (context-wise), exclude the current one
 * 4. Return a new Capabilities collection with only the non-redundant capabilities
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
     * 3. That covers the current capability (via Capability::covers())
     *
     * If all conditions are met, the more restrictive capability is excluded.
     *
     * @param Capabilities $capabilities The input collection to filter
     *
     * @return Capabilities A new collection with restrictive capabilities removed
     */
    public function filterRestrictive(Capabilities $capabilities): Capabilities
    {
        if ($capabilities->isEmpty()) {
            return Capabilities::empty();
        }

        $items = iterator_to_array($capabilities->getIterator());
        $result = [];

        foreach ($items as $capability) {
            $isRestrictiveOfOther = false;

            foreach ($items as $other) {
                // Skip comparing the capability with itself
                if ($capability === $other) {
                    continue;
                }

                // Check if $other is less restrictive than $capability
                if ($other->isLessRestrictiveThan($capability) && $other->covers($capability)) {
                    $isRestrictiveOfOther = true;
                    break;
                }
            }

            // Only include capabilities that are not made redundant by less restrictive ones
            if (!$isRestrictiveOfOther) {
                $result[] = $capability;
            }
        }

        return new Capabilities($result);
    }
}
