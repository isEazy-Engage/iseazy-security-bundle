<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Service;

use Iseazy\Security\Authorization\Domain\Model\Capabilities;

interface CapabilityFilterInterface
{
    /**
     * Removes the capabilities made redundant by a less restrictive one of the same action.
     *
     * The collection MUST contain the capabilities of a single platform: scopes are compared, not
     * contexts (a PLATFORM capability has the platform id as context, a BUSINESS one business ids).
     */
    public function filterRestrictive(Capabilities $capabilities): Capabilities;
}
