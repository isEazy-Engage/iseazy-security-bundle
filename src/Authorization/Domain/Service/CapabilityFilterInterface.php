<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Service;

use Iseazy\Security\Authorization\Domain\Model\Capabilities;

interface CapabilityFilterInterface
{
    public function filterRestrictive(Capabilities $capabilities): Capabilities;
}
