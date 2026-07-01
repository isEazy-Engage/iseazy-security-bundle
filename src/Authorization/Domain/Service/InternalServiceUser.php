<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Domain\Service;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Marker interface for users representing internal service accounts.
 *
 * Implementations bypass capability checks in CapabilityVoter entirely.
 * This interface belongs in the Authorization domain because the bypass
 * decision is an authorization concern, not an authentication concern.
 */
interface InternalServiceUser extends UserInterface
{
}
