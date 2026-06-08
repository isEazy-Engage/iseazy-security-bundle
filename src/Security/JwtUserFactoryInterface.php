<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Iseazy\Security\Authorization\Domain\Service\AuthorizationUser;
use Symfony\Component\Security\Core\User\UserInterface;

interface JwtUserFactoryInterface extends AuthorizationUser
{
    public static function createFromJwtPayload(array $payload): UserInterface;
}
