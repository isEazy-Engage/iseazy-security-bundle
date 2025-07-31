<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface JwtUserFactoryInterface extends IseazyUserInterface
{
    public function createFromJwtPayload(array $payload): UserInterface;

}