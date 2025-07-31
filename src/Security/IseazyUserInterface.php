<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface IseazyUserInterface
{
    public function createUser(?array $payload): UserInterface;

}