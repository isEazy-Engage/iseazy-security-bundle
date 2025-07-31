<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface ApiKeyUserFactoryInterface extends IseazyUserInterface
{
    public function createFromApiKey(string $apiKey): UserInterface;

}