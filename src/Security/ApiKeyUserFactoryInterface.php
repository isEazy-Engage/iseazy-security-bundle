<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface ApiKeyUserFactoryInterface extends UserInterface
{
    public static function createFromApiKey(string $apiKey, ?string $platformId): UserInterface;

    public function getPlatformId(): ?string;

}