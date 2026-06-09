<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Iseazy\Security\Authorization\Domain\Service\InternalServiceUser;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Note: intentionally does NOT extend AuthorizationUser.
 * API Key users are internal service accounts (InternalServiceUser) and
 * bypass capability checks entirely. The platformId is nullable because
 * service accounts may operate across all platforms.
 */
interface ApiKeyUserFactoryInterface extends InternalServiceUser
{
    public static function createFromApiKey(string $apiKey, ?string $platformId): UserInterface;

    public function platformId(): ?string;
}
