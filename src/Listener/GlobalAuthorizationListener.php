<?php

declare(strict_types=1);

namespace Iseazy\Security\Listener;

use Iseazy\Security\Security\ApiKeyUserFactoryInterface;
use Iseazy\Security\Security\JwtUserFactoryInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

final readonly class GlobalAuthorizationListener
{

    public function __construct(
        private Security $security
    ) {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();

        $user = $this->security->getUser();
        if (!$user) {
            throw new AccessDeniedHttpException('user_not_authenticated');
        }
        if ($user instanceof ApiKeyUserFactoryInterface) {
            return;
        }

        if ($user instanceof JwtUserFactoryInterface) {
            $platformId = $request->query->get('platformId') ?? $request->query->get(
                'platformUid'
            );
            $userPlatformId = $user->getPlatformId();
            if ($platformId && $platformId !== $userPlatformId) {
                throw new AccessDeniedHttpException('invalid_platform_id', null, 403);
            }
            return;
        }

        throw new AccessDeniedHttpException('user_not_supported', null, 403);
    }
}

