<?php

declare(strict_types=1);

namespace Iseazy\Security\Listener;

use Psr\Log\LoggerInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Uid\Uuid;

final readonly class GlobalAuthorizationListener
{
    private const API_FIREWALL = 'security.firewall.map.context.api';

    public function __construct(
        private Security $security,
        private LoggerInterface $logger
    ) {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $firewallContext = $request->attributes->get('_firewall_context');

        if ($firewallContext !== null && $firewallContext !== self::API_FIREWALL) {
            return;
        }

        $platformId = $request->query->get('platformId') ?? $request->query->get('platformUid');
        if ($platformId !== null) {
            $this->assertValidUuid($platformId, $request->getRequestUri());
        }

        $user = $this->security->getUser();
        if ($user === null) {
            $this->logger->warning('Unauthenticated access attempt', [
                'uri' => $request->getRequestUri(),
                'method' => $request->getMethod(),
                'ip' => $request->getClientIp(),
                'firewall' => $firewallContext,
            ]);
            throw new AccessDeniedHttpException('user_not_authenticated');
        }

        $this->logger->debug('Global authorization check passed', [
            'user' => $user->getUserIdentifier(),
            'platform_id' => $platformId,
            'uri' => $request->getRequestUri(),
        ]);
    }

    private function assertValidUuid(string $uuid, string $requestUri): void
    {
        try {
            Uuid::fromString($uuid);
        } catch (\InvalidArgumentException $e) {
            $this->logger->warning('Invalid UUID provided in request', [
                'uri' => $requestUri,
                'error' => $e->getMessage(),
            ]);
            throw new BadRequestException('invalid_uuid');
        }
    }

}
