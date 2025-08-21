<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

final class ApiKeyAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private readonly string $apiKey,
        private readonly string $userFactory
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('X-API-Key');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $apiKey = $request->headers->get('X-API-Key');
        if (!$request->headers->has('X-API-Key')) {
            throw new AuthenticationException('No ApiKey provided');
        }
        if ($apiKey !== $this->apiKey) {
            throw new AuthenticationException('Invalid API Key');
        }

        if (!is_subclass_of($this->userFactory, ApiKeyUserFactoryInterface::class)) {
            throw new \LogicException('invalid_user_key_entity_class', 500);
        }

        return new SelfValidatingPassport(
            new UserBadge(
                'api_key_user',
                fn() => $this->userFactory::createFromApiKey(
                    $apiKey,
                    $request->query->get('platformId') ?? $request->query->get('platformUid')
                )
            )
        );
    }

    public function onAuthenticationSuccess(
        Request $request,
        TokenInterface $token,
        string $firewallName
    ): ?JsonResponse {
        return null;
    }

    public function onAuthenticationFailure(
        Request $request,
        AuthenticationException $exception
    ): ?JsonResponse {
        return new JsonResponse(['message' => 'Unauthorized', 'code' => 401], 401);
    }
}
