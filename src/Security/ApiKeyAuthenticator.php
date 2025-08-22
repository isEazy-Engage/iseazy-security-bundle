<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
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
        if (!is_subclass_of($userFactory, ApiKeyUserFactoryInterface::class)) {
            throw new \LogicException(
                sprintf(
                    'The class "%s" must implement %s.',
                    $userFactory,
                    ApiKeyUserFactoryInterface::class
                )
            );
        }
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('X-API-Key');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $apiKey = $request->headers->get('X-API-Key');
        if ($apiKey === null) {
            throw new CustomUserMessageAuthenticationException('No API Key provided');
        }

        if ($apiKey !== $this->apiKey) {
            throw new CustomUserMessageAuthenticationException('Invalid API Key');
        }

        $platformId = $request->query->get('platformId') ?? $request->query->get('platformUid');

        return new SelfValidatingPassport(
            new UserBadge(
                'api_key_user',
                fn() => $this->userFactory::createFromApiKey(
                    $apiKey,
                    $platformId
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
        return new JsonResponse(['message' => 'Unauthorized', 'code' => JsonResponse::HTTP_UNAUTHORIZED],
            JsonResponse::HTTP_UNAUTHORIZED);
    }
}
