<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use UnexpectedValueException;

class JwtAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    private string $audience;
    private const JWKS_CACHE_KEY = 'jwks_cache';
    private const JWKS_CACHE_TTL = 300; // 5 minutos
    private CacheInterface $cache;

    public function __construct(
        private readonly string $idamUri,
        private readonly string $expectedIssuerUri,
        private readonly string $userFactory,
        CacheInterface $cache
    ) {
        if (!is_subclass_of($userFactory, JwtUserFactoryInterface::class)) {
            throw new \LogicException(
                sprintf(
                    'The class "%s" must implement %s.',
                    $userFactory,
                    JwtUserFactoryInterface::class
                )
            );
        }

        $this->audience = $_ENV['IDAM_AUDIENCE'] ?? 'IsEazy';
        $this->cache = $cache;
    }

    public function supports(Request $request): ?bool
    {
        $authHeader = $request->headers->get('Authorization');
        return $authHeader && str_starts_with($authHeader, 'Bearer ');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $token = substr($request->headers->get('Authorization'), 7);
        try {
            $payload = $this->decodeAndValidate($token);
        } catch (\Throwable $e) {
            throw new CustomUserMessageAuthenticationException('Invalid JWT Token');
        }

        if (!is_array($payload) || !isset($payload['sub'])) {
            throw new CustomUserMessageAuthenticationException('Invalid JWT Payload');
        }

        return new SelfValidatingPassport(
            new UserBadge(
                $payload['sub'] ?? '',
                fn() => $this->userFactory::createFromJwtPayload($payload)
            )
        );
    }


    public function onAuthenticationSuccess(
        Request $request,
        TokenInterface $token,
        string $firewallName
    ): ?Response {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): JsonResponse
    {
        return new JsonResponse(
            ['message' => $exception->getMessage(), 'code' => JsonResponse::HTTP_UNAUTHORIZED],
            JsonResponse::HTTP_UNAUTHORIZED
        );
    }


    private function validateToken(\stdClass $decoded): void
    {
        if ($decoded->iss !== $this->getIssuerCertKeycloak()) {
            throw new UnexpectedValueException(
                sprintf(
                    'Invalid issuer. Expected: %s, got: %s',
                    $this->getIssuerCertKeycloak(),
                    $decoded->iss
                )
            );
        }
        if (time() > $decoded->exp) {
            throw new UnexpectedValueException('Token expired');
        }
    }

    private function decodeAndValidate(string $token): array
    {
        $jwks = $this->fetchJwks();

        $decoded = JWT::decode($token, JWK::parseKeySet($jwks));

        $this->validateToken($decoded);

        return json_decode(json_encode($decoded), true);
    }

    protected function getIssuerCertKeycloak(): string
    {
        return $this->expectedIssuerUri . '/realms/' . $this->audience;
    }

    protected function fetchJwks(): array
    {
        $jwks = $this->cache->get(self::JWKS_CACHE_KEY, function (ItemInterface $item) {
            $item->expiresAfter(self::JWKS_CACHE_TTL);
            $url = $this->idamUri . '/realms/' . $this->audience . '/protocol/openid-connect/certs';
            $json = @file_get_contents($url);
            if ($json === false) {
                throw new UnexpectedValueException('Unable to fetch JWKS from ' . $url);
            }
            $jwks = json_decode($json, true);
            if (!is_array($jwks)) {
                throw new UnexpectedValueException('Invalid JWKS response');
            }
            return $jwks;
        });
        return $jwks;
    }

    public function start(Request $request, ?AuthenticationException $authException = null): JsonResponse
    {
        return new JsonResponse(['message' => 'Authentication Required'], 401);
    }
}
