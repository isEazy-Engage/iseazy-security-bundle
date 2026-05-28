<?php

declare(strict_types=1);

namespace Iseazy\Security\Security;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Psr\Log\LoggerInterface;
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
use Symfony\Contracts\HttpClient\HttpClientInterface;
use UnexpectedValueException;

class JwtAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    private const JWKS_CACHE_KEY = 'jwks_cache';
    private const JWKS_CACHE_TTL = 300; // 5 minutos

    public function __construct(
        private readonly string $idamUri,
        private readonly string $expectedIssuerUri,
        private readonly string $userFactory,
        private readonly CacheInterface $cache,
        private readonly HttpClientInterface $httpClient,
        private readonly LoggerInterface $logger,
        private readonly string $audience = 'IsEazy'
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
            $this->logger->warning('JWT authentication failed', [
                'error' => $e->getMessage(),
                'exception_class' => get_class($e),
                'uri' => $request->getRequestUri(),
                'method' => $request->getMethod(),
                'ip' => $request->getClientIp()
            ]);
            throw new CustomUserMessageAuthenticationException('Invalid JWT Token');
        }

        if (!is_array($payload) || !isset($payload['sub'])) {
            $this->logger->error('Invalid JWT payload structure', [
                'has_sub' => isset($payload['sub']),
                'payload_keys' => is_array($payload) ? array_keys($payload) : 'not_array',
                'uri' => $request->getRequestUri()
            ]);
            throw new CustomUserMessageAuthenticationException('Invalid JWT Payload');
        }

        $this->logger->info('JWT authentication successful', [
            'user_id' => $payload['sub'],
            'platform_id' => $payload['platform_id'] ?? null,
            'username' => $payload['preferred_username'] ?? null,
            'uri' => $request->getRequestUri(),
            'method' => $request->getMethod()
        ]);

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
        $expectedIssuer = $this->getIssuerCertKeycloak();

        if ($decoded->iss !== $expectedIssuer) {
            $this->logger->warning('JWT issuer validation failed', [
                'expected_issuer' => $expectedIssuer,
                'received_issuer' => $decoded->iss,
                'subject' => $decoded->sub ?? null
            ]);
            throw new UnexpectedValueException(
                sprintf(
                    'Invalid issuer. Expected: %s, got: %s',
                    $expectedIssuer,
                    $decoded->iss
                )
            );
        }

        if (time() > $decoded->exp) {
            $this->logger->warning('JWT token expired', [
                'expired_at' => date('Y-m-d H:i:s', $decoded->exp),
                'current_time' => date('Y-m-d H:i:s'),
                'subject' => $decoded->sub ?? null,
                'issuer' => $decoded->iss ?? null
            ]);
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

            try {
                $response = $this->httpClient->request('GET', $url, [
                    'timeout' => 10,
                ]);

                $json = $response->getContent();
                $jwks = json_decode($json, true);

                if (!is_array($jwks)) {
                    throw new UnexpectedValueException('Invalid JWKS response');
                }

                $this->logger->info('JWKS fetched successfully', [
                    'url' => $url,
                    'keys_count' => count($jwks['keys'] ?? [])
                ]);

                return $jwks;
            } catch (\Throwable $e) {
                $this->logger->error('Failed to fetch JWKS', [
                    'url' => $url,
                    'error' => $e->getMessage(),
                    'exception_class' => get_class($e)
                ]);
                throw new UnexpectedValueException('Unable to fetch JWKS from ' . $url, 0, $e);
            }
        });

        return $jwks;
    }

    public function start(Request $request, ?AuthenticationException $authException = null): JsonResponse
    {
        return new JsonResponse(['message' => 'Authentication Required'], 401);
    }
}
