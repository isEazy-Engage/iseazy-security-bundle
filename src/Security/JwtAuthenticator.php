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
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use UnexpectedValueException;

class JwtAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{

    private string $audience;

    public function __construct(
        private readonly string $idamUri,
        private readonly string $expectedIssuerUri,
        private readonly string $userFactory
    ) {
        $this->audience = $_ENV['IDAM_AUDIENCE'] ?? 'IsEazy';
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        if (!$request->headers->has('Authorization')) {
            throw new AuthenticationException('No token provided');
        }
        $authHeader = $request->headers->get('Authorization');
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            throw new AuthenticationException('No token provided');
        }

        $token = substr($authHeader, 7);

        try {
            $decoded = $this->decode($token);
        } catch (\Exception $e) {
            throw new AuthenticationException('Invalid JWT Token');
        } catch (\TypeError $e) {
            throw new AuthenticationException('Invalid JWT Token' . $e->getMessage());
        }
        $payload = $decoded['payload'] ?? null;


        if (!is_subclass_of($this->userFactory, JwtUserFactoryInterface::class)) {
            throw new \LogicException('invalid_user_entity_class', 500);
        }



        return new SelfValidatingPassport(
            new UserBadge($payload['sub'], fn() => $this->userFactory::createFromJwtPayload($payload))

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
        return new JsonResponse(['message' => $exception->getMessage(), 'code' => 401], 401);
    }

    /**
     * Decode the JWT token and validate it.
     *
     * @param string $token The JWT token to decode.
     * @return array An array containing the decoded payload and headers.
     * @throws UnexpectedValueException If the token is invalid or expired.
     */
    private function decode(string $token): array
    {
        $jwks = $this->getJwks();

        $headers = new \StdClass();
        $decoded = JWT::decode(
            $token,
            JWK::parseKeySet($jwks),
            $headers
        );

        $this->validateToken($decoded);

        return [
            'payload' => json_decode(json_encode($decoded), true),
            'headers' => json_decode(json_encode($headers), true),
        ];
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


    protected function getIssuerCertKeycloak(): string
    {
        return $this->expectedIssuerUri . '/realms/' . $this->audience;
    }

    protected function getJwks(): array
    {
        return json_decode(
            file_get_contents($this->getUrlCertsKeycloak()),
            true,
            512
        );
    }

    private function getUrlCertsKeycloak(): string
    {
        return $this->idamUri . '/realms/' . $this->audience . '/protocol/openid-connect/certs';
    }

    public function start(Request $request, ?AuthenticationException $authException = null): JsonResponse
    {
        return new JsonResponse(['message' => 'Authentication Required'], 401);
    }
}