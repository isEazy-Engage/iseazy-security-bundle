<?php

declare(strict_types=1);

namespace Tests\Security;

use Firebase\JWT\JWT;
use Iseazy\Security\Security\JwtAuthenticator;
use Iseazy\Security\Security\JwtUserFactoryInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class JwtAuthenticatorTest extends TestCase
{
    private function createAuthenticator(
        string $idamUri = 'http://fake-keycloak.test',
        string $issuerUri = 'http://fake-keycloak.test',
        ?string $userFactoryClass = null,
        ?CacheInterface $cache = null,
        ?HttpClientInterface $httpClient = null
    ): JwtAuthenticator {
        $userFactory = $userFactoryClass ?? $this->dummyUserFactory()::class;

        return new JwtAuthenticator(
            idamUri: $idamUri,
            expectedIssuerUri: $issuerUri,
            userFactory: $userFactory,
            cache: $cache ?? $this->createStub(CacheInterface::class),
            httpClient: $httpClient ?? $this->createStub(HttpClientInterface::class),
            logger: new NullLogger(),
        );
    }

    protected function generateMockToken(): string
    {
        $privateKey = file_get_contents(__DIR__ . '/../config/jwt/private.pem');
        $payload = [
            'sub' => 'f:realm:c34fc026-c263-4a9e-ad0d-98c6d67bf769',
            'iss' => 'http://fake-keycloak.test/realms/IsEazy',
            'aud' => 'account',
            'exp' => time() + 3600,
            'iat' => time(),
            'preferred_username' => 'testuser',
            'platform_id' => '3b594402-bda5-4f77-96d4-75f1a964bcbe',
            'roles' => [
                'global' => ['roles' => ['ROLE_SUPER_ADMIN' => ['ALL_PERMISSIONS']]],
                'projects' => [],
            ],
        ];

        return JWT::encode($payload, $privateKey, 'RS256', 'test-key');
    }

    #[Test]
    public function testSupportsReturnsFalseWhenNoAuthorizationHeader(): void
    {
        $authenticator = $this->createAuthenticator();
        $this->assertFalse($authenticator->supports(new Request()));
    }

    #[Test]
    public function testSupportsReturnsTrueWhenAuthorizationHeaderPresent(): void
    {
        $authenticator = $this->createAuthenticator();
        $request = new Request(server: ['HTTP_AUTHORIZATION' => 'Bearer some.jwt.token']);
        $this->assertTrue($authenticator->supports($request));
    }

    #[Test]
    public function testAuthenticateThrowsExceptionWhenHeaderMalformed(): void
    {
        $authenticator = $this->createAuthenticator();
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer');

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    #[Test]
    public function testAuthenticateThrowsExceptionWhenTokenInvalid(): void
    {
        $authenticator = $this->createAuthenticator(idamUri: 'http://idam', issuerUri: 'http://issuer');
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer invalidtoken');

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    #[Test]
    public function testAuthenticateWithValidToken(): void
    {
        $user = $this->createStub(UserInterface::class);
        $userFactory = $this->dummyUserFactory($user);
        $cache = $this->createStub(CacheInterface::class);
        $httpClient = $this->createStub(HttpClientInterface::class);

        $authenticator = $this->getMockBuilder(JwtAuthenticator::class)
            ->setConstructorArgs([
                'http://fake-keycloak.test',
                'http://fake-keycloak.test',
                $userFactory::class,
                $cache,
                $httpClient,
                new NullLogger(),
            ])
            ->onlyMethods(['fetchJwks'])
            ->getMock();

        $authenticator->expects($this->once())->method('fetchJwks')->willReturn(
            json_decode(file_get_contents(__DIR__ . '/../config/jwt/test-jwks.json'), true, 512)
        );

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $this->generateMockToken());

        $passport = $authenticator->authenticate($request);

        $this->assertInstanceOf(SelfValidatingPassport::class, $passport);
        $this->assertSame($user, $passport->getUser());
    }

    #[Test]
    public function testAuthenticateThrowsExceptionWhenTokenIsEmptyAfterBearer(): void
    {
        $authenticator = $this->createAuthenticator();
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ');

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    #[Test]
    public function testOnAuthenticationFailureReturnsUnauthorizedJsonResponse(): void
    {
        $authenticator = $this->createAuthenticator();
        $response = $authenticator->onAuthenticationFailure(
            new Request(),
            new AuthenticationException('Invalid JWT Token')
        );

        $this->assertInstanceOf(\Symfony\Component\HttpFoundation\JsonResponse::class, $response);
        $this->assertSame(401, $response->getStatusCode());
    }

    #[Test]
    public function testStartReturnsAuthenticationRequiredResponse(): void
    {
        $authenticator = $this->createAuthenticator();
        $response = $authenticator->start(new Request());

        $this->assertInstanceOf(\Symfony\Component\HttpFoundation\JsonResponse::class, $response);
        $this->assertSame(401, $response->getStatusCode());
        $decoded = json_decode($response->getContent(), true);
        $this->assertSame('Authentication Required', $decoded['message']);
    }

    #[Test]
    public function testConstructorThrowsWhenUserFactoryDoesNotImplementInterface(): void
    {
        $this->expectException(\LogicException::class);

        new JwtAuthenticator(
            idamUri: 'http://idam',
            expectedIssuerUri: 'http://idam',
            userFactory: \stdClass::class,
            cache: $this->createStub(CacheInterface::class),
            httpClient: $this->createStub(HttpClientInterface::class),
            logger: new NullLogger(),
        );
    }

    private function dummyUserFactory(?UserInterface $user = null)
    {
        if (!$user) {
            $user = new class implements UserInterface {
                public function getUserIdentifier(): string
                {
                    return '123';
                }

                public function getRoles(): array
                {
                    return ['ROLE_USER'];
                }

                public function eraseCredentials(): void
                {
                }
            };
        }

        return new class ($user) implements JwtUserFactoryInterface {
            private static $user;

            public function __construct($user)
            {
                self::$user = $user;
            }

            public static function createFromJwtPayload(array $payload): UserInterface
            {
                return self::$user;
            }

            public function userId(): string
            {
                return 'a1b2c3d4-0000-0000-0000-000000000000';
            }

            public function platformId(): string
            {
                return '3b594402-bda5-4f77-96d4-75f1a964bcbe';
            }

            public function getRoles(): array
            {
                return self::$user->getRoles();
            }

            public function eraseCredentials(): void
            {
            }

            public function getUserIdentifier(): string
            {
                return self::$user->getUserIdentifier();
            }
        };
    }
}
