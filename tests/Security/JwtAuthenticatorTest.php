<?php

declare(strict_types=1);

namespace Tests\Security;

use Firebase\JWT\JWT;
use Iseazy\Security\Security\JwtUserFactoryInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Iseazy\Security\Security\JwtAuthenticator;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class JwtAuthenticatorTest extends TestCase
{
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
                'global' => [
                    "roles" => [
                        "ROLE_SUPER_ADMIN" => [
                            "ALL_PERMISSIONS"
                        ]
                    ]
                ],
                'projects' => [
                ]
            ],
        ];

        return JWT::encode($payload, $privateKey, 'RS256', 'test-key');
    }

    public function testSupportsReturnsFalseWhenNoAuthorizationHeader(): void
    {
        $userFactory = $this->createStub(JwtUserFactoryInterface::class);
        $cache = $this->createStub(\Symfony\Contracts\Cache\CacheInterface::class);
        $authenticator = new JwtAuthenticator(
            'http://fake-keycloak.test',
            'http://fake-keycloak.test',
            $userFactory::class,
            $cache
        );

        $this->assertFalse($authenticator->supports(new Request()));
    }

    public function testSupportsReturnsTrueWhenAuthorizationHeaderPresent(): void
    {
        $userFactory = $this->createStub(JwtUserFactoryInterface::class);
        $cache = $this->createStub(\Symfony\Contracts\Cache\CacheInterface::class);
        $authenticator = new JwtAuthenticator(
            'http://fake-keycloak.test',
            'http://fake-keycloak.test',
            $userFactory::class,
            $cache
        );

        $request = new Request(server: [
            'HTTP_AUTHORIZATION' => 'Bearer some.jwt.token',
        ]);

        $this->assertTrue($authenticator->supports($request));
    }

    public function testAuthenticateThrowsExceptionWhenHeaderMalformed()
    {
        $userFactory = $this->createStub(JwtUserFactoryInterface::class);
        $cache = $this->createStub(\Symfony\Contracts\Cache\CacheInterface::class);
        $authenticator = new JwtAuthenticator(
            'http://fake-keycloak.test',
            'http://fake-keycloak.test',
            $userFactory::class,
            $cache
        );

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer'); // Sin token

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionWhenTokenInvalid()
    {
        $userFactory = $this->dummyUserFactory();
        $cache = $this->createStub(\Symfony\Contracts\Cache\CacheInterface::class);

        $authenticator = new JwtAuthenticator('http://idam', 'http://issuer', $userFactory::class, $cache);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer invalidtoken');

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateWithValidToken(): void
    {
        $user = $this->createStub(UserInterface::class);

        $userFactory = $this->dummyUserFactory($user);
        $cache = $this->createStub(\Symfony\Contracts\Cache\CacheInterface::class);

        $authenticator = $this->getMockBuilder(JwtAuthenticator::class)
            ->setConstructorArgs(['http://fake-keycloak.test', 'http://fake-keycloak.test', $userFactory::class, $cache])
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

            public function getPlatformId(): string
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
