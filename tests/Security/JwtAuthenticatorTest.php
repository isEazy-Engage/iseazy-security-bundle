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
    public function testAuthenticateThrowsExceptionWhenNoAuthorizationHeader()
    {
        $userFactory = $this->createMock(JwtUserFactoryInterface::class);
        $authenticator = new JwtAuthenticator('http://fake-keycloak.test', 'http://fake-keycloak.test', $userFactory);

        $request = new Request();

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionWhenHeaderMalformed()
    {
        $userFactory = $this->createMock(JwtUserFactoryInterface::class);
        $authenticator = new JwtAuthenticator('http://fake-keycloak.test', 'http://fake-keycloak.test', $userFactory);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer'); // Sin token

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionWhenTokenInvalid()
    {
        $userFactory = $this->createMock(JwtUserFactoryInterface::class);
        $userFactory->method('createFromJwtPayload')->willThrowException(new AuthenticationException());

        $authenticator = new JwtAuthenticator('http://idam', 'http://issuer', $userFactory);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer invalidtoken');

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateSuccess()
    {
        $userFactory = $this->createMock(JwtUserFactoryInterface::class);
        $user = $this->getMockBuilder(UserInterface::class)->getMock();
        $userFactory->method('createFromJwtPayload')->willReturn($user);

        $authenticator = $this->getMockBuilder(JwtAuthenticator::class)
            ->setConstructorArgs(['http://fake-keycloak.test', 'http://fake-keycloak.test', $userFactory])
            ->onlyMethods(['getJwks'])
            ->getMock();

        $authenticator->method('getJwks')->willReturn(
            json_decode(file_get_contents(__DIR__ . '/../config/jwt/test-jwks.json'), true, 512)
        );
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $this->generateMockToken());

        $passport = $authenticator->authenticate($request);

        $this->assertInstanceOf(\Symfony\Component\Security\Http\Authenticator\Passport\Passport::class, $passport);
    }
}