<?php

declare(strict_types=1);

namespace Tests\Security;

use Iseazy\Security\Security\ApiKeyAuthenticator;
use Iseazy\Security\Security\ApiKeyUserFactoryInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

class ApiKeyAuthenticatorTest extends TestCase
{
    private const API_KEY = 'test_api_key';

    private ApiKeyUserFactoryInterface $userFactory;
    private ApiKeyAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->userFactory = $this->createMock(ApiKeyUserFactoryInterface::class);
        $this->authenticator = new ApiKeyAuthenticator(self::API_KEY, $this->userFactory);
    }

    public function testSupportsWithApiKeyHeader(): void
    {
        $request = new Request([], [], [], [], [], ['HTTP_X_API_KEY' => self::API_KEY]);
        $this->assertTrue($this->authenticator->supports($request));
    }

    public function testSupportsWithoutApiKeyHeader(): void
    {
        $request = new Request();
        $this->assertFalse($this->authenticator->supports($request));
    }

    public function testAuthenticateWithValidApiKey(): void
    {
        $request = new Request([], [], [], [], [], ['HTTP_X_API_KEY' => self::API_KEY]);
        $this->userFactory
            ->expects($this->once())
            ->method('createFromApiKey')
            ->with(self::API_KEY);

        $passport = $this->authenticator->authenticate($request);
        $passport->getBadge(UserBadge::class)->getUser();
        $this->assertInstanceOf(\Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport::class, $passport);
    }

    public function testAuthenticateWithInvalidApiKeyThrowsException(): void
    {
        $request = new Request([], [], [], [], [], ['HTTP_X_API_KEY' => 'invalid_key']);
        $this->expectException(AuthenticationException::class);
        $this->authenticator->authenticate($request);
    }

    public function testAuthenticateWithoutApiKeyThrowsException(): void
    {
        $request = new Request();
        $this->expectException(AuthenticationException::class);
        $this->authenticator->authenticate($request);
    }

    public function testOnAuthenticationFailureReturnsJsonResponse(): void
    {
        $request = new Request();
        $exception = new AuthenticationException('Invalid API Key');
        $response = $this->authenticator->onAuthenticationFailure($request, $exception);

        $this->assertInstanceOf(\Symfony\Component\HttpFoundation\JsonResponse::class, $response);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertStringContainsString('Unauthorized', $response->getContent());
    }

    public function testOnAuthenticationSuccessReturnsNull(): void
    {
        $request = new Request();
        $token = $this->createMock(\Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class);
        $result = $this->authenticator->onAuthenticationSuccess($request, $token, 'main');
        $this->assertNull($result);
    }
}