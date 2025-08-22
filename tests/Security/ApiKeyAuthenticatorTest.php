<?php

declare(strict_types=1);

namespace Tests\Security;

use Iseazy\Security\Security\ApiKeyAuthenticator;
use Iseazy\Security\Security\ApiKeyUserFactoryInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class ApiKeyAuthenticatorTest extends TestCase
{
    private const API_KEY = 'test_api_key';

    private ApiKeyUserFactoryInterface $userFactory;
    private ApiKeyAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->userFactory = $this->createMock(ApiKeyUserFactoryInterface::class);
        $this->authenticator = new ApiKeyAuthenticator(self::API_KEY, $this->userFactory::class);
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
        $user = $this->createMock(UserInterface::class);


        $passport = $this->authenticator->authenticate($request);
        $passport->addBadge(new UserBadge('api_key_user', fn() => $user));
        $this->assertInstanceOf(SelfValidatingPassport::class, $passport);
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

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertStringContainsString('Unauthorized', $response->getContent());
    }

    public function testOnAuthenticationSuccessReturnsNull(): void
    {
        $request = new Request();
        $token = $this->createMock(TokenInterface::class);
        $result = $this->authenticator->onAuthenticationSuccess($request, $token, 'main');
        $this->assertNull($result);
    }

    private function dummyApiKeyUserFactory(?UserInterface $user = null, ?string $platformId = null)
    {
        $user ??= new class implements UserInterface {
            public function getUserIdentifier(): string
            {
                return '123';
            }

            public function getRoles(): array
            {
                return ['ROLE_INTERNAL'];
            }

            public function eraseCredentials(): void
            {
            }
        };

        $platformId ??= '3b594402-bda5-4f77-96d4-75f1a964bcbe';

        return new class ($user, $platformId) implements ApiKeyUserFactoryInterface {
            private static UserInterface $user;
            private static ?string $platformId;

            public function __construct(UserInterface $user, ?string $platformId)
            {
                self::$user = $user;
                self::$platformId = $platformId;
            }

            public static function createFromApiKey(string $apiKey, ?string $platformId): UserInterface
            {
                return self::$user;
            }

            public function getPlatformId(): ?string
            {
                return self::$platformId;
            }

            // Métodos de UserInterface
            public function getUserIdentifier(): string
            {
                return self::$user->getUserIdentifier();
            }

            public function getRoles(): array
            {
                return self::$user->getRoles();
            }

            public function eraseCredentials(): void
            {
            }
        };
    }
}
