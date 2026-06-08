<?php

declare(strict_types=1);

namespace Tests\Listener;

use Iseazy\Security\Listener\GlobalAuthorizationListener;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class GlobalAuthorizationListenerTest extends TestCase
{
    private Security $security;
    private GlobalAuthorizationListener $listener;

    protected function setUp(): void
    {
        $this->security = $this->createMock(Security::class);
        $this->listener = new GlobalAuthorizationListener($this->security, new NullLogger());
    }

    #[Test]
    public function testDoesNothingForSubRequests(): void
    {
        // ARRANGE
        $kernel = $this->createStub(HttpKernelInterface::class);
        $request = new Request();
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::SUB_REQUEST);

        // ACT & ASSERT — no exception thrown
        $this->security->expects($this->never())->method('getUser');
        $this->listener->onKernelRequest($event);
    }

    #[Test]
    public function testDoesNothingForNonApiFirewall(): void
    {
        // ARRANGE
        $kernel = $this->createStub(HttpKernelInterface::class);
        $request = new Request();
        $request->attributes->set('_firewall_context', 'security.firewall.map.context.other');
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        // ACT & ASSERT — no exception thrown, getUser never called
        $this->security->expects($this->never())->method('getUser');
        $this->listener->onKernelRequest($event);
    }

    #[Test]
    public function testThrowsBadRequestForInvalidUuid(): void
    {
        // ARRANGE
        $kernel = $this->createStub(HttpKernelInterface::class);
        $request = new Request(query: ['platformId' => 'not-a-valid-uuid']);
        // No _firewall_context set → null → passes the firewall check
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        // ACT & ASSERT
        $this->expectException(BadRequestException::class);
        $this->expectExceptionMessage('invalid_uuid');

        $this->listener->onKernelRequest($event);
    }

    #[Test]
    public function testDoesNotValidateUuidWhenPlatformIdAbsent(): void
    {
        // ARRANGE
        $kernel = $this->createStub(HttpKernelInterface::class);
        $request = new Request(); // No platformId query param
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $user = $this->createStub(UserInterface::class);
        $user->method('getUserIdentifier')->willReturn('user-123');
        $this->security->method('getUser')->willReturn($user);

        // ACT & ASSERT — no BadRequestException, no error about UUID
        $this->listener->onKernelRequest($event);
        $this->addToAssertionCount(1);
    }

    #[Test]
    public function testThrowsAccessDeniedWhenUserIsNull(): void
    {
        // ARRANGE
        $kernel = $this->createStub(HttpKernelInterface::class);
        $request = new Request(query: ['platformId' => '550e8400-e29b-41d4-a716-446655440000']);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $this->security->method('getUser')->willReturn(null);

        // ACT & ASSERT
        $this->expectException(AccessDeniedHttpException::class);
        $this->expectExceptionMessage('user_not_authenticated');

        $this->listener->onKernelRequest($event);
    }

    #[Test]
    public function testPassesWhenUserAuthenticatedWithValidUuid(): void
    {
        // ARRANGE
        $kernel = $this->createStub(HttpKernelInterface::class);
        $request = new Request(query: ['platformId' => '550e8400-e29b-41d4-a716-446655440000']);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $user = $this->createStub(UserInterface::class);
        $user->method('getUserIdentifier')->willReturn('user-abc');
        $this->security->method('getUser')->willReturn($user);

        // ACT & ASSERT — no exception thrown
        $this->listener->onKernelRequest($event);
        $this->addToAssertionCount(1);
    }
}
