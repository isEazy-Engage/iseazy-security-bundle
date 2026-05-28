<?php

declare(strict_types=1);

namespace Iseazy\Security\Tests\DependencyInjection;

use Iseazy\Security\DependencyInjection\IseazySecurityExtension;
use Iseazy\Security\Listener\GlobalAuthorizationListener;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class IseazySecurityExtensionTest extends TestCase
{
    public function testGlobalListenerIsRegisteredByDefault(): void
    {
        $container = new ContainerBuilder();
        $extension = new IseazySecurityExtension();

        $extension->load([
            [
                'jwt_user_class' => 'App\\Security\\JwtUserFactory',
            ]
        ], $container);

        $this->assertTrue($container->hasDefinition(GlobalAuthorizationListener::class));
    }

    public function testGlobalListenerIsNotRegisteredWhenDisabled(): void
    {
        $container = new ContainerBuilder();
        $extension = new IseazySecurityExtension();

        $extension->load([
            [
                'jwt_user_class' => 'App\\Security\\JwtUserFactory',
                'enable_global_listener' => false,
            ]
        ], $container);

        $this->assertFalse($container->hasDefinition(GlobalAuthorizationListener::class));
    }

    public function testGlobalListenerIsRegisteredWhenExplicitlyEnabled(): void
    {
        $container = new ContainerBuilder();
        $extension = new IseazySecurityExtension();

        $extension->load([
            [
                'jwt_user_class' => 'App\\Security\\JwtUserFactory',
                'enable_global_listener' => true,
            ]
        ], $container);

        $this->assertTrue($container->hasDefinition(GlobalAuthorizationListener::class));

        $definition = $container->getDefinition(GlobalAuthorizationListener::class);
        $tags = $definition->getTag('kernel.event_listener');

        $this->assertCount(1, $tags);
        $this->assertSame('kernel.request', $tags[0]['event']);
        $this->assertSame(-100, $tags[0]['priority']);
    }
}
