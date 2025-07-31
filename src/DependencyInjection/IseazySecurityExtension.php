<?php

declare(strict_types=1);

namespace Iseazy\Security\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class IseazySecurityExtension extends Extension
{
    public function getAlias(): string
    {
        return 'iseazy_security';
    }

    public function load(array $configs, ContainerBuilder $container)
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../../config'));
        $loader->load('services.yaml');

        $container->autowire(
            'Iseazy\Security\Security\JwtAuthenticator',
            'Iseazy\Security\Security\JwtAuthenticator'
        )->addTag('security.authenticator');
    }
}