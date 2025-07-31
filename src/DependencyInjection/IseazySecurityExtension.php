<?php

declare(strict_types=1);

namespace Iseazy\Security\DependencyInjection;

use Iseazy\Security\Security\ApiKeyAuthenticator;
use Iseazy\Security\Security\ApiKeyUserFactoryInterface;
use Iseazy\Security\Security\IseazyUserInterface;
use Iseazy\Security\Security\JwtAuthenticator;
use Iseazy\Security\Security\JwtUserFactoryInterface;
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

        $container->registerForAutoconfiguration(JwtUserFactoryInterface::class)
            ->addTag('iseazy.security.jwt_factory');

        $container->registerForAutoconfiguration(ApiKeyUserFactoryInterface::class)
            ->addTag('iseazy.security.apikey_factory');

        $container->autowire(JwtAuthenticator::class)
            ->setArgument('$idamUri', '%env(IDAM_URI)%')
            ->setArgument('$expectedIssuerUri', '%env(IDAM_EXPECTED_ISSUER_URI)%')
            ->addTag('security.authenticator');

        $container->autowire(ApiKeyAuthenticator::class)
            ->setArgument('$apiKey', '%env(API_KEY)%')
            ->addTag('security.authenticator');
    }
}