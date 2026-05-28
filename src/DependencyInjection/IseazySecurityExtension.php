<?php

declare(strict_types=1);

namespace Iseazy\Security\DependencyInjection;

use Iseazy\Security\Listener\GlobalAuthorizationListener;
use Iseazy\Security\Security\ApiKeyAuthenticator;
use Iseazy\Security\Security\ApiKeyUserFactoryInterface;
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

    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../../config'));
        $loader->load('services.yaml');

        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $jwtUserClass = $config['jwt_user_class'];
        $apiKeyUserClass = $config['api_key_user_class'];
        $audience = $config['audience'];
        $enableGlobalListener = $config['enable_global_listener'];

        $container->registerForAutoconfiguration(JwtUserFactoryInterface::class)
            ->addTag('iseazy.security.jwt_factory');

        $container->autowire(JwtAuthenticator::class)
            ->setArgument('$idamUri', '%env(IDAM_URI)%')
            ->setArgument('$expectedIssuerUri', '%env(IDAM_EXPECTED_ISSUER_URI)%')
            ->setArgument('$userFactory', $jwtUserClass)
            ->setArgument('$audience', $audience)
            ->addTag('security.authenticator')
            ->addTag('monolog.logger', ['channel' => 'security']);


        if ($apiKeyUserClass !== null) {
            $container->registerForAutoconfiguration(ApiKeyUserFactoryInterface::class)
                ->addTag('iseazy.security.apikey_factory');

            $container->autowire(ApiKeyAuthenticator::class)
                ->setArgument('$apiKey', '%env(API_KEY)%')
                ->setArgument('$userFactory', $apiKeyUserClass)
                ->addTag('security.authenticator')
                ->addTag('monolog.logger', ['channel' => 'security']);
        }

        // Register GlobalAuthorizationListener only if enabled
        if ($enableGlobalListener) {
            $container->autowire(GlobalAuthorizationListener::class)
                ->addTag('kernel.event_listener', [
                    'event' => 'kernel.request',
                    'priority' => -100
                ])
                ->addTag('monolog.logger', ['channel' => 'security']);
        }
    }
}
