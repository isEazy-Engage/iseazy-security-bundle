<?php

declare(strict_types=1);

namespace Iseazy\Security\DependencyInjection;

use Iseazy\Security\Listener\GlobalAuthorizationListener;
use Iseazy\Security\Security\ApiKeyAuthenticator;
use Iseazy\Security\Security\ApiKeyUserFactoryInterface;
use Iseazy\Security\Security\JwtAuthenticator;
use Iseazy\Security\Security\JwtUserFactoryInterface;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

final class IseazySecurityExtension extends Extension
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

        if ($config['authorization']['enabled']) {
            $loader->load('authorization.yaml');

            $container->setParameter(
                'iseazy_security.authorization.http.timeout',
                $config['authorization']['http']['timeout']
            );
            $container->setParameter(
                'iseazy_security.authorization.http.fail_mode',
                $config['authorization']['http']['fail_mode']
            );
            $container->setParameter(
                'iseazy_security.authorization.cache.ttl',
                $config['authorization']['cache']['ttl']
            );
        }

        if ($config['jwt']['enabled'] || $config['api_key']['enabled']) {
            $container->autowire(GlobalAuthorizationListener::class)
                ->addTag('kernel.event_listener', ['event' => 'kernel.request', 'priority' => -100]);
        }

        if ($config['jwt']['enabled']) {
            $container->registerForAutoconfiguration(JwtUserFactoryInterface::class)
                ->addTag('iseazy.security.jwt_factory');

            $container->autowire(JwtAuthenticator::class)
                ->setArgument('$idamUri', '%env(IDAM_URI)%')
                ->setArgument('$expectedIssuerUri', '%env(IDAM_EXPECTED_ISSUER_URI)%')
                ->setArgument('$userFactory', $config['jwt']['user_class'])
                ->setArgument('$audience', '%env(IDAM_AUDIENCE)%')
                ->addTag('security.authenticator')
                ->addTag('monolog.logger', ['channel' => 'security']);
        }

        if ($config['api_key']['enabled']) {
            $container->registerForAutoconfiguration(ApiKeyUserFactoryInterface::class)
                ->addTag('iseazy.security.apikey_factory');

            $container->autowire(ApiKeyAuthenticator::class)
                ->setArgument('$apiKey', '%env(API_KEY)%')
                ->setArgument('$userFactory', $config['api_key']['user_class'])
                ->addTag('security.authenticator')
                ->addTag('monolog.logger', ['channel' => 'security']);
        }
    }
}
