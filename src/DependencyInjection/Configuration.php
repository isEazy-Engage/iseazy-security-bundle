<?php

declare(strict_types=1);

namespace Iseazy\Security\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('iseazy_security');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
                ->arrayNode('jwt')
                    ->addDefaultsIfNotSet()
                    ->info('JWT authentication via Keycloak')
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultFalse()
                            ->info('Enable JWT authenticator')
                        ->end()
                        ->scalarNode('user_class')
                            ->defaultNull()
                            ->info('Fully qualified class name implementing JwtUserFactoryInterface')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('api_key')
                    ->addDefaultsIfNotSet()
                    ->info('API Key authentication for service-to-service')
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultFalse()
                            ->info('Enable API Key authenticator')
                        ->end()
                        ->scalarNode('user_class')
                            ->defaultNull()
                            ->info('Fully qualified class name implementing ApiKeyUserFactoryInterface')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('authorization')
                    ->addDefaultsIfNotSet()
                    ->info('Authorization system configuration for capability-based access control')
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultFalse()
                            ->info('Enable the capability-based authorization system')
                        ->end()
                        ->arrayNode('http')
                            ->addDefaultsIfNotSet()
                            ->info('HTTP client configuration for HttpCapabilityProvider')
                            ->children()
                                ->integerNode('timeout')
                                    ->defaultValue(3)
                                    ->min(1)
                                    ->max(30)
                                    ->info('HTTP request timeout in seconds')
                                ->end()
                                ->enumNode('fail_mode')
                                    ->values(['closed', 'open'])
                                    ->defaultValue('closed')
                                    ->info(
                                        'Behavior when capability provider is unavailable: '
                                        . 'closed (deny) or open (allow)'
                                    )
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('cache')
                            ->addDefaultsIfNotSet()
                            ->info('Cache configuration for CachedCapabilityProvider')
                            ->children()
                                ->integerNode('ttl')
                                    ->defaultValue(900)
                                    ->min(0)
                                    ->info('Cache TTL in seconds (0 to disable caching)')
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
