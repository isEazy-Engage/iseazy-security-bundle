<?php

declare(strict_types=1);

namespace Iseazy\Security\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('iseazy_security');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
                ->scalarNode('jwt_user_class')
                    ->defaultNull()
                ->end()
                ->scalarNode('api_key_user_class')
                    ->defaultNull()
                ->end()
                ->scalarNode('audience')
                    ->info('JWT audience (realm name)')
                    ->defaultValue('IsEazy')
                ->end()
                ->booleanNode('enable_global_listener')
                    ->info('Enable/disable the GlobalAuthorizationListener')
                    ->defaultTrue()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
