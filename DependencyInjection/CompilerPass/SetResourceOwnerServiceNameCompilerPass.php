<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\DependencyInjection\CompilerPass;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Set the appropriate name for aliased services.
 *
 * @author Tomas Pecserke <tomas.pecserke@gmail.com>
 */
final class SetResourceOwnerServiceNameCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        foreach (array_keys($container->getAliases()) as $alias) {
            if (0 !== strpos($alias, 'hwi_oauth.resource_owner.')) {
                continue;
            }

            $aliasIdParts = explode('.', $alias);
            $resourceOwnerDefinition = $container->findDefinition($alias);
            $resourceOwnerDefinition->addMethodCall('setName', [end($aliasIdParts)]);
        }
    }
}