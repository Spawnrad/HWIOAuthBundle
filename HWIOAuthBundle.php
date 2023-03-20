<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle;

use HWI\Bundle\OAuthBundle\DependencyInjection\CompilerPass\EnableRefreshOAuthTokenListenerCompilerPass;
use HWI\Bundle\OAuthBundle\DependencyInjection\CompilerPass\RefreshOAuthTokenCompilerPass;
use HWI\Bundle\OAuthBundle\DependencyInjection\CompilerPass\ResourceOwnerCompilerPass;
use HWI\Bundle\OAuthBundle\DependencyInjection\Security\Factory\OAuthAuthenticatorFactory;
use HWI\Bundle\OAuthBundle\DependencyInjection\Security\Factory\OAuthFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;

/**
 * @author Geoffrey Bachelet <geoffrey.bachelet@gmail.com>
 * @author Alexander <geoffrey.bachelet@gmail.com>
 */
class HWIOAuthBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        /** @var SecurityExtension $extension */
        $extension = $container->getExtension('security');

        $firewallNames = $this->extension->getFirewallNames();

        if (method_exists($extension, 'addAuthenticatorFactory')) {
            $extension->addAuthenticatorFactory(new OAuthAuthenticatorFactory($firewallNames));
        } elseif (interface_exists(AuthenticationProviderInterface::class)) {
            // @phpstan-ignore-next-line Symfony 4.4 BC layer
            $extension->addSecurityListenerFactory(new OAuthFactory($firewallNames));
            $container->addCompilerPass(new RefreshOAuthTokenCompilerPass());
        } else {
            // @phpstan-ignore-next-line Symfony < 5.4 BC layer
            $extension->addSecurityListenerFactory(new OAuthAuthenticatorFactory($firewallNames));
        }

        $container->addCompilerPass(new ResourceOwnerCompilerPass());
        $container->addCompilerPass(new EnableRefreshOAuthTokenListenerCompilerPass());
    }

    /**
     * {@inheritdoc}
     */
    public function getContainerExtension(): ?ExtensionInterface
    {
        // return the right extension instead of "auto-registering" it. Now the
        // alias can be hwi_oauth instead of hwi_o_auth.
        return $this->extension ?: $this->extension = $this->createContainerExtension();
    }
}