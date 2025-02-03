<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * @author Geoffrey Bachelet <geoffrey.bachelet@gmail.com>
 */
class PinterestResourceOwner extends GenericOAuth2ResourceOwner
{
    protected array $paths = [
        'identifier' => 'id',
        'name' => 'username',
        'profilepicture' => 'profile_image',
        'link' => '',
        'statusCode' => 'error.code',
        'error' => 'error.message',
    ];

    public function getUserInformation(array $accessToken, array $extraParameters = [])
    {
        if ($this->options['appsecret_proof']) {
            $extraParameters['appsecret_proof'] = hash_hmac('sha256', $accessToken['access_token'], $this->options['client_secret']);
        }

        return parent::getUserInformation($accessToken, $extraParameters);
    }

    public function getAuthorizationUrl($redirectUri, array $extraParameters = [])
    {
        $extraOptions = [];
        if (isset($this->options['display'])) {
            $extraOptions['display'] = $this->options['display'];
        }

        if (isset($this->options['auth_type'])) {
            $extraOptions['auth_type'] = $this->options['auth_type'];
        }

        return parent::getAuthorizationUrl($redirectUri, array_merge($extraOptions, $extraParameters));
    }

    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults([
            'authorization_url' => 'https://www.pinterest.com/oauth/',
            'access_token_url' => 'https://api.pinterest.com/v5/oauth/token',
            'revoke_token_url' => '',
            'infos_url' => 'https://api.pinterest.com/v5/user_account',
            'use_commas_in_scope' => true,
            'display' => null,
            'auth_type' => null,
            'appsecret_proof' => false,
        ]);

        $resolver
            ->setAllowedValues('display', ['page', 'popup', 'touch', null])
            ->setAllowedValues('auth_type', ['rerequest', null])
            ->setAllowedTypes('appsecret_proof', 'bool')
        ;
    }
}
