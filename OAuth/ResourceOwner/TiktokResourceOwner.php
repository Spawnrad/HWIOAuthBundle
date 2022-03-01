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

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 *
 * TiktokResourceOwner.
 * @author Geoffrey Bachelet <geoffrey.bachelet@gmail.com>
 */
class TiktokResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritdoc}
     */
    protected $paths = [
        'identifier' => 'id',
        'name' => 'data.display_name',
        'profilepicture' => 'data.avatar_url',        
        'statusCode' => 'error.code',
        'error' => 'error.message',
    ];

    /**
     * {@inheritdoc}
     */
    public function getUserInformation(array $accessToken, array $extraParameters = [])
    {
        if ($this->options['appsecret_proof']) {
            $extraParameters['appsecret_proof'] = hash_hmac('sha256', $accessToken['access_token'], $this->options['client_secret']);
        }

        return parent::getUserInformation($accessToken, $extraParameters);
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationUrl($redirectUri, array $extraParameters = [])
    {
        if ($this->options['csrf']) {
            if (null === $this->state) {
                $this->state = $this->generateNonce();
            }

            $this->storage->save($this, $this->state, 'csrf_state');
        }

        $parameters = array_merge([
            'response_type' => 'code',
            'client_key' => $this->options['client_id'],
            'scope' => $this->options['scope'],
            'state' => $this->state ? urlencode($this->state) : null,
            'redirect_uri' => $redirectUri,
        ], $extraParameters);

        return parent::normalizeUrl($this->options['authorization_url'], $parameters);
    }    

    /**
     * {@inheritdoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults([
            'authorization_url' => 'https://open-api.tiktok.com/platform/oauth/connect/',
            'access_token_url' => 'https://open-api.tiktok.com/oauth/access_token/',
            'revoke_token_url' => 'https://open-api.tiktok.com/oauth/revoke/',
            'refresh_token_url' => 'https://open-api.tiktok.com/oauth/refresh_token',
            'infos_url' => 'https://open-api.tiktok.com/user/info/',
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
