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
 * FacebookResourceOwner.
 *
 * @author Geoffrey Bachelet <geoffrey.bachelet@gmail.com>
 */
class FacebookResourceOwner extends GenericOAuth2ResourceOwner
{
    protected array $paths = [
        'identifier' => 'id',
        'name' => 'accounts.data.0.name',
        'profilepicture' => 'accounts.data.0.picture.data.url',
        'followers' => 'accounts.data.0.followers_count',
        'page_id' => 'accounts.data.0.id',
        'page_access_token' => 'accounts.data.0.access_token',
        'link' => 'accounts.data.0.link',
        'accounts' => 'accounts.data',
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

    public function getAccessToken(Request $request, $redirectUri, array $extraParameters = [])
    {
        $parameters = [];
        if ($request->query->has('fb_source')) {
            $parameters['fb_source'] = $request->query->get('fb_source');
        }

        if ($request->query->has('fb_appcenter')) {
            $parameters['fb_appcenter'] = $request->query->get('fb_appcenter');
        }

        return parent::getAccessToken($request, $this->normalizeUrl($redirectUri, $parameters), $extraParameters);
    }

    public function refreshAccessToken($access_token, array $extraParameters = [])
    {
        $parameters = array_merge([
            'fb_exchange_token' => $access_token,
            'grant_type' => 'fb_exchange_token',
        ], $extraParameters);

        $response = $this->doGetTokenRequest($this->options['access_token_url'], $parameters);
        $response = $this->getResponseContent($response);

        $this->validateResponseContent($response);

        return $response;
    }

    public function revokeToken($token)
    {
        $parameters = [
            'client_id' => $this->options['client_id'],
            'client_secret' => $this->options['client_secret'],
        ];

        $response = $this->httpRequest($this->normalizeUrl($this->options['revoke_token_url'], ['access_token' => $token]), $parameters, [], 'DELETE');

        return 200 === $response->getStatusCode();
    }

    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults([
            'authorization_url' => 'https://facebook.com/v21.0/dialog/oauth',
            'access_token_url' => 'https://graph.facebook.com/v21.0/oauth/access_token',
            'revoke_token_url' => 'https://graph.facebook.com/v21.0/me/permissions',
            'infos_url' => 'https://graph.facebook.com/v21.0/me',
            'use_commas_in_scope' => true,
            'display' => null,
            'auth_type' => null,
            'appsecret_proof' => false,
        ]);

        $resolver
            ->setAllowedValues('display', ['page', 'popup', 'touch', null]) // @link https://developers.facebook.com/docs/reference/dialogs/#display
            ->setAllowedValues('auth_type', ['rerequest', null]) // @link https://developers.facebook.com/docs/reference/javascript/FB.login/
            ->setAllowedTypes('appsecret_proof', 'bool') // @link https://developers.facebook.com/docs/graph-api/securing-requests
        ;
    }
}
