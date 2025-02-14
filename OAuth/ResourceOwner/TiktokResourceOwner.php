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

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use HWI\Bundle\OAuthBundle\Security\OAuthErrorHandler;
use Symfony\Component\HttpFoundation\Request as HttpRequest;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * TiktokResourceOwner.
 *
 * @author Geoffrey Bachelet <geoffrey.bachelet@gmail.com>
 */
class TiktokResourceOwner extends GenericOAuth2ResourceOwner
{
    protected array $paths = [
        'identifier' => 'data.user.open_id',
        'name' => 'data.user.display_name',
        'profilepicture' => 'data.user.avatar_url',
        'followers' => 'data.user.follower_count',
        'bio' => 'data.user.bio_description',
        'link' => 'data.user.profile_deep_link',
        'statusCode' => 'error.code',
        'error' => 'error.message',
    ];

    public function getUserInformation(array $accessToken, array $extraParameters = [])
    {
        $content = $this->httpRequest(
            $this->normalizeUrl($this->options['infos_url'], $extraParameters),
            null,
            ['Authorization' => 'Bearer '.$accessToken['access_token']]
        );

        $response = $this->getUserResponse();
        $response->setData($content->toArray(false));
        $response->setResourceOwner($this);
        $response->setOAuthToken(new OAuthToken($accessToken));

        return $response;
    }

    public function getAccessToken(HttpRequest $request, $redirectUri, array $extraParameters = [])
    {
        OAuthErrorHandler::handleOAuthError($request);

        $parameters = array_merge([
            'code' => $request->query->get('code'),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $redirectUri,
        ], $extraParameters);

        $response = $this->doGetTokenRequest($this->options['access_token_url'], $parameters);
        $response = $this->getResponseContent($response);

        $this->validateResponseContent($response);

        return $response;
    }

    public function refreshAccessToken($refreshToken, array $extraParameters = [])
    {
        $parameters = array_merge([
            'refresh_token' => $refreshToken,
            'grant_type' => 'refresh_token',
        ], $extraParameters);

        $response = $this->doGetTokenRequest($this->options['refresh_token_url'], $parameters);
        $response = $this->getResponseContent($response);

        $this->validateResponseContent($response);

        return $response;
    }

    public function getAuthorizationUrl($redirectUri, array $extraParameters = [])
    {
        if ($this->options['csrf']) {
            parent::handleCsrfToken();
        }

        $parameters = array_merge([
            'response_type' => 'code',
            'client_key' => $this->options['client_id'],
            'scope' => $this->options['scope'],
            'state' => $this->state->encode(),
            'redirect_uri' => $redirectUri,
        ], $extraParameters);

        return parent::normalizeUrl($this->options['authorization_url'], $parameters);
    }

    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults([
            'authorization_url' => 'https://www.tiktok.com/v2/auth/authorize/',
            'access_token_url' => 'https://open.tiktokapis.com/v2/oauth/token/',
            'revoke_token_url' => 'https://open.tiktokapis.com/v2/oauth/revoke/',
            'refresh_token_url' => 'https://open.tiktokapis.com/v2/oauth/token/',
            'infos_url' => 'https://open.tiktokapis.com/v2/user/info/',
            'use_authorization_to_get_token' => false,
            'use_commas_in_scope' => false,
            'scope' => 'user.info.basic,video.list',
            'display' => null,
            'auth_type' => null,
            'appsecret_proof' => false,
            'client_attr_name' => 'client_key',
            'use_bearer_authorization' => false,
            'fields' => ['open_id', 'union_id', 'avatar_url', 'display_name'],
        ]);

        $resolver
            ->setAllowedValues('display', ['page', 'popup', 'touch', null])
            ->setAllowedValues('auth_type', ['rerequest', null])
            ->setAllowedTypes('appsecret_proof', 'bool');
    }
}
