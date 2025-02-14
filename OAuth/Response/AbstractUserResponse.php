<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\Response;

use HWI\Bundle\OAuthBundle\OAuth\ResourceOwnerInterface;
use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * @author Alexander <iam.asm89@gmail.com>
 */
abstract class AbstractUserResponse implements UserResponseInterface
{
    /**
     * @var array
     */
    protected $data;

    /**
     * @var ResourceOwnerInterface
     */
    protected $resourceOwner;

    /**
     * @var OAuthToken
     */
    protected $oAuthToken;

    public function getEmail()
    {
        return null;
    }

    public function getProfilePicture($page_id = null)
    {
        return null;
    }

    public function getAccessToken()
    {
        return $this->oAuthToken->getAccessToken();
    }

    public function getRefreshToken()
    {
        return $this->oAuthToken->getRefreshToken();
    }

    public function getTokenSecret()
    {
        return $this->oAuthToken->getTokenSecret();
    }

    public function getExpiresIn()
    {
        return $this->oAuthToken->getExpiresIn();
    }

    public function setOAuthToken(OAuthToken $token)
    {
        $this->oAuthToken = $token;
    }

    public function getOAuthToken()
    {
        return $this->oAuthToken;
    }

    public function getData()
    {
        return $this->data;
    }

    public function setData($data)
    {
        if (\is_array($data)) {
            $this->data = $data;
        } else {
            // First check that response exists, due too bug: https://bugs.php.net/bug.php?id=54484
            if (!$data) {
                $this->data = [];
            } else {
                $this->data = json_decode($data, true);

                if (JSON_ERROR_NONE !== json_last_error()) {
                    throw new AuthenticationException('Response is not a valid JSON code.');
                }
            }
        }
    }

    public function getResourceOwner()
    {
        return $this->resourceOwner;
    }

    public function setResourceOwner(ResourceOwnerInterface $resourceOwner)
    {
        $this->resourceOwner = $resourceOwner;
    }
}
