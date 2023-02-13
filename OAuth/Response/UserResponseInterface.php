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

use HWI\Bundle\OAuthBundle\OAuth\ResponseInterface;
use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;

/**
 * @author Alexander <iam.asm89@gmail.com>
 * @author Joseph Bielawski <stloyd@gmail.com>
 */
interface UserResponseInterface extends ResponseInterface
{
    /**
     * @return string
     */
    public function getUsername();

    /**
     * Get the username to display.
     *
     * @return string
     */
    public function getNickname();

    /**
     * Get the first name of user.
     *
     * @return string|null
     */
    public function getFirstName();

    /**
     * Get the last name of user.
     *
     * @return string|null
     */
    public function getLastName();

    /**
     * Get the real name of user.
     *
     * @return string|null
     */
    public function getRealName();

    /**
     * Get the email address.
     *
     * @return string|null
     */
    public function getEmail();

    /**
     * Get the url to the profile picture.
     *
     * @return string|null
     */
    public function getProfilePicture($page_id = null);

    public function getPageId($page_level );

    /**
     * Get bio.
     *
     * @return string|null
     */
    public function getBio();

    /**
     * Get Accounts
     *
     * @return array|null
     */
    public function getAccounts();

    /**
     * Get Followers count
     *
     * @return string|null
     */
    public function getFollowers($limit = null, $page_id = null);

    /**
     * Get the access token used for the request.
     *
     * @return string
     */
    public function getAccessToken();

    /**
     * Get the access token used for the request.
     *
     * @return string|null
     */
    public function getRefreshToken();

    /**
     * Get oauth token secret used for the request.
     *
     * @return string|null
     */
    public function getTokenSecret();

    /**
     * Get the info when token will expire.
     *
     * @return string|null
     */
    public function getExpiresIn();

    /**
     * Set the raw token data from the request.
     *
     * @param OAuthToken $token
     */
    public function setOAuthToken(OAuthToken $token);

    /**
     * Get the raw token data from the request.
     *
     * @return OAuthToken
     */
    public function getOAuthToken();
}
