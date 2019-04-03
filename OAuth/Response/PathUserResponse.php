<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\Response;

/**
 * Class parsing the properties by given path options.
 *
 * @author Geoffrey Bachelet <geoffrey.bachelet@gmail.com>
 * @author Alexander <iam.asm89@gmail.com>
 * @author Joseph Bielawski <stloyd@gmail.com>
 */
class PathUserResponse extends AbstractUserResponse
{
    /**
     * @var array
     */
    protected $paths = array(
        'identifier' => null,
        'nickname' => null,
        'firstname' => null,
        'lastname' => null,
        'realname' => null,
        'email' => null,
        'profilepicture' => null,
        'followers' => null,
        'accounts' => null,
    );

    /**
     * {@inheritdoc}
     */
    public function getUsername()
    {
        return $this->getValueForPath('identifier');
    }

    /**
     * {@inheritdoc}
     */
    public function getNickname()
    {
        return $this->getValueForPath('nickname');
    }

    /**
     * {@inheritdoc}
     */
    public function getFirstName()
    {
        return $this->getValueForPath('firstname');
    }

    /**
     * {@inheritdoc}
     */
    public function getLastName()
    {
        return $this->getValueForPath('lastname');
    }

    /**
     * {@inheritdoc}
     */
    public function getRealName()
    {
        return $this->getValueForPath('realname');
    }

    /**
     * {@inheritdoc}
     */
    public function getEmail()
    {
        return $this->getValueForPath('email');
    }

    /**
     * {@inheritdoc}
     */
    public function getProfilePicture($page_id = null)
    {
        return $this->getValueForPath('profilepicture', null, null, $page_id);
    }

    /**
     * {@inheritdoc}
     */
    public function getFollowers($limit, $page_id = null)
    {
        return $this->getValueForPath('followers', $limit, null, $page_id);
    }

    /**
     * {@inheritdoc}
     */
    public function getPageId($page_level)
    {
        return $this->getValueForPath('page_id', null, $page_level);
    }

    /**
     * {@inheritdoc}
     */
    public function getPageAccessToken($page_id)
    {
        return $this->getValueForPath('page_access_token', null, null, $page_id);
    }

    /**
     * {@inheritdoc}
     */
    public function getPageLink($page_id)
    {
        return $this->getValueForPath('link', null, null, $page_id);
    }

    /**
     * {@inheritdoc}
     */
    public function getPageName($page_id = null)
    {
        return $this->getValueForPath('name', null, null, $page_id);
    }

    /**
     * {@inheritdoc}
     */
    public function getUploadId()
    {
        return $this->getValueForPath('uploadId');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccounts()
    {
        return $this->getValueForPath('accounts');
    }

    /**
     * {@inheritdoc}
     */
    public function getInstagramAccount($page_id)
    {
        return $this->getValueForPath('instagram', null, null, $page_id);
    }

    /**
     * Get the configured paths.
     *
     * @return array
     */
    public function getPaths()
    {
        return $this->paths;
    }

    /**
     * Configure the paths.
     *
     * @param array $paths
     */
    public function setPaths(array $paths)
    {
        $this->paths = array_merge($this->paths, $paths);
    }

    /**
     * @param string $name
     *
     * @return array|null
     */
    public function getPath($name)
    {
        return array_key_exists($name, $this->paths) ? $this->paths[$name] : null;
    }

    /**
     * Extracts a value from the response for a given path.
     *
     * @param string $path Name of the path to get the value for
     *
     * @return null|string
     */
    protected function getValueForPath($path, $limit = null, $page_level = null, $page_id = null)
    {
        $data = $this->data;
        if (!$data) {
            return null;
        }

        $steps = $this->getPath($path);
        if (!$steps) {
            return null;
        }

        if ($page_id) {
            $accountsPath = $this->getPath('accounts');

            if ($accountsPath) {
                $accounts = $this->getValue($accountsPath, $data);

                if ($accounts) {
                    $page_level = array_search($page_id, array_column($accounts, 'id'));

                    if($page_level === false){
                        return null;
                    }
                }
            }
        }

        if ($page_level) {
            $steps = preg_replace("|(\d+)|", $page_level, $steps);
        }

        if (is_array($steps)) {
            if (1 === count($steps)) {
                return $this->getValue(current($steps), $data);
            }

            $value = [];
            foreach ($steps as $step) {
                $value[] = $this->getValue($step, $data);
            }

            return trim(implode(' ', $value)) ? : null;
        }

        if (isset($limit)) {
            $value = $this->getValue($steps, $data);
            $cp = 0;
            while ($value < $limit and $cp != 5) {
                $cp++;
                $steps = preg_replace_callback("|(\d+)|", function ($matches) {
                    return ++$matches[1];
                }, $steps);
                $value = $this->getValue($steps, $data);
                preg_match("|(\d+)|", $steps, $level);
            }

            //return page level and value
            if ($value >= $limit and isset($level)) {
                return [$value, $level[1]];
            }

            return $value;
        }

        return $this->getValue($steps, $data);
    }

    /**
     * @param string $steps
     * @param array  $data
     *
     * @return null|string
     */
    private function getValue($steps, array $data)
    {
        $value = $data;
        foreach (explode('.', $steps) as $step) {
            if (!array_key_exists($step, $value)) {
                return null;
            }

            $value = $value[$step];
        }

        return $value;
    }
}
