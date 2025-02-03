<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\Security\Core\Exception;

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\AbstractOAuthToken;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;

if (class_exists(UserNotFoundException::class)) {
    final class AccountNotLinkedException extends UserNotFoundException implements OAuthAwareExceptionInterface
    {
        private ?string $resourceOwnerName = null;

        public function __serialize(): array
        {
            return [
                $this->resourceOwnerName,
                parent::__serialize(),
            ];
        }

        public function __unserialize(array $data): void
        {
            [
                $this->resourceOwnerName,
                $parentData,
            ] = $data;

            parent::__unserialize($parentData);
        }

        public function getMessageKey(): string
        {
            return 'Account could not be linked correctly.';
        }

        public function getAccessToken(): string
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getAccessToken();
        }

        public function getRawToken(): array
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getRawToken();
        }

        public function getRefreshToken(): ?string
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getRefreshToken();
        }

        public function getExpiresIn(): ?int
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getExpiresIn();
        }

        public function getTokenSecret(): ?string
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getTokenSecret();
        }

        public function getResourceOwnerName(): ?string
        {
            return $this->resourceOwnerName;
        }

        public function setResourceOwnerName($resourceOwnerName): void
        {
            $this->resourceOwnerName = $resourceOwnerName;
        }
    }
} else {
    final class AccountNotLinkedException extends UsernameNotFoundException implements OAuthAwareExceptionInterface
    {
        private ?string $resourceOwnerName = null;

        public function __serialize(): array
        {
            return [
                $this->resourceOwnerName,
                parent::__serialize(),
            ];
        }

        public function __unserialize(array $data): void
        {
            [
                $this->resourceOwnerName,
                $parentData,
            ] = $data;

            parent::__unserialize($parentData);
        }

        public function getMessageKey(): string
        {
            return 'Account could not be linked correctly.';
        }

        public function getAccessToken(): string
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getAccessToken();
        }

        public function getRawToken(): array
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getRawToken();
        }

        public function getRefreshToken(): ?string
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getRefreshToken();
        }

        public function getExpiresIn(): ?int
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getExpiresIn();
        }

        public function getTokenSecret(): ?string
        {
            /** @var AbstractOAuthToken $token */
            $token = $this->getToken();

            return $token->getTokenSecret();
        }

        public function getResourceOwnerName(): ?string
        {
            return $this->resourceOwnerName;
        }

        public function setResourceOwnerName($resourceOwnerName): void
        {
            $this->resourceOwnerName = $resourceOwnerName;
        }
    }
}
