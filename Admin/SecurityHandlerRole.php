<?php

/*
 * This file is part of the Glavweb SecurityBundle package.
 *
 * (c) GLAVWEB <info@glavweb.ru>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Glavweb\SecurityBundle\Admin;

use Glavweb\SecurityBundle\Security\AccessHandler;
use Sonata\AdminBundle\Admin\AdminInterface;
use Sonata\AdminBundle\Security\Handler\SecurityHandlerInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException;

/**
 * Class SecurityHandlerRole.
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 */
class SecurityHandlerRole implements SecurityHandlerInterface
{
    /**
     * @var array
     */
    protected $roleReplaces = [
        'LIST' => 'LIST',
        'VIEW' => 'VIEW',
        'CREATE' => 'CREATE',
        'EDIT' => 'EDIT',
        'DELETE' => 'DELETE',
        'EXPORT' => 'EXPORT',
    ];

    public function __construct(
        protected AuthorizationCheckerInterface $authorizationChecker,
        private readonly AccessHandler $accessHandler,
        /**
         * @var mixed[]
         */
        protected array $superAdminRoles,
    ) {
    }

    public function isGranted(AdminInterface $admin, $attributes, ?object $object = null): bool
    {
        if (!\is_string($attributes)) {
            throw new \InvalidArgumentException('The attributes must be a string.');
        }

        $attribute = strtoupper($attributes);
        $attribute = $this->roleReplaces[$attribute] ?? $attribute;

        if (!str_starts_with((string) $attribute, 'ROLE_')) {
            $attribute = \sprintf($this->getBaseRole($admin), $attribute);
        }

        try {
            if ($this->authorizationChecker->isGranted($this->superAdminRoles)) {
                return true;
            }

            return $this->authorizationChecker->isGranted($attribute, $object);
        } catch (AuthenticationCredentialsNotFoundException) {
            return false;
        }
    }

    public function getBaseRole(AdminInterface $admin): string
    {
        $baseRole = $this->accessHandler->getBaseRole($admin->getClass());

        if (!$baseRole) {
            return 'ROLE_'.str_replace('.', '_', strtoupper($admin->getCode())).'_%s';
        }

        return $baseRole;
    }

    public function buildSecurityInformation(AdminInterface $admin): array
    {
        return [];
    }

    public function createObjectSecurity(AdminInterface $admin, $object): void
    {
    }

    public function deleteObjectSecurity(AdminInterface $admin, $object): void
    {
    }
}
