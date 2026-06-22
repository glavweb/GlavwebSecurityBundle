<?php

/*
 * This file is part of the Glavweb SecurityBundle package.
 *
 * (c) GLAVWEB <info@glavweb.ru>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Glavweb\SecurityBundle\Util;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class RoleHierarchyUtil.
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 */
class RoleHierarchyUtil
{
    /**
     * RoleHierarchyUtil constructor.
     */
    public function __construct(private array $roleHierarchy)
    {
    }

    /**
     * @return mixed[]
     */
    public function getUserRoles(UserInterface $user): array
    {
        $userRoles = $user->getRoles();

        $roles = [];
        foreach ($userRoles as $role) {
            $roles[] = $role;

            if (isset($this->roleHierarchy[$role])) {
                $roles = array_unique(array_merge(
                    $roles,
                    $this->getRoleByHierarchy($role)
                ));
            }
        }

        return $roles;
    }

    /**
     * @param string $targetRole
     */
    public function getRoleByHierarchy($targetRole): array
    {
        $roles = [];

        if (isset($this->roleHierarchy[$targetRole])) {
            foreach ($this->roleHierarchy[$targetRole] as $role) {
                $roles[] = $role;

                if (isset($this->roleHierarchy[$role])) {
                    $roles = array_unique(array_merge(
                        $roles,
                        $this->getRoleByHierarchy($role)
                    ));
                }
            }
        }

        return $roles;
    }
}
