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
 * Class RoleHierarchyUtil
 * 
 * @author Andrey Nilov <nilov@glavweb.ru>
 * @package Glavweb\SecurityBundle
 */
class RoleHierarchyUtil
{
    /**
     * @var array
     */
    private $roleHierarchy;

    /**
     * RoleHierarchyUtil constructor.
     *
     * @param array $roleHierarchy
     */
    public function __construct(array $roleHierarchy)
    {
        $this->roleHierarchy = $roleHierarchy;
    }
    
    /**
     * @param UserInterface $user
     * @return mixed
     */
    public function getUserRoles(UserInterface $user)
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
     * @return array
     */
    public function getRoleByHierarchy($targetRole)
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