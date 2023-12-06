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
 * Class SecurityHandlerRole
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 * @package Glavweb\SecurityBundle
 */
class SecurityHandlerRole implements SecurityHandlerInterface
{
    /**
     * @var AuthorizationCheckerInterface
     */
    protected $authorizationChecker;

    /**
     * @var AccessHandler
     */
    private $accessHandler;

    /**
     * @var array
     */
    protected $superAdminRoles;

    /**
     * @var array
     */
    protected $roleReplaces = [
        'LIST'   => 'LIST',
        'VIEW'   => 'VIEW',
        'CREATE' => 'CREATE',
        'EDIT'   => 'EDIT',
        'DELETE' => 'DELETE',
        'EXPORT' => 'EXPORT',
    ];

    /**
     * @param AuthorizationCheckerInterface $authorizationChecker
     * @param AccessHandler $accessHandler
     * @param array $superAdminRoles
     */
    public function __construct(AuthorizationCheckerInterface $authorizationChecker, AccessHandler $accessHandler, array $superAdminRoles)
    {
        $this->authorizationChecker = $authorizationChecker;
        $this->accessHandler        = $accessHandler;
        $this->superAdminRoles      = $superAdminRoles;
    }

    /**
     * {@inheritdoc}
     */
    public function isGranted(AdminInterface $admin, $attributes, $object = null)
    {
        if (!is_array($attributes)) {
            $attributes = array($attributes);
        }

        foreach ($attributes as $pos => $attribute) {
            $attribute = strtoupper($attribute);
            $attribute = isset($this->roleReplaces[$attribute]) ? $this->roleReplaces[$attribute] : $attribute;

            if (strpos($attribute, 'ROLE_') !== 0) {
                $attribute = sprintf($this->getBaseRole($admin), $attribute);
            }

            $attributes[$pos] = $attribute;
        }

        try {
            return 
                $this->authorizationChecker->isGranted($this->superAdminRoles) ||
                $this->authorizationChecker->isGranted($attributes, $object)
            ;
            
        } catch (AuthenticationCredentialsNotFoundException $e) {
            return false;
            
        } catch (\Exception $e) {
            throw $e;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseRole(AdminInterface $admin)
    {
        $baseRole = $this->accessHandler->getBaseRole($admin->getClass());

        if (!$baseRole) {
            $baseRole = 'ROLE_' . str_replace('.', '_', strtoupper($admin->getCode())) . '_%s';
        }

        return $baseRole;
    }

    /**
     * {@inheritdoc}
     */
    public function buildSecurityInformation(AdminInterface $admin)
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function createObjectSecurity(AdminInterface $admin, $object)
    {}

    /**
     * {@inheritdoc}
     */
    public function deleteObjectSecurity(AdminInterface $admin, $object)
    {}
}
