<?php

/*
 * This file is part of the Glavweb SecurityBundle package.
 *
 * (c) GLAVWEB <info@glavweb.ru>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Glavweb\SecurityBundle\Security\Authorization\Voter;

use Doctrine\Bundle\DoctrineBundle\Registry;
use Doctrine\Common\Annotations\Reader;
use Doctrine\ORM\EntityManager;
use Glavweb\SecurityBundle\Mapping\Annotation\Access;
use Glavweb\SecurityBundle\Security\AccessHandler;
use Glavweb\SecurityBundle\Util\RoleHierarchyUtil;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class AccessVoter
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 * @package Glavweb\SecurityBundle
 */
class AccessVoter implements VoterInterface
{
    /**
     * @var Registry
     */
    protected $doctrine;

    /**
     * @var AccessHandler
     */
    private $accessHandler;

    /**
     * @var Access
     */
    protected $accessAnnotation;

    /**
     * @var RoleHierarchyUtil
     */
    private $roleHierarchyUtil;

    /**
     * AccessVoter constructor.
     *
     * @param Registry          $doctrine
     * @param AccessHandler     $accessHandler
     * @param RoleHierarchyUtil $roleHierarchyUtil
     */
    public function __construct(Registry $doctrine, AccessHandler $accessHandler, RoleHierarchyUtil $roleHierarchyUtil)
    {
        $this->doctrine          = $doctrine;
        $this->accessHandler     = $accessHandler;
        $this->roleHierarchyUtil = $roleHierarchyUtil;
    }

    /**
     * Checks if the voter supports the given attribute.
     *
     * @param string $attribute An attribute
     *
     * @return bool true if this Voter supports the attribute, false otherwise
     */
    public function supportsAttribute($attribute)
    {
        return true;
    }

    /**
     * Checks if the voter supports the given class.
     *
     * @param string $class A class name
     *
     * @return bool true if this Voter can process the class
     */
    public function supportsClass($class)
    {
        return true;
    }

    /**
     * Returns the vote for the given parameters.
     *
     * This method must return one of the following constants:
     * ACCESS_GRANTED, ACCESS_DENIED, or ACCESS_ABSTAIN.
     *
     * @param TokenInterface $token      A TokenInterface instance
     * @param object|null $object     The object to secure
     * @param array $attributes An array of attributes associated with the method being invoked
     *
     * @return int either ACCESS_GRANTED, ACCESS_ABSTAIN, or ACCESS_DENIED
     */
    public function vote(TokenInterface $token, $object, array $attributes)
    {
        $class = get_class($object);

        if (!$this->supportsClass($class)) {
            return VoterInterface::ACCESS_ABSTAIN;
        }

        if (!method_exists($object, 'getId')) {
            return VoterInterface::ACCESS_ABSTAIN;
        }

        /** @var UserInterface $user */
        $user = $token->getUser();
        if (!$user instanceof UserInterface || !method_exists($user, 'getId')) {
            return VoterInterface::ACCESS_ABSTAIN;
        }
        $userRoles = $this->roleHierarchyUtil->getUserRoles($user);

        $alias = 't';
        foreach ($attributes as $attribute) {
            if (in_array($attribute, $userRoles)) {
                return VoterInterface::ACCESS_GRANTED;
            }

            $action = $this->accessHandler->getActionByRole($class, $attribute);
            if (!$action) {
                continue;
            }

            $conditions = [];
            $additionalRoles = $this->accessHandler->getAdditionalRoles($class);
            foreach ($additionalRoles as $additionalRoleName => $additionalRoleData) {
                $role = $this->accessHandler->getRole($class, $action, $additionalRoleName);

                if (isset($additionalRoleData['condition']) && in_array($role, $userRoles)) {
                    $conditions[] = $this->accessHandler->conditionPlaceholder($additionalRoleData['condition'], $alias, $user);
                }
            }

            if ($conditions) {
                $isExistsObject = $this->isExistsObjectByConditions($object, $conditions, $alias);
                if ($isExistsObject) {
                    return VoterInterface::ACCESS_GRANTED;
                }
            }
        }

        return VoterInterface::ACCESS_ABSTAIN;
    }

    /**
     * @param object $object
     * @param array  $conditions
     * @param string $alias
     * @return bool
     */
    private function isExistsObjectByConditions($object, array $conditions, $alias)
    {
        /** @var EntityManager $em */
        $em = $this->doctrine->getManager();
        $class = get_class($object);

        $qb = $em->getRepository($class)->createQueryBuilder($alias);
        $expr = $qb->expr();
        $qb
            ->select('COUNT(' . $alias . ')')
            ->where($alias . '.id = :object_id')
            ->andWhere($expr->orX()->addMultiple($conditions))
            ->setParameter('object_id', $object->getId())
        ;
        $isValid = (bool)$qb->getQuery()->getSingleScalarResult();

        return $isValid;
    }
}