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
use Doctrine\ORM\EntityManager;
use Glavweb\SecurityBundle\Security\AccessHandler;
use Glavweb\SecurityBundle\Util\RoleHierarchyUtil;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class AccessVoter.
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 */
class AccessVoter implements VoterInterface
{
    /**
     * AccessVoter constructor.
     */
    public function __construct(
        protected Registry $doctrine,
        private readonly AccessHandler $accessHandler,
        private readonly RoleHierarchyUtil $roleHierarchyUtil,
    ) {
    }

    /**
     * Checks if the voter supports the given class.
     *
     * @param string $class A class name
     *
     * @return bool true if this Voter can process the class
     */
    public function supportsClass($class): bool
    {
        return true;
    }

    /**
     * Returns the vote for the given parameters.
     *
     * This method must return one of the following constants:
     * ACCESS_GRANTED, ACCESS_DENIED, or ACCESS_ABSTAIN.
     *
     * @return int either ACCESS_GRANTED, ACCESS_ABSTAIN, or ACCESS_DENIED
     */
    public function vote(TokenInterface $token, mixed $subject, array $attributes, ?Vote $vote = null): int
    {
        if (!\is_object($subject)) {
            return VoterInterface::ACCESS_ABSTAIN;
        }

        $class = $subject::class;

        if (!$this->supportsClass($class)) {
            return VoterInterface::ACCESS_ABSTAIN;
        }

        if (!method_exists($subject, 'getId')) {
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
            if (\in_array($attribute, $userRoles)) {
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

                if (isset($additionalRoleData['condition']) && \in_array($role, $userRoles)) {
                    $conditions[] = $this->accessHandler->conditionPlaceholder($additionalRoleData['condition'], $alias, $user);
                }
            }

            if ($conditions) {
                $isExistsObject = $this->isExistsObjectByConditions($subject, $conditions, $alias);
                if ($isExistsObject) {
                    return VoterInterface::ACCESS_GRANTED;
                }
            }
        }

        return VoterInterface::ACCESS_ABSTAIN;
    }

    private function isExistsObjectByConditions(object $object, array $conditions, string $alias): bool
    {
        /** @var EntityManager $em */
        $em = $this->doctrine->getManager();
        $class = $object::class;

        $qb = $em->getRepository($class)->createQueryBuilder($alias);
        $expr = $qb->expr();
        $qb
            ->select('COUNT('.$alias.')')
            ->where($alias.'.id = :object_id')
            ->andWhere($expr->orX()->addMultiple($conditions))
            ->setParameter('object_id', $object->getId())
        ;

        return (bool) $qb->getQuery()->getSingleScalarResult();
    }
}
