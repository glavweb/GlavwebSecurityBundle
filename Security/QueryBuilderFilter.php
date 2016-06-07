<?php

/*
 * This file is part of the Glavweb SecurityBundle package.
 *
 * (c) GLAVWEB <info@glavweb.ru>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Glavweb\SecurityBundle\Security;

use Doctrine\ORM\QueryBuilder;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * Class QueryBuilderFilter
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 * @package Glavweb\SecurityBundle
 */
class QueryBuilderFilter
{
    /**
     * @var AccessHandler
     */
    private $accessHandler;

    /**
     * @var AuthorizationCheckerInterface
     */
    private $authorizationChecker;

    /**
     * QueryBuilderFilter constructor.
     *
     * @param AccessHandler $accessHandler
     * @param AuthorizationCheckerInterface $authorizationChecker
     */
    public function __construct(AccessHandler $accessHandler, AuthorizationCheckerInterface $authorizationChecker)
    {
        $this->accessHandler        = $accessHandler;
        $this->authorizationChecker = $authorizationChecker;
    }

    /**
     * @param QueryBuilder $queryBuilder
     * @param string $class
     * @param string $alias
     * @return QueryBuilder
     * @throws AccessDeniedException
     */
    protected function filter(QueryBuilder $queryBuilder, $class, $alias)
    {
        $condition = $this->getSecurityCondition($class);

        if ($condition) {
            $preparedCondition = $this->accessHandler->conditionPlaceholder($condition, $alias);
            $queryBuilder->andWhere($preparedCondition);
        }

        return $queryBuilder;
    }

    /**
     * @param string $class
     * @return string|null
     */
    public function getSecurityCondition($class)
    {
        $accessHandler        = $this->accessHandler;
        $authorizationChecker = $this->authorizationChecker;

        $securityConditions = [];
        if ($accessHandler->hasAccessAnnotation($class)) {
            $masterViewRole = $accessHandler->getRole($class, 'VIEW');

            if (!$authorizationChecker->isGranted($masterViewRole)) {
                $additionalRoles = $accessHandler->getAdditionalRoles($class);
                foreach ($additionalRoles as $additionalRoleName => $additionalRoleData) {
                    $role = $accessHandler->getRole($class, 'VIEW', $additionalRoleName);

                    if (isset($additionalRoleData['condition']) && $authorizationChecker->isGranted($role)) {
                        $securityConditions[] = $additionalRoleData['condition'];
                    }
                }

                if (!$securityConditions) {
                    throw new AccessDeniedException();
                }
            }
        }

        if (!$securityConditions) {
            return null;
        }

        return implode(' OR ', $securityConditions);
    }
}