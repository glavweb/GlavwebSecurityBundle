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
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * Class QueryBuilderFilter.
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 */
class QueryBuilderFilter
{
    /**
     * QueryBuilderFilter constructor.
     */
    public function __construct(
        private readonly AccessHandler $accessHandler,
        private readonly AuthorizationCheckerInterface $authorizationChecker,
    ) {
    }

    /**
     * @param string $class
     * @param string $alias
     *
     * @throws AccessDeniedException
     */
    protected function filter(QueryBuilder $queryBuilder, $class, $alias): QueryBuilder
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
     */
    public function getSecurityCondition($class): ?string
    {
        $accessHandler = $this->accessHandler;
        $authorizationChecker = $this->authorizationChecker;

        $securityConditions = [];
        if ($accessHandler->hasAccessAttribute($class)) {
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
