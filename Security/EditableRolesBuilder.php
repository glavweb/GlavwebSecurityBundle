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

use Doctrine\Bundle\DoctrineBundle\Registry;
use Doctrine\ORM\Mapping\ClassMetadata;

/**
 * Class EditableRolesBuilder.
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 */
class EditableRolesBuilder
{
    /**
     * @internal param Reader $annotationReader
     */
    public function __construct(
        /**
         * @var
         */
        protected Registry $doctrine,
        protected AccessHandler $accessHandler,
        /**
         * @var mixed[]
         */
        protected array $rolesHierarchy = [],
    ) {
    }

    /**
     * @return array<int, int[]|string[]|non-empty-array<array<string, mixed>>[]>
     */
    public function getRoles(): array
    {
        /** @var ClassMetadata[] $allMetaData */
        $actions = $this->accessHandler->getActions();
        $actionsOnlyObjects = $this->accessHandler->getActions(true);
        $em = $this->doctrine->getManager();

        // Entity roles
        $entityRoles = [];
        $allMetaData = $em->getMetadataFactory()->getAllMetadata();
        foreach ($allMetaData as $metaData) {
            $reflectionClass = $metaData->getReflectionClass();
            $accessAttribute = $this->accessHandler->getAccessAttribute($reflectionClass);

            if (!$accessAttribute) {
                continue;
            }

            $entityClass = $metaData->getName();
            $entityName = $accessAttribute->getName() ?: current(\array_slice(explode('\\', $entityClass), -1));

            // Master
            $entityRoles[$entityName]['master']['name'] = 'Master';
            foreach ($actions as $action) {
                $role = $this->accessHandler->getRole($reflectionClass, $action);
                $entityRoles[$entityName]['master']['roles'][$role] = $role;
            }

            // Additional Roles
            $additionalRoles = $accessAttribute->getAdditionalRoles();
            foreach ($additionalRoles as $additionalRoleName => $additionalRoleData) {
                $roleTitle = $additionalRoleData['name'] ?? ucfirst((string) $additionalRoleName);
                $entityRoles[$entityName][$additionalRoleName]['name'] = $roleTitle;

                foreach ($actionsOnlyObjects as $action) {
                    $role = $this->accessHandler->getRole($reflectionClass, $action, $additionalRoleName);
                    $entityRoles[$entityName][$additionalRoleName]['roles'][$role] = $role;
                }
            }
        }

        // Get roles from the service container
        $securityRoles = [];
        foreach (array_keys($this->rolesHierarchy) as $name) {
            $securityRoles[$name] = $name;
        }

        return [$entityRoles, $securityRoles];
    }
}
