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

use Doctrine\Common\Annotations\Reader;
use Glavweb\SecurityBundle\Mapping\Annotation\Access;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class AccessHandler
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 * @package Glavweb\SecurityBundle
 */
class AccessHandler
{
    /**
     * @var array
     */
    private static $accessAnnotationCache = [];

    /**
     * @var array
     */
    private $actions = ['CREATE', 'LIST', 'VIEW', 'EDIT', 'DELETE', 'EXPORT'];

    /**
     * @var Reader
     */
    protected $annotationReader;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var \Twig_Environment
     */
    private $twigEnvironment;

    /**
     * AccessHandler constructor.
     *
     * @param Reader $annotationReader
     * @param TokenStorageInterface $tokenStorage
     */
    public function __construct(Reader $annotationReader, TokenStorageInterface $tokenStorage)
    {
        $this->annotationReader = $annotationReader;
        $this->tokenStorage     = $tokenStorage;
    }

    /**
     * @param bool $onlyForObjects
     * @return array
     */
    public function getActions($onlyForObjects = false)
    {
        $actions = $this->actions;

        if ($onlyForObjects) {
            $actions = array_filter($actions, function ($item) {
                return !in_array($item, ['CREATE', 'LIST']);
            });
        }

        return $actions;
    }

    /**
     * @param string $class
     * @return array|null
     */
    public function getAdditionalRoles($class)
    {
        $accessAnnotation = $this->getAccessAnnotation($class);
        if ($accessAnnotation instanceof Access) {
            return $accessAnnotation->getAdditionalRoles();
        }

        return null;
    }

    /**
     * @param string $class
     * @return string|null
     */
    public function getBaseRole($class)
    {
        $accessAnnotation = $this->getAccessAnnotation($class);
        if ($accessAnnotation instanceof Access) {
            return $accessAnnotation->getBaseRole();
        }

        return null;
    }

    /**
     * @param string $class
     * @param string $role
     * @return bool
     */
    public function checkRole($class, $role)
    {
        return (bool)$this->getActionByRole($class, $role);
    }

    /**
     * @param string $class
     * @param string $role
     * @return string|null
     */
    public function getActionByRole($class, $role)
    {
        $baseRole = $this->getBaseRole($class);

        if (!$baseRole) {
            return false;
        }

        foreach ($this->actions as $action) {
            if ($this->makeRole($baseRole, $action) == $role) {
                return $action;
            }
        }

        return null;
    }

    /**
     * @param string $class
     * @param string $action
     * @param string $additionalRole
     * @return null|string
     */
    public function getRole($class, $action, $additionalRole = null)
    {
        $baseRole = $this->getBaseRole($class);

        if (!$baseRole) {
            return null;
        }

        return $this->makeRole($baseRole, strtoupper($action), $additionalRole);
    }

    /**
     * @param string $baseRole
     * @param string $action
     * @param string $additionalRole
     * @return null|string
     */
    protected function makeRole($baseRole, $action, $additionalRole = null)
    {
        $role = sprintf($baseRole, strtoupper($action));

        if ($additionalRole) {
            $role .= '__' . strtoupper($additionalRole);
        }

        return $role;
    }

    /**
     * @param string $class
     * @return bool
     */
    public function hasAccessAnnotation($class)
    {
        return (bool)$this->getAccessAnnotation($class);
    }

    /**
     * @param string|\ReflectionClass $class
     * @return Access|null
     */
    public function getAccessAnnotation($class)
    {
        $className = $class;
        if ($class instanceof \ReflectionClass) {
            $className = $class->getName();
        }

        if (!isset(self::$accessAnnotationCache[$className])) {
            $reflectionClass = $class;
            if (!$reflectionClass instanceof \ReflectionClass) {
                $reflectionClass = new \ReflectionClass($reflectionClass);
            }

            // If is a Proxy
            if (in_array(Proxy::class, $reflectionClass->getInterfaceNames())) {
                $reflectionClass = new \ReflectionClass($reflectionClass->getParentClass()->getName());
            }
            
            self::$accessAnnotationCache[$className] = $this->annotationReader->getClassAnnotation(
                $reflectionClass,
                'Glavweb\SecurityBundle\Mapping\Annotation\Access'
            );
        }

        return self::$accessAnnotationCache[$className];
    }

    /**
     * @param string $condition
     * @param string $alias
     * @param UserInterface $user
     * @return string
     */
    public function conditionPlaceholder($condition, $alias, UserInterface $user = null)
    {
        if (!$user) {
            $user = $this->tokenStorage->getToken()->getUser();
        }

        $userId = null;
        if ($user instanceof UserInterface && method_exists($user, 'getId')) {
            $userId = $user->getId();
        }

        $template = $this->getTwigEnvironment()->createTemplate($condition);

        return trim($template->render([
            'alias'  => $alias,
            'user'   => $user,
            'userId' => $userId,
        ]));
    }

    /**
     * @return \Twig_Environment
     */
    private function getTwigEnvironment()
    {
        if (!$this->twigEnvironment) {
            $this->twigEnvironment = new \Twig_Environment(new \Twig_Loader_Array([]), [
                'strict_variables' => true,
                'autoescape'       => false,
            ]);
        }

        return $this->twigEnvironment;
    }
}
