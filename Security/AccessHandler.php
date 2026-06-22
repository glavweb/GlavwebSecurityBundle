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

use Glavweb\SecurityBundle\Mapping\Attribute\Access;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Environment;
use Twig\Error\LoaderError;
use Twig\Error\SyntaxError;
use Twig\Loader\ArrayLoader;

/**
 * Class AccessHandler.
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 */
class AccessHandler
{
    private static array $accessAttributeCache = [];

    /**
     * @var string[]
     */
    private array $actions = ['CREATE', 'LIST', 'VIEW', 'EDIT', 'DELETE', 'EXPORT'];

    private ?Environment $twigEnvironment = null;

    /**
     * AccessHandler constructor.
     */
    public function __construct(private readonly TokenStorageInterface $tokenStorage)
    {
    }

    /**
     * @param bool $onlyForObjects
     */
    public function getActions($onlyForObjects = false): array
    {
        $actions = $this->actions;

        if ($onlyForObjects) {
            return array_filter($actions, static fn (string $item): bool => !\in_array($item, ['CREATE', 'LIST'], true));
        }

        return $actions;
    }

    /**
     * @param string $class
     */
    public function getAdditionalRoles($class): ?array
    {
        $accessAttribute = $this->getAccessAttribute($class);
        if ($accessAttribute instanceof Access) {
            return $accessAttribute->getAdditionalRoles();
        }

        return null;
    }

    /**
     * @param string $class
     */
    public function getBaseRole($class): ?string
    {
        $accessAttribute = $this->getAccessAttribute($class);
        if ($accessAttribute instanceof Access) {
            return $accessAttribute->getBaseRole();
        }

        return null;
    }

    /**
     * @param string $class
     * @param string $role
     */
    public function checkRole($class, $role): bool
    {
        return (bool) $this->getActionByRole($class, $role);
    }

    /**
     * @param string $class
     * @param string $role
     *
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
     */
    public function getRole($class, $action, $additionalRole = null): ?string
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
     */
    protected function makeRole($baseRole, $action, $additionalRole = null): string
    {
        $role = \sprintf($baseRole, strtoupper($action));

        if ($additionalRole) {
            $role .= '__'.strtoupper($additionalRole);
        }

        return $role;
    }

    /**
     * @param string $class
     */
    public function hasAccessAttribute($class): bool
    {
        return (bool) $this->getAccessAttribute($class);
    }

    /**
     * @param string|\ReflectionClass $class
     *
     * @return Access|null
     */
    public function getAccessAttribute($class)
    {
        $className = $class;
        if ($class instanceof \ReflectionClass) {
            $className = $class->getName();
        }

        if (!isset(self::$accessAttributeCache[$className])) {
            $reflectionClass = $class;
            if (!$reflectionClass instanceof \ReflectionClass) {
                $reflectionClass = new \ReflectionClass($reflectionClass);
            }

            $reflectionAttributes = $reflectionClass->getAttributes(Access::class);

            if (\count($reflectionAttributes) > 1) {
                throw new \RuntimeException('Only one access attribute is allowed');
            }

            self::$accessAttributeCache[$className] = $reflectionAttributes ? $reflectionAttributes[0]->newInstance() : null;
        }

        return self::$accessAttributeCache[$className];
    }

    /**
     * @param string $alias
     *
     * @throws LoaderError
     * @throws SyntaxError
     */
    public function conditionPlaceholder(string $condition, $alias, ?UserInterface $user = null): string
    {
        if (!$user instanceof UserInterface) {
            $user = $this->tokenStorage->getToken()->getUser();
        }

        $userId = null;
        if ($user instanceof UserInterface && method_exists($user, 'getId')) {
            $userId = $user->getId();
        }

        $template = $this->getTwigEnvironment()->createTemplate($condition);

        return trim($template->render([
            'alias' => $alias,
            'user' => $user,
            'userId' => $userId,
        ]));
    }

    private function getTwigEnvironment(): Environment
    {
        if (!$this->twigEnvironment instanceof Environment) {
            $this->twigEnvironment = new Environment(new ArrayLoader([]), [
                'strict_variables' => true,
                'autoescape' => false,
            ]);
        }

        return $this->twigEnvironment;
    }
}
