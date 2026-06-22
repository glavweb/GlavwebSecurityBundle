<?php

/*
 * This file is part of the Glavweb SecurityBundle package.
 *
 * (c) GLAVWEB <info@glavweb.ru>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Glavweb\SecurityBundle\Form\Transformer;

use Glavweb\SecurityBundle\Security\EditableRolesBuilder;
use Symfony\Component\Form\DataTransformerInterface;

/**
 * Class RestoreRolesTransformer.
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 */
class RestoreRolesTransformer implements DataTransformerInterface
{
    /**
     * @var array
     */
    protected $originalRoles;

    public function __construct(protected EditableRolesBuilder $rolesBuilder)
    {
    }

    public function setOriginalRoles(?array $originalRoles = null): void
    {
        $this->originalRoles = $originalRoles ?: [];
    }

    public function transform($value): mixed
    {
        if ($value === null) {
            return $value;
        }

        if ($this->originalRoles === null) {
            throw new \RuntimeException('Invalid state, originalRoles array is not set');
        }

        return $value;
    }

    public function reverseTransform($value): mixed
    {
        if ($this->originalRoles === null) {
            throw new \RuntimeException('Invalid state, originalRoles array is not set');
        }

        [$availableRoles] = $this->rolesBuilder->getRoles();

        $hiddenRoles = array_diff($this->originalRoles, array_keys($availableRoles));

        return array_merge($value, $hiddenRoles);
    }
}
