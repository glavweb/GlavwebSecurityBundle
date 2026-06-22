<?php

/*
 * This file is part of the Glavweb SecurityBundle package.
 *
 * (c) GLAVWEB <info@glavweb.ru>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Glavweb\SecurityBundle\Mapping\Attribute;

/**
 * Class Access.
 *
 * @author Sergey Zvyagintsev <nitron.ru@gmail.com>
 */
#[\Attribute(\Attribute::TARGET_CLASS)]
class Access
{
    public function __construct(public string $name, public string $baseRole, public array $additionalRoles = [])
    {
    }

    public function getBaseRole(): string
    {
        return $this->baseRole;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getAdditionalRoles(): array
    {
        return $this->additionalRoles;
    }
}
