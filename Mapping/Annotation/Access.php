<?php

/*
 * This file is part of the Glavweb SecurityBundle package.
 *
 * (c) GLAVWEB <info@glavweb.ru>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Glavweb\SecurityBundle\Mapping\Annotation;

/**
 * Class Access
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 * @package Glavweb\SecurityBundle
 *
 * @Annotation
 * @Target({"CLASS"})
 */
class Access
{
    /**
     * @var string
     */
    public $baseRole;

    /**
     * @var string
     */
    public $name;

    /**
     * @var array
     */
    public $additionalRoles = [];

    /**
     * @return string
     */
    public function getBaseRole()
    {
        return $this->baseRole;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return array
     */
    public function getAdditionalRoles()
    {
        return $this->additionalRoles;
    }
}

