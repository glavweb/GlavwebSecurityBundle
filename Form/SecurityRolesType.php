<?php

/*
 * This file is part of the Glavweb SecurityBundle package.
 *
 * (c) GLAVWEB <info@glavweb.ru>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Glavweb\SecurityBundle\Form;

use Glavweb\SecurityBundle\Security\EditableRolesBuilder;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\OptionsResolver\Options;

/**
 * Class SecurityRolesType
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 * @package Glavweb\SecurityBundle
 */
class SecurityRolesType extends AbstractType
{
    /**
     * @var EditableRolesBuilder
     */
    protected $rolesBuilder;

    /**
     * @param EditableRolesBuilder $rolesBuilder
     */
    public function __construct(EditableRolesBuilder $rolesBuilder)
    {
        $this->rolesBuilder = $rolesBuilder;
    }

    /**
     * {@inheritdoc}
     */
    public function buildView(FormView $view, FormInterface $form, array $options)
    {
        $attr = $view->vars['attr'];

        if (isset($attr['class']) && empty($attr['class'])) {
            $attr['class'] = 'sonata-medium';
        }

        $view->vars['entityRoles']   = $options['entityRoles'];
        $view->vars['securityRoles'] = $options['securityRoles'];
        $view->vars['attr']          = $attr;
    }

    /**
     * {@inheritdoc}
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        list($entityRoles, $securityRoles) = $this->rolesBuilder->getRoles();

        $resolver->setDefaults(array(
            'choices' => function (Options $options, $parentChoices) use ($entityRoles, $securityRoles) {
                return empty($parentChoices) ? array_merge($entityRoles, $securityRoles) : [];
            },

            'entityRoles' => function (Options $options, $parentChoices) use ($entityRoles) {
                return empty($parentChoices) ? $entityRoles : [];
            },

            'securityRoles' => function (Options $options, $parentChoices) use ($securityRoles) {
                return empty($parentChoices) ? $securityRoles : [];
            },

            'data_class' => null
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function getBlockPrefix()
    {
        return 'glavweb_security_roles';
    }

    /**
     * {@inheritdoc}
     */
    public function getParent()
    {
        return ChoiceType::class;
    }
}