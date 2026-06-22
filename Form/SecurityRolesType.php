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
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Class SecurityRolesType.
 *
 * @author Andrey Nilov <nilov@glavweb.ru>
 */
class SecurityRolesType extends AbstractType
{
    public function __construct(protected EditableRolesBuilder $rolesBuilder)
    {
    }

    public function buildView(FormView $view, FormInterface $form, array $options): void
    {
        $attr = $view->vars['attr'];

        if (isset($attr['class']) && empty($attr['class'])) {
            $attr['class'] = 'sonata-medium';
        }

        $view->vars['entityRoles'] = $options['entityRoles'];
        $view->vars['securityRoles'] = $options['securityRoles'];
        $view->vars['attr'] = $attr;
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        [$entityRoles, $securityRoles] = $this->rolesBuilder->getRoles();

        $resolver->setDefaults([
            'choices' => static fn (Options $options, $parentChoices): array => empty($parentChoices) ? array_merge(
                $entityRoles,
                $securityRoles
            ) : [],

            'entityRoles' => static fn (Options $options, $parentChoices) => empty($parentChoices) ? $entityRoles : [],

            'securityRoles' => static fn (Options $options, $parentChoices) => empty($parentChoices) ? $securityRoles : [],

            'data_class' => null,
        ]);
    }

    #[\Override]
    public function getBlockPrefix(): string
    {
        return 'glavweb_security_roles';
    }

    #[\Override]
    public function getParent(): ?string
    {
        return ChoiceType::class;
    }
}
