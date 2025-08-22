<?php

declare(strict_types=1);

namespace Iseazy\Security;

use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Iseazy\Security\DependencyInjection\IseazySecurityExtension;

class IseazySecurityBundle extends Bundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        return new IseazySecurityExtension();
    }
}
