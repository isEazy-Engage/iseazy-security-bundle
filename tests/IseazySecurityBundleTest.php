<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use Iseazy\Security\IseazySecurityBundle;
use Iseazy\Security\DependencyInjection\IseazySecurityExtension;

class IseazySecurityBundleTest extends TestCase
{
    public function testGetContainerExtensionReturnsCorrectInstance()
    {
        $bundle = new IseazySecurityBundle();
        $extension = $bundle->getContainerExtension();
        $this->assertInstanceOf(IseazySecurityExtension::class, $extension);
    }
}
