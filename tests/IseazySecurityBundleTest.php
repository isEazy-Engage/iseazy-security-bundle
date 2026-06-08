<?php

declare(strict_types=1);

namespace Tests;

use Iseazy\Security\DependencyInjection\IseazySecurityExtension;
use Iseazy\Security\IseazySecurityBundle;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class IseazySecurityBundleTest extends TestCase
{
    #[Test]
    public function testGetContainerExtensionReturnsCorrectInstance(): void
    {
        $bundle = new IseazySecurityBundle();
        $extension = $bundle->getContainerExtension();
        $this->assertInstanceOf(IseazySecurityExtension::class, $extension);
    }
}
