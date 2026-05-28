<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Exception;

/**
 * Exception thrown when attempting to create or manipulate an invalid Capability.
 *
 * Thrown in the following scenarios:
 * - Action is empty
 * - Context array is empty
 * - Global scope is used without ['*'] context
 * - Attempting to merge capabilities with different actions or scopes
 * - Missing required fields when deserializing from array
 */
final class InvalidCapabilityException extends \InvalidArgumentException
{
}
