<?php

declare(strict_types=1);

namespace Iseazy\Security\Authorization\Model;

/**
 * Represents the scope or level of restriction of a capability.
 *
 * Defines four levels of restriction from least to most restrictive:
 * - GLOBAL: Applies across all contexts (least restrictive)
 * - PLATFORM: Applies to platform-specific contexts
 * - BUSINESS: Applies to business-specific contexts (parallel to HIERARCHY)
 * - HIERARCHY: Applies to hierarchy-specific contexts (parallel to BUSINESS)
 *
 * Note: BUSINESS and HIERARCHY are parallel branches with equal restriction levels
 * and do not cover each other.
 */
enum Scope: string
{
    case GLOBAL = 'global';
    case PLATFORM = 'platform';
    case BUSINESS = 'business';
    case HIERARCHY = 'hierarchy';

    /**
     * Determines if this scope is less restrictive than another scope.
     *
     * Restriction hierarchy (from least to most restrictive):
     * GLOBAL < PLATFORM < (BUSINESS = HIERARCHY)
     *
     * @param self $other The scope to compare against
     * @return bool True if this scope is less restrictive than the other
     */
    public function isLessRestrictiveThan(self $other): bool
    {
        return $this->restrictionLevel() < $other->restrictionLevel();
    }

    /**
     * Determines if this scope covers (includes) another scope.
     *
     * Coverage rules:
     * - GLOBAL covers all scopes (GLOBAL, PLATFORM, BUSINESS, HIERARCHY)
     * - PLATFORM covers PLATFORM, BUSINESS, and HIERARCHY
     * - BUSINESS only covers BUSINESS (itself)
     * - HIERARCHY only covers HIERARCHY (itself)
     *
     * Note: BUSINESS and HIERARCHY are parallel branches and do not cover each other.
     *
     * @param self $other The scope to check coverage for
     * @return bool True if this scope covers the other scope
     */
    public function covers(self $other): bool
    {
        return match ($this) {
            self::GLOBAL => true,
            self::PLATFORM => in_array($other, [self::PLATFORM, self::BUSINESS, self::HIERARCHY], true),
            self::BUSINESS => $other === self::BUSINESS,
            self::HIERARCHY => $other === self::HIERARCHY,
        };
    }

    /**
     * Returns the numeric restriction level for this scope.
     *
     * Lower numbers indicate less restrictive scopes:
     * - GLOBAL: 0 (least restrictive)
     * - PLATFORM: 1
     * - BUSINESS: 2
     * - HIERARCHY: 2 (same level as BUSINESS - parallel branches)
     *
     * @return int The restriction level
     */
    private function restrictionLevel(): int
    {
        return match ($this) {
            self::GLOBAL => 0,
            self::PLATFORM => 1,
            self::BUSINESS => 2,
            self::HIERARCHY => 2,
        };
    }
}
