<?php

namespace Restruct\SilverStripe\Waf\Models;

use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Permission;

/**
 * Banned IP address record
 *
 * @property string $IpAddress
 * @property string $Reason
 * @property string $ExpiresAt
 * @property bool $IsPermanent
 * @property string $Created
 */
class BannedIp extends DataObject
{
    private static string $table_name = 'Waf_BannedIp';

    private static string $singular_name = 'Banned IP';
    private static string $plural_name = 'Banned IPs';

    private static array $db = [
        'IpAddress' => 'Varchar(45)',     // IPv6 max length
        'Reason' => 'Varchar(255)',
        'ExpiresAt' => 'Datetime',
        'IsPermanent' => 'Boolean',
    ];

    private static array $indexes = [
        'IpAddress' => true,
        'ExpiresAt' => true,
    ];

    private static string $default_sort = 'Created DESC';

    private static array $summary_fields = [
        'IpAddress' => 'IP Address',
        'Reason' => 'Reason',
        'ExpiresAt.Nice' => 'Expires',
        'IsPermanent.Nice' => 'Permanent',
        'IsActive' => 'Active',
    ];

    private static array $searchable_fields = [
        'IpAddress',
        'Reason',
        'IsPermanent',
    ];

    public function getCMSFields(): FieldList
    {
        $fields = parent::getCMSFields();

        if ($this->exists()) {
            $fields->addFieldToTab(
                'Root.Main',
                ReadonlyField::create('IsActiveDisplay', 'Currently Active', $this->IsActive ? 'Yes' : 'No'),
                'Reason'
            );
        }

        return $fields;
    }

    /**
     * Check if this ban is currently active
     */
    public function getIsActive(): bool
    {
        if ($this->IsPermanent) {
            return true;
        }

        if (!$this->ExpiresAt) {
            return false;
        }

        return strtotime($this->ExpiresAt) > time();
    }

    /**
     * Get remaining ban duration in seconds
     */
    public function getRemainingDuration(): int
    {
        if ($this->IsPermanent) {
            return PHP_INT_MAX;
        }

        if (!$this->ExpiresAt) {
            return 0;
        }

        $remaining = strtotime($this->ExpiresAt) - time();
        return max(0, $remaining);
    }

    public function canView($member = null): bool
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    public function canEdit($member = null): bool
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    public function canDelete($member = null): bool
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    public function canCreate($member = null, $context = []): bool
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    /**
     * Clean up expired bans (call via scheduled task)
     */
    public static function cleanupExpired(): int
    {
        $expired = static::get()->filter([
            'IsPermanent' => false,
            'ExpiresAt:LessThan' => date('Y-m-d H:i:s'),
        ]);

        $count = $expired->count();

        foreach ($expired as $ban) {
            $ban->delete();
        }

        return $count;
    }
}
