<?php

namespace Restruct\SilverStripe\Waf\Models;

use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Permission;

/**
 * Log entry for a blocked request
 *
 * @property string $IpAddress
 * @property string $Uri
 * @property string $UserAgent
 * @property string $Reason
 * @property string $Detail
 * @property string $Created
 */
class BlockedRequest extends DataObject
{
    private static string $table_name = 'Waf_BlockedRequest';

    private static string $singular_name = 'Blocked Request';
    private static string $plural_name = 'Blocked Requests';

    private static array $db = [
        'IpAddress' => 'Varchar(45)',     // IPv6 max length
        'Uri' => 'Varchar(255)',
        'UserAgent' => 'Varchar(255)',
        'Reason' => 'Varchar(50)',
        'Detail' => 'Varchar(255)',
    ];

    private static array $indexes = [
        'IpAddress' => true,
        'Reason' => true,
        'Created' => true,
    ];

    private static string $default_sort = 'Created DESC';

    private static array $summary_fields = [
        'Created.Nice' => 'Time',
        'IpAddress' => 'IP Address',
        'Reason' => 'Reason',
        'Uri' => 'URI',
    ];

    private static array $searchable_fields = [
        'IpAddress',
        'Reason',
        'Uri',
    ];

    public function canView($member = null): bool
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    public function canEdit($member = null): bool
    {
        return false; // Log entries are immutable
    }

    public function canDelete($member = null): bool
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    public function canCreate($member = null, $context = []): bool
    {
        return true; // Created by middleware
    }
}
