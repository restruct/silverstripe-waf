<?php

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
class WafBlockedRequest extends DataObject
{
    private static $singular_name = 'Blocked Request';
    private static $plural_name = 'Blocked Requests';

    private static $db = array(
        'IpAddress' => 'Varchar(45)',     # IPv6 max length
        'Uri' => 'Varchar(255)',
        'UserAgent' => 'Varchar(255)',
        'Reason' => 'Varchar(50)',
        'Detail' => 'Varchar(255)',
    );

    private static $indexes = array(
        'IpAddress' => true,
        'Reason' => true,
        'Created' => true,
    );

    private static $default_sort = 'Created DESC';

    private static $summary_fields = array(
        'Created.Nice' => 'Time',
        'IpAddress' => 'IP Address',
        'Reason' => 'Reason',
        'Uri' => 'URI',
    );

    private static $searchable_fields = array(
        'IpAddress',
        'Reason',
        'Uri',
    );

    /**
     * @param Member $member
     * @return bool
     */
    public function canView($member = null)
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    /**
     * @param Member $member
     * @return bool
     */
    public function canEdit($member = null)
    {
        return false; # Log entries are immutable
    }

    /**
     * @param Member $member
     * @return bool
     */
    public function canDelete($member = null)
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    /**
     * @param Member $member
     * @return bool
     */
    public function canCreate($member = null)
    {
        return true; # Created by request filter
    }
}
