<?php

/**
 * Banned IP address record
 *
 * @property string $IpAddress
 * @property string $Reason
 * @property string $ExpiresAt
 * @property bool $IsPermanent
 * @property string $Created
 */
class WafBannedIp extends DataObject
{
    private static $singular_name = 'Banned IP';
    private static $plural_name = 'Banned IPs';

    private static $db = array(
        'IpAddress' => 'Varchar(45)',     # IPv6 max length
        'Reason' => 'Varchar(255)',
        'ExpiresAt' => 'SS_Datetime',
        'IsPermanent' => 'Boolean',
    );

    private static $indexes = array(
        'IpAddress' => true,
        'ExpiresAt' => true,
    );

    private static $default_sort = 'Created DESC';

    private static $summary_fields = array(
        'IpAddress' => 'IP Address',
        'Reason' => 'Reason',
        'ExpiresAt.Nice' => 'Expires',
        'IsPermanent.Nice' => 'Permanent',
        'IsActive' => 'Active',
    );

    private static $searchable_fields = array(
        'IpAddress',
        'Reason',
        'IsPermanent',
    );

    /**
     * @return FieldList
     */
    public function getCMSFields()
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
     *
     * @return bool
     */
    public function getIsActive()
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
     *
     * @return int
     */
    public function getRemainingDuration()
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
        return Permission::check('ADMIN', 'any', $member);
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
        return Permission::check('ADMIN', 'any', $member);
    }

    /**
     * Clean up expired bans (call via scheduled task)
     *
     * @return int
     */
    public static function cleanupExpired()
    {
        $expired = static::get()->filter(array(
            'IsPermanent' => false,
            'ExpiresAt:LessThan' => date('Y-m-d H:i:s'),
        ));

        $count = $expired->count();

        foreach ($expired as $ban) {
            $ban->delete();
        }

        return $count;
    }
}
