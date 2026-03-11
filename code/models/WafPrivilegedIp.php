<?php

/**
 * Privileged IP - receives elevated rate limits via a configurable multiplier
 *
 * Unlike whitelisted IPs (which skip ALL checks), privileged IPs still go through
 * all security checks (bans, blocklist, user-agent) but receive an elevated rate
 * limit. E.g. Factor 2.0 with base limit 100 = effective limit 200.
 *
 * Always DB-backed regardless of WAF storage_mode setting — this is small,
 * rarely-changing configuration data that needs CRUD.
 *
 * @property string $IpAddress
 * @property float $Factor
 * @property string $Tier
 * @property bool $IsActive
 */
class WafPrivilegedIp extends DataObject
{
    private static $singular_name = 'Privileged IP';
    private static $plural_name = 'Privileged IPs';

    private static $db = array(
        'IpAddress' => 'Varchar(45)',     # Single IP or CIDR (e.g. 10.0.0.0/8)
        'Factor'    => 'Float',           # Rate limit multiplier (2.0 = double the base limit)
        'Tier'      => 'Varchar(100)',    # Group name ("Office", "Partner", "Monitoring")
        'IsActive'  => 'Boolean',         # Toggle without deleting
    );

    private static $defaults = array(
        'Factor' => 2.0,
        'IsActive' => true,
    );

    private static $indexes = array(
        'IpAddress' => true,
        'IsActive' => true,
    );

    private static $default_sort = 'Tier ASC, IpAddress ASC';

    private static $summary_fields = array(
        'IpAddress' => 'IP Address',
        'Factor' => 'Factor',
        'Tier' => 'Tier',
        'IsActive.Nice' => 'Active',
    );

    private static $searchable_fields = array(
        'IpAddress',
        'Tier',
        'IsActive',
    );

    /**
     * @return FieldList
     */
    public function getCMSFields()
    {
        $fields = parent::getCMSFields();

        # Replace auto-scaffolded fields with better configured ones
        $fields->removeByName(array('IpAddress', 'Factor', 'Tier'));

        $fields->addFieldToTab('Root.Main',
            TextField::create('IpAddress', 'IP Address')
                ->setDescription('Single IP or CIDR range (e.g. 1.2.3.4 or 10.0.0.0/8)'),
            'IsActive'
        );
        $fields->addFieldToTab('Root.Main',
            NumericField::create('Factor', 'Rate Limit Factor')
                ->setDescription('Multiplier for the base rate limit (e.g. 2.0 = double)'),
            'IsActive'
        );
        $fields->addFieldToTab('Root.Main',
            TextField::create('Tier', 'Tier')
                ->setDescription('Group name for organization (e.g. Office, Partner, Monitoring)'),
            'IsActive'
        );

        return $fields;
    }

    /**
     * @return ValidationResult
     */
    public function validate()
    {
        $result = parent::validate();

        $ip = $this->IpAddress;

        # Validate IP or CIDR format
        if (strpos($ip, '/') !== false) {
            list($subnet, $bits) = explode('/', $ip, 2);
            if (!filter_var($subnet, FILTER_VALIDATE_IP) || !is_numeric($bits)
                || (int) $bits < 0 || (int) $bits > 128) {
                $result->error('Invalid CIDR notation (e.g. 10.0.0.0/8)', 'IpAddress');
            }
        } elseif (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $result->error('Invalid IP address', 'IpAddress');
        }

        # Factor must be positive
        if ($this->Factor <= 0) {
            $result->error('Factor must be greater than 0', 'Factor');
        }

        return $result;
    }

    /**
     * Invalidate cached privileged IP list when entries change
     */
    protected function onAfterWrite()
    {
        parent::onAfterWrite();
        $this->invalidatePrivilegedCache();
    }

    /**
     * Invalidate cached privileged IP list when entries are deleted
     */
    protected function onAfterDelete()
    {
        parent::onAfterDelete();
        $this->invalidatePrivilegedCache();
    }

    private function invalidatePrivilegedCache()
    {
        try {
            /** @var WafStorageService $storage */
            $storage = Injector::inst()->get('WafStorageService');
            $storage->invalidatePrivilegedIpCache();
        } catch (Exception $e) {
            // Don't break on cache issues
        }
    }

    // ========================================================================
    // Permissions (consistent with WafAdmin)
    // ========================================================================

    /**
     * @param Member $member
     * @return bool
     */
    public function canView($member = null)
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }

    /**
     * @param Member $member
     * @return bool
     */
    public function canEdit($member = null)
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }

    /**
     * @param Member $member
     * @return bool
     */
    public function canDelete($member = null)
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }

    /**
     * @param Member $member
     * @return bool
     */
    public function canCreate($member = null)
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }
}
