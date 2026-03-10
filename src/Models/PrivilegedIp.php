<?php

namespace Restruct\SilverStripe\Waf\Models;

use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\NumericField;
use SilverStripe\Forms\TextField;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBBoolean;
use SilverStripe\ORM\FieldType\DBFloat;
use SilverStripe\ORM\FieldType\DBVarchar;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Permission;

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
class PrivilegedIp extends DataObject
{
    private static string $table_name = 'Waf_PrivilegedIp';

    private static string $singular_name = 'Privileged IP';
    private static string $plural_name = 'Privileged IPs';

    private static array $db = [
        'IpAddress' => DBVarchar::class . '(45)',     # Single IP or CIDR (e.g. 10.0.0.0/8)
        'Factor'    => DBFloat::class,                # Rate limit multiplier (2.0 = double the base limit)
        'Tier'      => DBVarchar::class . '(100)',    # Group name ("Office", "Partner", "Monitoring")
        'IsActive'  => DBBoolean::class,              # Toggle without deleting
    ];

    private static array $defaults = [
        'Factor' => 2.0,
        'IsActive' => true,
    ];

    private static array $indexes = [
        'IpAddress' => true,
        'IsActive' => true,
    ];

    private static string $default_sort = 'Tier ASC, IpAddress ASC';

    private static array $summary_fields = [
        'IpAddress' => 'IP Address',
        'Factor' => 'Factor',
        'Tier' => 'Tier',
        'IsActive.Nice' => 'Active',
    ];

    private static array $searchable_fields = [
        'IpAddress',
        'Tier',
        'IsActive',
    ];

    public function getCMSFields(): FieldList
    {
        $fields = parent::getCMSFields();

        # Replace auto-scaffolded fields with better configured ones
        $fields->removeByName(['IpAddress', 'Factor', 'Tier']);

        $fields->addFieldsToTab('Root.Main', [
            TextField::create('IpAddress', 'IP Address')
                ->setDescription('Single IP or CIDR range')
                ->setAttribute('placeholder', '1.2.3.4 or 10.0.0.0/8'),
            NumericField::create('Factor', 'Rate Limit Factor')
                ->setDescription('Multiplier for the base rate limit (e.g. 2.0 = double)')
                ->setScale(1),
            TextField::create('Tier', 'Tier')
                ->setDescription('Group name for organization (e.g. Office, Partner, Monitoring)')
                ->setAttribute('placeholder', 'Office'),
        ], 'IsActive');

        return $fields;
    }

    public function validate(): ValidationResult
    {
        $result = parent::validate();

        $ip = $this->IpAddress;

        # Validate IP or CIDR format
        if (str_contains($ip, '/')) {
            [$subnet, $bits] = explode('/', $ip, 2);
            if (!filter_var($subnet, FILTER_VALIDATE_IP) || !is_numeric($bits)
                || (int) $bits < 0 || (int) $bits > 128) {
                $result->addFieldError('IpAddress', 'Invalid CIDR notation (e.g. 10.0.0.0/8)');
            }
        } elseif (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $result->addFieldError('IpAddress', 'Invalid IP address');
        }

        # Factor must be positive
        if ($this->Factor <= 0) {
            $result->addFieldError('Factor', 'Factor must be greater than 0');
        }

        return $result;
    }

    /**
     * Invalidate cached privileged IP list when entries change
     */
    protected function onAfterWrite(): void
    {
        parent::onAfterWrite();
        $this->invalidateCache();
    }

    /**
     * Invalidate cached privileged IP list when entries are deleted
     */
    protected function onAfterDelete(): void
    {
        parent::onAfterDelete();
        $this->invalidateCache();
    }

    private function invalidateCache(): void
    {
        try {
            /** @var WafStorageService $storage */
            $storage = Injector::inst()->get(WafStorageService::class);
            $storage->invalidatePrivilegedIpCache();
        } catch (\Exception $e) {
            // Don't break on cache issues
        }
    }

    // ========================================================================
    // Permissions (consistent with WafAdmin)
    // ========================================================================

    public function canView($member = null): bool
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }

    public function canEdit($member = null): bool
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }

    public function canDelete($member = null): bool
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }

    public function canCreate($member = null, $context = []): bool
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }
}
