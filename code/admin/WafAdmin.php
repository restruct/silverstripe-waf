<?php

/**
 * CMS Admin interface for WAF management
 *
 * Works with arbitrary data (ArrayList) - no database required.
 * Data comes from WafStorageService (file or cache based).
 *
 * SS3 backport: extends LeftAndMain with non-namespaced form fields.
 */
class WafAdmin extends LeftAndMain implements PermissionProvider
{
    private static $url_segment = 'waf';
    private static $menu_title = 'WAF';
    private static $menu_icon = 'silverstripe-waf/images/shield.png';
    private static $menu_priority = -1;

    private static $allowed_actions = array(
        'EditForm',
        'unban',
        'ban',
    );

    /**
     * @param int $id
     * @param FieldList $fields
     * @return Form
     */
    public function getEditForm($id = null, $fields = null)
    {
        $fields = FieldList::create(
            TabSet::create('Root',
                Tab::create('BlockedRequests', 'Blocked Requests',
                    $this->getStatsField(),
                    $this->getBlockedRequestsGrid()
                ),
                Tab::create('BannedIPs', 'Banned IPs',
                    $this->getBannedIpsGrid(),
                    $this->getManualBanFields()
                ),
                Tab::create('PrivilegedIPs', 'Privileged IPs',
                    $this->getPrivilegedIpsInfoField(),
                    $this->getPrivilegedIpsGrid(),
                    $this->getPrivilegedIpsConfigField()
                ),
                Tab::create('Blocklist', 'IP Blocklist',
                    $this->getBlocklistStatsField()
                )
            )
        );

        $actions = FieldList::create();

        $form = Form::create(
            $this,
            'EditForm',
            $fields,
            $actions
        );

        $form->setTemplate($this->getTemplatesWithSuffix('_EditForm'));
        $form->addExtraClass('cms-edit-form');
        $form->setAttribute('data-pjax-fragment', 'CurrentForm');

        return $form;
    }

    /**
     * @return LiteralField
     */
    protected function getStatsField()
    {
        /** @var WafIpBlocklistService $blocklistService */
        $blocklistService = Injector::inst()->get('WafIpBlocklistService');
        $stats = $blocklistService->getStats();

        /** @var WafStorageService $storageService */
        $storageService = Injector::inst()->get('WafStorageService');

        $blockedRequests = $storageService->getBlockedRequests(1000);
        // ArrayList doesn't support ORM-style filtering, so filter manually
        $blockedToday = 0;
        $todayStart = date('Y-m-d 00:00:00');
        foreach ($blockedRequests as $item) {
            if ($item->Created >= $todayStart) {
                $blockedToday++;
            }
        }
        $totalBlocked = $blockedRequests->count();

        $bans = $storageService->getActiveBans();
        $bannedCount = $bans->count();

        $syncedAt = isset($stats['synced_at']) && $stats['synced_at']
            ? date('Y-m-d H:i:s', $stats['synced_at'])
            : 'Never';

        $sourcesList = '';
        $sources = isset($stats['sources']) ? $stats['sources'] : array();
        foreach ($sources as $name => $source) {
            if (isset($source['error'])) {
                $sourcesList .= "<li><strong>{$name}:</strong> <span style='color:red'>Error - {$source['error']}</span></li>";
            } else {
                $count = isset($source['count']) ? $source['count'] : 0;
                $sourcesList .= "<li><strong>{$name}:</strong> {$count} entries</li>";
            }
        }

        $storageMode = WafStorageService::config()->get('storage_mode');

        return LiteralField::create('WafStats', "
<div style=\"background: #f5f5f5; padding: 15px; margin-bottom: 20px; border-radius: 4px;\">
    <h3 style=\"margin-top: 0;\">WAF Status</h3>
    <div style=\"display: flex; gap: 30px; flex-wrap: wrap;\">
        <div>
            <strong>Blocked Today:</strong> {$blockedToday}<br>
            <strong>Total Logged:</strong> {$totalBlocked}<br>
            <strong>Active Bans:</strong> {$bannedCount}
        </div>
        <div>
            <strong>Blocklist IPs:</strong> {$stats['total_ips']}<br>
            <strong>Blocklist CIDRs:</strong> {$stats['total_cidrs']}<br>
            <strong>Last Sync:</strong> {$syncedAt}
        </div>
        <div>
            <strong>Storage Mode:</strong> {$storageMode}<br>
            <strong>Sources:</strong>
            <ul style=\"margin: 5px 0 0 0; padding-left: 20px;\">{$sourcesList}</ul>
        </div>
    </div>
    <p style=\"margin-bottom: 0; margin-top: 10px; font-size: 12px; color: #666;\">
        Sync blocklists: <code>php framework/cli-script.php dev/tasks/WafSyncBlocklistsTask</code>
    </p>
</div>
        ");
    }

    /**
     * @return GridField
     */
    protected function getBlockedRequestsGrid()
    {
        /** @var WafStorageService $storageService */
        $storageService = Injector::inst()->get('WafStorageService');
        $data = $storageService->getBlockedRequests(100);

        $config = GridFieldConfig::create()
            ->addComponent(new GridFieldToolbarHeader())
            ->addComponent(new GridFieldSortableHeader())
            ->addComponent($columns = new GridFieldDataColumns())
            ->addComponent(new GridFieldPaginator(25));

        $columns->setDisplayFields(array(
            'Created' => 'Time',
            'IpAddress' => 'IP Address',
            'Reason' => 'Reason',
            'Uri' => 'URI',
        ));

        return GridField::create('BlockedRequests', 'Recent Blocked Requests', $data, $config);
    }

    /**
     * @return GridField
     */
    protected function getBannedIpsGrid()
    {
        /** @var WafStorageService $storageService */
        $storageService = Injector::inst()->get('WafStorageService');
        $data = $storageService->getActiveBans();

        $config = GridFieldConfig::create()
            ->addComponent(new GridFieldToolbarHeader())
            ->addComponent(new GridFieldSortableHeader())
            ->addComponent($columns = new GridFieldDataColumns())
            ->addComponent(new GridFieldPaginator(25));

        $columns->setDisplayFields(array(
            'IpAddress' => 'IP Address',
            'Reason' => 'Reason',
            'ExpiresAt' => 'Expires',
        ));

        // Add unban action column
        $columns->setFieldFormatting(array(
            'IpAddress' => function ($value, $item) {
                $url = $this->Link('unban') . '?ip=' . urlencode($value);
                return "{$value} <a href='{$url}' class='btn btn-sm btn-outline-danger' onclick='return confirm(\"Unban {$value}?\")'>Unban</a>";
            },
        ));

        return GridField::create('BannedIPs', 'Active Bans', $data, $config);
    }

    /**
     * @return LiteralField
     */
    protected function getManualBanFields()
    {
        $banUrl = $this->Link('ban');

        return LiteralField::create('ManualBan', "
<div style=\"background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 4px; border: 1px solid #ffc107;\">
    <h4 style=\"margin-top: 0;\">Manual Ban</h4>
    <form method=\"post\" action=\"{$banUrl}\" style=\"display: flex; gap: 10px; align-items: end;\">
        <div>
            <label>IP Address</label><br>
            <input type=\"text\" name=\"ip\" required pattern=\"[0-9a-fA-F.:\/]+\" placeholder=\"1.2.3.4\" style=\"padding: 5px;\">
        </div>
        <div>
            <label>Duration (hours)</label><br>
            <input type=\"number\" name=\"hours\" value=\"24\" min=\"1\" max=\"8760\" style=\"padding: 5px; width: 80px;\">
        </div>
        <div>
            <label>Reason</label><br>
            <input type=\"text\" name=\"reason\" value=\"Manual ban\" style=\"padding: 5px; width: 200px;\">
        </div>
        <button type=\"submit\" class=\"btn btn-warning\">Ban IP</button>
    </form>
</div>
        ");
    }

    /**
     * @return LiteralField
     */
    protected function getPrivilegedIpsInfoField()
    {
        $baseLimit = WafRequestFilter::config()->get('rate_limit_requests');
        $window = WafRequestFilter::config()->get('rate_limit_window');
        $exampleDouble = $baseLimit * 2;

        return LiteralField::create('PrivilegedIpsInfo', "
<div style=\"background: #e8f5e9; padding: 15px; margin-bottom: 20px; border-radius: 4px; border: 1px solid #a5d6a7;\">
    <h4 style=\"margin-top: 0;\">Privileged IPs</h4>
    <p style=\"margin-bottom: 5px;\">
        Privileged IPs still go through <strong>all security checks</strong> (bans, blocklist, user-agent)
        but receive an elevated rate limit via a configurable multiplier.
    </p>
    <p style=\"margin-bottom: 0;\">
        <strong>Base rate limit:</strong> {$baseLimit} requests per {$window} seconds.
        A Factor of <strong>2.0</strong> = {$baseLimit} &times; 2 = <strong>{$exampleDouble}</strong> effective requests.
    </p>
</div>
        ");
    }

    /**
     * @return GridField
     */
    protected function getPrivilegedIpsGrid()
    {
        return GridField::create(
            'PrivilegedIPs',
            'Privileged IPs (Database)',
            WafPrivilegedIp::get(),
            GridFieldConfig_RecordEditor::create()
        );
    }

    /**
     * @return LiteralField
     */
    protected function getPrivilegedIpsConfigField()
    {
        $tiers = WafRequestFilter::config()->get('privileged_tiers');
        if (!is_array($tiers)) {
            $tiers = array();
        }

        if (empty($tiers)) {
            return LiteralField::create('PrivilegedIpsConfig', "
<div style=\"background: #f5f5f5; padding: 15px; margin-top: 20px; border-radius: 4px;\">
    <h4 style=\"margin-top: 0;\">YAML Config Tiers</h4>
    <p style=\"margin-bottom: 0; color: #666;\">No tiers defined in YAML config. Use the grid above to manage privileged IPs, or define tiers in <code>_config/config.yml</code>.</p>
</div>
            ");
        }

        $tierRows = '';
        foreach ($tiers as $tierName => $tierConfig) {
            $factor = isset($tierConfig['factor']) ? $tierConfig['factor'] : 2.0;
            $ips = isset($tierConfig['ips']) ? $tierConfig['ips'] : array();
            $ipList = implode(', ', $ips);
            $tierRows .= "<tr><td><strong>{$tierName}</strong></td><td>{$factor}</td><td style='font-size: 12px;'>{$ipList}</td></tr>";
        }

        return LiteralField::create('PrivilegedIpsConfig', "
<div style=\"background: #f5f5f5; padding: 15px; margin-top: 20px; border-radius: 4px;\">
    <h4 style=\"margin-top: 0;\">YAML Config Tiers <span style=\"font-weight: normal; color: #666;\">(read-only)</span></h4>
    <p style=\"font-size: 12px; color: #666;\">These tiers are defined in YAML config and merged with database entries at runtime. DB entries override config for the same IP.</p>
    <table class=\"table\" style=\"width: 100%;\">
        <thead><tr><th>Tier</th><th>Factor</th><th>IPs</th></tr></thead>
        <tbody>{$tierRows}</tbody>
    </table>
</div>
        ");
    }

    /**
     * @return LiteralField
     */
    protected function getBlocklistStatsField()
    {
        /** @var WafIpBlocklistService $service */
        $service = Injector::inst()->get('WafIpBlocklistService');
        $stats = $service->getStats();

        $sourceRows = '';
        $sources = isset($stats['sources']) ? $stats['sources'] : array();
        foreach ($sources as $name => $source) {
            $status = isset($source['error'])
                ? "<span style='color:red'>Error: {$source['error']}</span>"
                : "<span style='color:green'>OK</span>";
            $count = isset($source['count']) ? $source['count'] : 0;
            $url = isset($source['url']) ? $source['url'] : (isset($source['file']) ? $source['file'] : '-');

            $sourceRows .= "<tr><td>{$name}</td><td>{$count}</td><td>{$status}</td><td style='font-size:11px'>{$url}</td></tr>";
        }

        $syncedAtTs = isset($stats['synced_at']) ? $stats['synced_at'] : null;
        $syncedAt = $syncedAtTs ? date('Y-m-d H:i:s', $syncedAtTs) : 'Never';
        $timeAgo = $this->timeAgo($syncedAtTs);

        return LiteralField::create('BlocklistStats', "
<div style=\"padding: 15px;\">
    <h3>Threat Intelligence Blocklist</h3>
    <p>
        <strong>Total IPs:</strong> {$stats['total_ips']}<br>
        <strong>Total CIDRs:</strong> {$stats['total_cidrs']}<br>
        <strong>Last Sync:</strong> {$syncedAt} ({$timeAgo})
    </p>

    <h4>Sources</h4>
    <table class=\"table\" style=\"width: 100%;\">
        <thead><tr><th>Source</th><th>Entries</th><th>Status</th><th>URL</th></tr></thead>
        <tbody>{$sourceRows}</tbody>
    </table>

    <p style=\"margin-top: 20px;\">
        <strong>Sync command:</strong><br>
        <code>php framework/cli-script.php dev/tasks/WafSyncBlocklistsTask</code>
    </p>
    <p>
        <strong>Recommended cron (every 6 hours):</strong><br>
        <code>0 */6 * * * cd /path/to/site && php framework/cli-script.php dev/tasks/WafSyncBlocklistsTask</code>
    </p>
</div>
        ");
    }

    /**
     * @param int|null $timestamp
     * @return string
     */
    protected function timeAgo($timestamp)
    {
        if (!$timestamp) {
            return 'never';
        }

        $diff = time() - $timestamp;

        if ($diff < 60) {
            return "{$diff} seconds ago";
        }
        if ($diff < 3600) {
            return round($diff / 60) . " minutes ago";
        }
        if ($diff < 86400) {
            return round($diff / 3600) . " hours ago";
        }

        return round($diff / 86400) . " days ago";
    }

    // ========================================================================
    // Actions
    // ========================================================================

    public function unban()
    {
        $ip = $this->getRequest()->getVar('ip');
        if ($ip && $this->canEdit()) {
            /** @var WafStorageService $storageService */
            $storageService = Injector::inst()->get('WafStorageService');
            $storageService->unbanIp($ip);
        }

        return $this->redirect($this->Link());
    }

    public function ban()
    {
        $request = $this->getRequest();
        $ip = $request->postVar('ip');
        $hours = (int) $request->postVar('hours');
        if (!$hours) {
            $hours = 24;
        }
        $reason = $request->postVar('reason');
        if (!$reason) {
            $reason = 'Manual ban';
        }

        if ($ip && $this->canEdit()) {
            /** @var WafStorageService $storageService */
            $storageService = Injector::inst()->get('WafStorageService');
            $storageService->banIp($ip, $hours * 3600, $reason);
        }

        return $this->redirect($this->Link());
    }

    // ========================================================================
    // Permissions
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
     * @return array
     */
    public function providePermissions()
    {
        return array(
            'WAF_ADMIN' => array(
                'name' => 'Administer WAF',
                'category' => 'Security',
                'help' => 'View blocked requests and manage IP bans',
            ),
        );
    }
}
