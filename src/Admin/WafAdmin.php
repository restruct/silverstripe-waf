<?php

namespace Restruct\SilverStripe\Waf\Admin;

use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Admin\LeftAndMain;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig;
use SilverStripe\Forms\GridField\GridFieldDataColumns;
use SilverStripe\Forms\GridField\GridFieldPaginator;
use SilverStripe\Forms\GridField\GridFieldSortableHeader;
use SilverStripe\Forms\GridField\GridFieldToolbarHeader;
use SilverStripe\Forms\HeaderField;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\Tab;
use SilverStripe\Forms\TabSet;
use SilverStripe\Forms\TextField;
use SilverStripe\ORM\ArrayList;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;
use SilverStripe\View\ArrayData;

/**
 * CMS Admin interface for WAF management
 *
 * Works with arbitrary data (ArrayList) - no database required.
 * Data comes from WafStorageService (file or cache based).
 */
class WafAdmin extends LeftAndMain implements PermissionProvider
{
    private static string $url_segment = 'waf';
    private static string $menu_title = 'WAF';
    private static string $menu_icon_class = 'font-icon-shield';
    private static int $menu_priority = -1;

    private static array $allowed_actions = [
        'EditForm',
        'unban',
        'ban',
    ];

    public function getEditForm($id = null, $fields = null): Form
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

    protected function getStatsField(): LiteralField
    {
        /** @var IpBlocklistService $blocklistService */
        $blocklistService = Injector::inst()->get(IpBlocklistService::class);
        $stats = $blocklistService->getStats();

        /** @var WafStorageService $storageService */
        $storageService = Injector::inst()->get(WafStorageService::class);

        $blockedRequests = $storageService->getBlockedRequests(1000);
        $blockedToday = $blockedRequests->filter('Created:GreaterThan', date('Y-m-d 00:00:00'))->count();
        $totalBlocked = $blockedRequests->count();

        $bans = $storageService->getActiveBans();
        $bannedCount = $bans->count();

        $syncedAt = $stats['synced_at']
            ? date('Y-m-d H:i:s', $stats['synced_at'])
            : 'Never';

        $sourcesList = '';
        foreach ($stats['sources'] ?? [] as $name => $source) {
            if (isset($source['error'])) {
                $sourcesList .= "<li><strong>{$name}:</strong> <span style='color:red'>Error - {$source['error']}</span></li>";
            } else {
                $count = $source['count'] ?? 0;
                $sourcesList .= "<li><strong>{$name}:</strong> {$count} entries</li>";
            }
        }

        $storageMode = WafStorageService::config()->get('storage_mode');

        return LiteralField::create('WafStats', <<<HTML
<div style="background: #f5f5f5; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
    <h3 style="margin-top: 0;">WAF Status</h3>
    <div style="display: flex; gap: 30px; flex-wrap: wrap;">
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
            <ul style="margin: 5px 0 0 0; padding-left: 20px;">{$sourcesList}</ul>
        </div>
    </div>
    <p style="margin-bottom: 0; margin-top: 10px; font-size: 12px; color: #666;">
        Sync blocklists: <code>vendor/bin/sake dev/tasks/waf-sync-blocklists</code>
    </p>
</div>
HTML
        );
    }

    protected function getBlockedRequestsGrid(): GridField
    {
        /** @var WafStorageService $storageService */
        $storageService = Injector::inst()->get(WafStorageService::class);
        $data = $storageService->getBlockedRequests(100);

        $config = GridFieldConfig::create()
            ->addComponent(new GridFieldToolbarHeader())
            ->addComponent(new GridFieldSortableHeader())
            ->addComponent($columns = new GridFieldDataColumns())
            ->addComponent(new GridFieldPaginator(25));

        $columns->setDisplayFields([
            'Created' => 'Time',
            'IpAddress' => 'IP Address',
            'Reason' => 'Reason',
            'Uri' => 'URI',
        ]);

        return GridField::create('BlockedRequests', 'Recent Blocked Requests', $data, $config);
    }

    protected function getBannedIpsGrid(): GridField
    {
        /** @var WafStorageService $storageService */
        $storageService = Injector::inst()->get(WafStorageService::class);
        $data = $storageService->getActiveBans();

        $config = GridFieldConfig::create()
            ->addComponent(new GridFieldToolbarHeader())
            ->addComponent(new GridFieldSortableHeader())
            ->addComponent($columns = new GridFieldDataColumns())
            ->addComponent(new GridFieldPaginator(25));

        $columns->setDisplayFields([
            'IpAddress' => 'IP Address',
            'Reason' => 'Reason',
            'ExpiresAt' => 'Expires',
        ]);

        // Add unban action column
        $columns->setFieldFormatting([
            'IpAddress' => function ($value, $item) {
                $url = $this->Link('unban') . '?ip=' . urlencode($value);
                return "{$value} <a href='{$url}' class='btn btn-sm btn-outline-danger' onclick='return confirm(\"Unban {$value}?\")'>Unban</a>";
            },
        ]);

        return GridField::create('BannedIPs', 'Active Bans', $data, $config);
    }

    protected function getManualBanFields(): LiteralField
    {
        $banUrl = $this->Link('ban');

        return LiteralField::create('ManualBan', <<<HTML
<div style="background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 4px; border: 1px solid #ffc107;">
    <h4 style="margin-top: 0;">Manual Ban</h4>
    <form method="post" action="{$banUrl}" style="display: flex; gap: 10px; align-items: end;">
        <div>
            <label>IP Address</label><br>
            <input type="text" name="ip" required pattern="[0-9a-fA-F.:\/]+" placeholder="1.2.3.4" style="padding: 5px;">
        </div>
        <div>
            <label>Duration (hours)</label><br>
            <input type="number" name="hours" value="24" min="1" max="8760" style="padding: 5px; width: 80px;">
        </div>
        <div>
            <label>Reason</label><br>
            <input type="text" name="reason" value="Manual ban" style="padding: 5px; width: 200px;">
        </div>
        <button type="submit" class="btn btn-warning">Ban IP</button>
    </form>
</div>
HTML
        );
    }

    protected function getBlocklistStatsField(): LiteralField
    {
        /** @var IpBlocklistService $service */
        $service = Injector::inst()->get(IpBlocklistService::class);
        $stats = $service->getStats();

        $sourceRows = '';
        foreach ($stats['sources'] ?? [] as $name => $source) {
            $status = isset($source['error'])
                ? "<span style='color:red'>Error: {$source['error']}</span>"
                : "<span style='color:green'>OK</span>";
            $count = $source['count'] ?? 0;
            $url = $source['url'] ?? $source['file'] ?? '-';

            $sourceRows .= "<tr><td>{$name}</td><td>{$count}</td><td>{$status}</td><td style='font-size:11px'>{$url}</td></tr>";
        }

        return LiteralField::create('BlocklistStats', <<<HTML
<div style="padding: 15px;">
    <h3>Threat Intelligence Blocklist</h3>
    <p>
        <strong>Total IPs:</strong> {$stats['total_ips']}<br>
        <strong>Total CIDRs:</strong> {$stats['total_cidrs']}<br>
        <strong>Last Sync:</strong> {$stats['synced_at']} ({$this->timeAgo($stats['synced_at'])})
    </p>

    <h4>Sources</h4>
    <table class="table" style="width: 100%;">
        <thead><tr><th>Source</th><th>Entries</th><th>Status</th><th>URL</th></tr></thead>
        <tbody>{$sourceRows}</tbody>
    </table>

    <p style="margin-top: 20px;">
        <strong>Sync command:</strong><br>
        <code>vendor/bin/sake dev/tasks/waf-sync-blocklists</code>
    </p>
    <p>
        <strong>Recommended cron (every 6 hours):</strong><br>
        <code>0 */6 * * * cd /path/to/site && vendor/bin/sake dev/tasks/waf-sync-blocklists</code>
    </p>
</div>
HTML
        );
    }

    protected function timeAgo(?int $timestamp): string
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

    public function unban(): void
    {
        $ip = $this->getRequest()->getVar('ip');
        if ($ip && $this->canEdit()) {
            /** @var WafStorageService $storageService */
            $storageService = Injector::inst()->get(WafStorageService::class);
            $storageService->unbanIp($ip);
        }

        $this->redirect($this->Link());
    }

    public function ban(): void
    {
        $request = $this->getRequest();
        $ip = $request->postVar('ip');
        $hours = (int) $request->postVar('hours') ?: 24;
        $reason = $request->postVar('reason') ?: 'Manual ban';

        if ($ip && $this->canEdit()) {
            /** @var WafStorageService $storageService */
            $storageService = Injector::inst()->get(WafStorageService::class);
            $storageService->banIp($ip, $hours * 3600, $reason);
        }

        $this->redirect($this->Link());
    }

    // ========================================================================
    // Permissions
    // ========================================================================

    public function canView($member = null): bool
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }

    public function canEdit($member = null): bool
    {
        return Permission::check('WAF_ADMIN', 'any', $member);
    }

    public function providePermissions(): array
    {
        return [
            'WAF_ADMIN' => [
                'name' => 'Administer WAF',
                'category' => 'Security',
                'help' => 'View blocked requests and manage IP bans',
            ],
        ];
    }
}
