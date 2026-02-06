<?php

namespace Restruct\SilverStripe\Waf\Admin;

use Restruct\SilverStripe\Waf\Models\BannedIp;
use Restruct\SilverStripe\Waf\Models\BlockedRequest;
use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use SilverStripe\Admin\ModelAdmin;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig_RecordEditor;
use SilverStripe\Forms\GridField\GridFieldDeleteAction;
use SilverStripe\Forms\GridField\GridFieldExportButton;
use SilverStripe\Forms\HeaderField;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\Tab;
use SilverStripe\Forms\TabSet;

/**
 * CMS Admin interface for WAF management
 *
 * Provides:
 * - View blocked requests log
 * - Manage banned IPs
 * - View blocklist sync status
 */
class WafAdmin extends ModelAdmin
{
    private static string $url_segment = 'waf';
    private static string $menu_title = 'WAF';
    private static string $menu_icon_class = 'font-icon-shield';
    private static int $menu_priority = -1;

    private static array $managed_models = [
        BlockedRequest::class,
        BannedIp::class,
    ];

    private static array $model_importers = [];

    public function getEditForm($id = null, $fields = null)
    {
        $form = parent::getEditForm($id, $fields);

        // Add blocklist stats to the main tab
        if ($this->modelClass === BlockedRequest::class) {
            $fields = $form->Fields();

            // Add stats panel
            $statsHtml = $this->getStatsHtml();
            $fields->unshift(LiteralField::create('WafStats', $statsHtml));
        }

        // Add bulk delete for blocked requests
        if ($this->modelClass === BlockedRequest::class) {
            $gridField = $form->Fields()->dataFieldByName($this->sanitiseClassName($this->modelClass));
            if ($gridField instanceof GridField) {
                $config = $gridField->getConfig();
                $config->addComponent(new GridFieldDeleteAction(true));
            }
        }

        return $form;
    }

    protected function getStatsHtml(): string
    {
        /** @var IpBlocklistService $service */
        $service = Injector::inst()->get(IpBlocklistService::class);
        $stats = $service->getStats();

        $syncedAt = $stats['synced_at']
            ? date('Y-m-d H:i:s', $stats['synced_at'])
            : 'Never';

        $blockedCount = BlockedRequest::get()->count();
        $blockedToday = BlockedRequest::get()
            ->filter('Created:GreaterThan', date('Y-m-d 00:00:00'))
            ->count();

        $bannedCount = BannedIp::get()
            ->filterAny([
                'IsPermanent' => true,
                'ExpiresAt:GreaterThan' => date('Y-m-d H:i:s'),
            ])
            ->count();

        $sourcesList = '';
        foreach ($stats['sources'] ?? [] as $name => $source) {
            if (isset($source['error'])) {
                $sourcesList .= "<li><strong>{$name}:</strong> <span style='color:red'>Error</span></li>";
            } else {
                $count = $source['count'] ?? 0;
                $sourcesList .= "<li><strong>{$name}:</strong> {$count} entries</li>";
            }
        }

        return <<<HTML
<div style="background: #f5f5f5; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
    <h3 style="margin-top: 0;">WAF Status</h3>
    <div style="display: flex; gap: 30px; flex-wrap: wrap;">
        <div>
            <strong>Blocked Today:</strong> {$blockedToday}<br>
            <strong>Total Blocked:</strong> {$blockedCount}<br>
            <strong>Active Bans:</strong> {$bannedCount}
        </div>
        <div>
            <strong>Blocklist IPs:</strong> {$stats['total_ips']}<br>
            <strong>Blocklist CIDRs:</strong> {$stats['total_cidrs']}<br>
            <strong>Last Sync:</strong> {$syncedAt}
        </div>
        <div>
            <strong>Sources:</strong>
            <ul style="margin: 0; padding-left: 20px;">{$sourcesList}</ul>
        </div>
    </div>
    <p style="margin-bottom: 0; font-size: 12px; color: #666;">
        Run <code>vendor/bin/sake dev/tasks/waf-sync-blocklists</code> to sync blocklists.
    </p>
</div>
HTML;
    }

    public function getList()
    {
        $list = parent::getList();

        // For blocked requests, show most recent first
        if ($this->modelClass === BlockedRequest::class) {
            $list = $list->sort('Created', 'DESC');
        }

        // For banned IPs, show active first
        if ($this->modelClass === BannedIp::class) {
            $list = $list->sort([
                'IsPermanent' => 'DESC',
                'ExpiresAt' => 'DESC',
            ]);
        }

        return $list;
    }
}
