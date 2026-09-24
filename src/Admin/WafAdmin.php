<?php

namespace Restruct\SilverStripe\Waf\Admin;

use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use Restruct\SilverStripe\Waf\Models\PrivilegedIp;
use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use Restruct\SilverStripe\Waf\Tasks\SyncBlocklistsTask;
use SilverStripe\Admin\LeftAndMain;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig;
use SilverStripe\Forms\GridField\GridFieldConfig_RecordEditor;
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
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;
use SilverStripe\Security\SecurityToken;

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
                    # The manual ban is now a component of the Active Bans grid (GridFieldManualBan):
                    # this LiteralField nested a <form> inside the edit form, which browsers drop,
                    # and posted without a security token.
                    // $this->getManualBanFields()
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
        )->setHTMLID('Form_EditForm');

        # CMSTabSet renders tab panels only (no <ul> nav — that's in LeftAndMain_EditForm.ss header).
        # The cms-tabset class on the form triggers Entwine to init jQuery UI Tabs,
        # which styles the header <ul> with ui-tabs-nav classes.
        if ($fields->hasTabSet()) {
            $fields->findOrMakeTab('Root')->setTemplate('SilverStripe\\Forms\\CMSTabSet');
        }

        $form->setTemplate($this->getTemplatesWithSuffix('_EditForm'));
        $form->addExtraClass('cms-tabset cms-edit-form');
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
            # Source names come from config and errors from a remote fetch: escape both
            $name = Convert::raw2xml((string) $name);
            if (isset($source['error'])) {
                $error = Convert::raw2xml((string) $source['error']);
                $sourcesList .= "<li><strong>{$name}:</strong> <span style='color:red'>Error - {$error}</span></li>";
            } else {
                $count = Convert::raw2xml((string) ($source['count'] ?? 0));
                $sourcesList .= "<li><strong>{$name}:</strong> {$count} entries</li>";
            }
        }

        # Everything interpolated into the HTML below is escaped, including values that are
        # numbers today: a LiteralField prints its content as-is.
        $blockedToday = Convert::raw2xml((string) $blockedToday);
        $totalBlocked = Convert::raw2xml((string) $totalBlocked);
        $bannedCount = Convert::raw2xml((string) $bannedCount);
        $syncedAt = Convert::raw2xml((string) $syncedAt);
        $totalIps = Convert::raw2xml((string) ($stats['total_ips'] ?? 0));
        $totalCidrs = Convert::raw2xml((string) ($stats['total_cidrs'] ?? 0));
        $storageMode = Convert::raw2xml((string) WafStorageService::config()->get('storage_mode'));
        # The sake syntax differs per major (dev/tasks/<segment> on SS5, tasks:<name> on SS6)
        $syncCommand = Convert::raw2xml(SyncBlocklistsTask::getSakeCommand());

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
            <strong>Blocklist IPs:</strong> {$totalIps}<br>
            <strong>Blocklist CIDRs:</strong> {$totalCidrs}<br>
            <strong>Last Sync:</strong> {$syncedAt}
        </div>
        <div>
            <strong>Storage Mode:</strong> {$storageMode}<br>
            <strong>Sources:</strong>
            <ul style="margin: 5px 0 0 0; padding-left: 20px;">{$sourcesList}</ul>
        </div>
    </div>
    <p style="margin-bottom: 0; margin-top: 10px; font-size: 12px; color: #666;">
        Sync blocklists: <code>{$syncCommand}</code>
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
            'Detail' => 'Detail',
            'Uri' => 'URI',
            'UserAgent' => 'User Agent',
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

        # Unban and manual ban are GridField actions: GridField posts them with the form's security
        # token and checks it before the action runs (GridField::gridFieldAlterAction()).
        $config->addComponent(new GridFieldUnbanAction());
        $config->addComponent(new GridFieldManualBan());

        # Replaced in 1.6.0 by GridFieldUnbanAction. This was a GET link without a security token
        # (cross-site request forgery), and the IP went into an inline onclick handler, where the
        # HTML-escaped value is decoded again before the JavaScript runs (script injection).
        // Add unban action column
        // $columns->setFieldFormatting([
        //     'IpAddress' => function ($value, $item) {
        //         $url = $this->Link('unban') . '?ip=' . urlencode($value);
        //         return "{$value} <a href='{$url}' class='btn btn-sm btn-outline-danger' onclick='return confirm(\"Unban {$value}?\")'>Unban</a>";
        //     },
        // ]);

        return GridField::create('BannedIPs', 'Active Bans', $data, $config);
    }

    # Replaced in 1.6.0 by GridFieldManualBan. This markup nested a <form> inside the edit form
    # (browsers drop the inner one, so the button never posted here), sent no security token and
    # validated the IP only in the browser (pattern attribute).
    // protected function getManualBanFields(): LiteralField
    // {
    //     $banUrl = $this->Link('ban');
    //
    //     return LiteralField::create('ManualBan', <<<HTML
    // <div style="background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 4px; border: 1px solid #ffc107;">
    // <h4 style="margin-top: 0;">Manual Ban</h4>
    // <form method="post" action="{$banUrl}" style="display: flex; gap: 10px; align-items: end;">
    //     <div>
    //         <label>IP Address</label><br>
    //         <input type="text" name="ip" required pattern="[0-9a-fA-F.:\/]+" placeholder="1.2.3.4" style="padding: 5px;">
    //     </div>
    //     <div>
    //         <label>Duration (hours)</label><br>
    //         <input type="number" name="hours" value="24" min="1" max="8760" style="padding: 5px; width: 80px;">
    //     </div>
    //     <div>
    //         <label>Reason</label><br>
    //         <input type="text" name="reason" value="Manual ban" style="padding: 5px; width: 200px;">
    //     </div>
    //     <button type="submit" class="btn btn-warning">Ban IP</button>
    // </form>
    // </div>
    // HTML
    //     );
    // }

    protected function getPrivilegedIpsInfoField(): LiteralField
    {
        $baseLimit = WafMiddleware::config()->get('rate_limit_requests');
        $window = WafMiddleware::config()->get('rate_limit_window');
        # Config values printed into a LiteralField: escape them
        $exampleDouble = Convert::raw2xml((string) ((int) $baseLimit * 2));
        $baseLimit = Convert::raw2xml((string) $baseLimit);
        $window = Convert::raw2xml((string) $window);

        return LiteralField::create('PrivilegedIpsInfo', <<<HTML
<div style="background: #e8f5e9; padding: 15px; margin-bottom: 20px; border-radius: 4px; border: 1px solid #a5d6a7;">
    <h4 style="margin-top: 0;">Privileged IPs</h4>
    <p style="margin-bottom: 5px;">
        Privileged IPs still go through <strong>all security checks</strong> (bans, blocklist, user-agent)
        but receive an elevated rate limit via a configurable multiplier.
    </p>
    <p style="margin-bottom: 5px;">
        <strong>Base rate limit:</strong> {$baseLimit} requests per {$window} seconds.
        A Factor of <strong>2.0</strong> = {$baseLimit} &times; 2 = <strong>{$exampleDouble}</strong> effective requests.
    </p>
    <p style="margin-bottom: 0;">
        IPs assigned to a <strong>config tier</strong> automatically inherit that tier's factor.
        Changing a tier's factor in YAML applies to all IPs in that tier.
    </p>
</div>
HTML
        );
    }

    protected function getPrivilegedIpsGrid(): GridField
    {
        return GridField::create(
            'PrivilegedIPs',
            'Privileged IPs (Database)',
            PrivilegedIp::get(),
            GridFieldConfig_RecordEditor::create()
        );
    }

    protected function getPrivilegedIpsConfigField(): LiteralField
    {
        $tiers = WafMiddleware::config()->get('privileged_tiers') ?: [];

        if (empty($tiers)) {
            return LiteralField::create('PrivilegedIpsConfig', <<<HTML
<div style="background: #f5f5f5; padding: 15px; margin-top: 20px; border-radius: 4px;">
    <h4 style="margin-top: 0;">YAML Config Tiers</h4>
    <p style="margin-bottom: 0; color: #666;">No tiers defined in YAML config. Use the grid above to manage privileged IPs, or define tiers in <code>_config/config.yml</code>.</p>
</div>
HTML
            );
        }

        $tierRows = '';
        foreach ($tiers as $tierName => $tierConfig) {
            # Tier names, factors and IPs come from YAML config: escape them
            $tierName = Convert::raw2xml((string) $tierName);
            $factor = Convert::raw2xml((string) ($tierConfig['factor'] ?? 2.0));
            $ips = $tierConfig['ips'] ?? [];
            $ipList = Convert::raw2xml(implode(', ', (array) $ips));
            $tierRows .= "<tr><td><strong>{$tierName}</strong></td><td>{$factor}</td><td style='font-size: 12px;'>{$ipList}</td></tr>";
        }

        return LiteralField::create('PrivilegedIpsConfig', <<<HTML
<div style="background: #f5f5f5; padding: 15px; margin-top: 20px; border-radius: 4px;">
    <h4 style="margin-top: 0;">YAML Config Tiers <span style="font-weight: normal; color: #666;">(read-only)</span></h4>
    <p style="font-size: 12px; color: #666;">These tiers are defined in YAML config and merged with database entries at runtime. DB entries override config for the same IP.</p>
    <table class="table" style="width: 100%;">
        <thead><tr><th>Tier</th><th>Factor</th><th>IPs</th></tr></thead>
        <tbody>{$tierRows}</tbody>
    </table>
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
            # Names and URLs come from config, errors from a remote fetch: escape all of them
            $status = isset($source['error'])
                ? "<span style='color:red'>Error: " . Convert::raw2xml((string) $source['error']) . "</span>"
                : "<span style='color:green'>OK</span>";
            $name = Convert::raw2xml((string) $name);
            $count = Convert::raw2xml((string) ($source['count'] ?? 0));
            $url = Convert::raw2xml((string) ($source['url'] ?? $source['file'] ?? '-'));

            $sourceRows .= "<tr><td>{$name}</td><td>{$count}</td><td>{$status}</td><td style='font-size:11px'>{$url}</td></tr>";
        }

        $totalIps = Convert::raw2xml((string) ($stats['total_ips'] ?? 0));
        $totalCidrs = Convert::raw2xml((string) ($stats['total_cidrs'] ?? 0));
        $syncedAt = Convert::raw2xml((string) ($stats['synced_at'] ?? ''));
        $syncedAgo = Convert::raw2xml($this->timeAgo($stats['synced_at'] ?? null));
        # The sake syntax differs per major (dev/tasks/<segment> on SS5, tasks:<name> on SS6)
        $syncCommand = Convert::raw2xml(SyncBlocklistsTask::getSakeCommand());

        return LiteralField::create('BlocklistStats', <<<HTML
<div style="padding: 15px;">
    <h3>Threat Intelligence Blocklist</h3>
    <p>
        <strong>Total IPs:</strong> {$totalIps}<br>
        <strong>Total CIDRs:</strong> {$totalCidrs}<br>
        <strong>Last Sync:</strong> {$syncedAt} ({$syncedAgo})
    </p>

    <h4>Sources</h4>
    <table class="table" style="width: 100%;">
        <thead><tr><th>Source</th><th>Entries</th><th>Status</th><th>URL</th></tr></thead>
        <tbody>{$sourceRows}</tbody>
    </table>

    <p style="margin-top: 20px;">
        <strong>Sync command:</strong><br>
        <code>{$syncCommand}</code>
    </p>
    <p>
        <strong>Recommended cron (every 6 hours):</strong><br>
        <code>0 */6 * * * cd /path/to/site && {$syncCommand}</code>
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

    /**
     * Unban an IP: POST only, with the security token (param `SecurityID`), as a WAF admin.
     * The admin screen itself unbans through GridFieldUnbanAction; this URL action is kept for
     * scripted use and answers 405 / 400 / 403 to a request that fails those checks.
     */
    public function unban(HTTPRequest $request): HTTPResponse
    {
        $this->checkStateChangingRequest($request);

        $ip = trim((string) $request->postVar('ip'));
        if ($ip !== '') {
            $this->applyUnban($ip);
        }

        return $this->redirect($this->Link());
    }

    /**
     * Ban an IP manually: POST only, with the security token, as a WAF admin, and the IP must be
     * a single valid IPv4 or IPv6 address (400 otherwise; bans are per address, not per range).
     */
    public function ban(HTTPRequest $request): HTTPResponse
    {
        $this->checkStateChangingRequest($request);

        $applied = $this->applyManualBan(
            (string) $request->postVar('ip'),
            (int) $request->postVar('hours'),
            (string) $request->postVar('reason')
        );
        if (!$applied) {
            $this->httpError(400, 'Not a valid IP address');
        }

        return $this->redirect($this->Link());
    }

    /**
     * The WafAdmin a GridField action runs under, refusing a request that is not a POST (405) and
     * a member without WAF_ADMIN (403). GridField has already refused a request without a valid
     * security token by then.
     *
     * @throws HTTPResponse_Exception
     */
    public static function fromGridField(GridField $gridField): self
    {
        $admin = $gridField->getForm()?->getController();
        if (!$admin instanceof self || !$admin->canEdit()) {
            throw new HTTPResponse_Exception('Not allowed to administer the WAF', 403);
        }
        # GridField also runs an action from GET parameters. With the token in the query string that
        # is still a replayable state change (a token leaked through a Referer, a log or history,
        # a prefetcher), so a GridField action here changes state on a POST only, as GridField's
        # own JavaScript sends it.
        if (!$admin->getRequest()->isPOST()) {
            throw new HTTPResponse_Exception('This action accepts POST requests only', 405);
        }

        return $admin;
    }

    /**
     * Refuse a state-changing request that is not a POST, lacks a valid security token or comes
     * from a member without WAF_ADMIN. Each refusal throws (via httpError), so nothing runs after it.
     */
    protected function checkStateChangingRequest(HTTPRequest $request): void
    {
        # A GET must never change state: links can be followed by anyone's browser (CSRF)
        if (!$request->isPOST()) {
            $this->httpError(405, 'This action accepts POST requests only');
        }
        # The token ties the request to this member's session, so another site cannot forge it
        if (!SecurityToken::inst()->checkRequest($request)) {
            $this->httpError(400, 'Invalid or missing security token');
        }
        if (!$this->canEdit()) {
            $this->httpError(403, 'Not allowed to administer the WAF');
        }
    }

    /**
     * Ban an IP after validating it server-side. Used by the ban action and GridFieldManualBan;
     * the caller has already checked the request (method, token, permission).
     *
     * @return bool false when $ip is not a single valid IPv4/IPv6 address (nothing is banned)
     */
    public function applyManualBan(string $ip, int $hours, string $reason): bool
    {
        $ip = trim($ip);
        # Validated here, not only by the form's pattern attribute: a client-side check is advice.
        # Bans are keyed per exact address, so a range such as 10.0.0.0/8 would never match.
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        # Store the canonical spelling: bans are keyed on the exact string, and PHP reports a
        # client's IPv6 address in compressed lower case (2001:db8::99). A ban typed as
        # 2001:DB8::99 or 2001:0db8:0:0:0:0:0:99 would be listed as active and block nobody.
        # IPv4 comes back unchanged. An IPv4-mapped IPv6 address (::ffff:192.0.2.1) keeps that
        # form: whether the server reports such a client as IPv4 or mapped IPv6 depends on the stack.
        $ip = (string) inet_ntop((string) inet_pton($ip));
        # Same bounds as the form field: 1 hour to 1 year, 24 hours when not given
        $hours = $hours > 0 ? min($hours, 8760) : 24;
        $reason = trim($reason) !== '' ? trim($reason) : 'Manual ban';

        /** @var WafStorageService $storageService */
        $storageService = Injector::inst()->get(WafStorageService::class);
        $storageService->banIp($ip, $hours * 3600, $reason);

        return true;
    }

    /**
     * Remove a ban. Not validated as an IP on purpose: a malformed entry that is already stored
     * must stay removable. Used by the unban action and GridFieldUnbanAction.
     */
    public function applyUnban(string $ip): void
    {
        /** @var WafStorageService $storageService */
        $storageService = Injector::inst()->get(WafStorageService::class);
        $storageService->unbanIp($ip);
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
