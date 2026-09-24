<?php

namespace Restruct\SilverStripe\Waf\Tests\Admin;

use Psr\SimpleCache\CacheInterface;
use Restruct\SilverStripe\Waf\Admin\WafAdmin;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Security\Member;

/**
 * The WAF admin screen builds and renders on both majors, in file and database storage mode.
 */
class WafAdminTest extends SapphireTest
{
    protected $usesDatabase = true;

    protected function setUp(): void
    {
        parent::setUp();
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        Config::modify()->set('Restruct\\SilverStripe\\Waf\\Services\\IpBlocklistService', 'blocklist_sources', []);
    }

    protected function tearDown(): void
    {
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        parent::tearDown();
    }

    public function testPermissionIsRequired(): void
    {
        $this->logInWithPermission('WAF_ADMIN');
        $this->assertTrue(WafAdmin::singleton()->canView());

        $this->logOut();
        $this->logInAs(Member::create(['Email' => 'noperm@example.com']));
        $this->assertFalse(WafAdmin::singleton()->canView());
    }

    public function testEditFormHasTabsAndGridsInEveryStorageMode(): void
    {
        $this->logInWithPermission('ADMIN');

        foreach (['file', 'database'] as $mode) {
            Config::modify()->set(WafStorageService::class, 'storage_mode', $mode);
            # A ban and a blocked request so the grids have rows (database mode lists a DataList)
            $storage = WafStorageService::create();
            $storage->banIp('198.51.100.20', 3600, "ban in $mode mode");
            $storage->logBlockedRequest('198.51.100.20', '/wp-admin', 'curl', 'blocked_pattern', $mode);

            $admin = WafAdmin::create();
            $request = new HTTPRequest('GET', '/admin/waf');
            $request->setSession(new Session([]));   # Form reads its session through the request
            $admin->setRequest($request);
            $form = $admin->getEditForm();
            $fields = $form->Fields();

            foreach (['Root.BlockedRequests', 'Root.BannedIPs', 'Root.PrivilegedIPs', 'Root.Blocklist'] as $tab) {
                $this->assertNotNull($fields->findTab($tab), "$mode: $tab");
            }
            foreach (['BlockedRequests', 'BannedIPs', 'PrivilegedIPs'] as $grid) {
                $this->assertInstanceOf(GridField::class, $fields->dataFieldByName($grid), "$mode: $grid");
            }
            $this->assertGreaterThan(0, $fields->dataFieldByName('BannedIPs')->getList()->count(), "$mode bans");

            # Rendering walks every grid row, which is where a wrong list type would surface.
            $html = (string) $form->forTemplate();
            $this->assertStringContainsString('198.51.100.20', $html, "$mode render");
        }
    }
}
