<?php

namespace Restruct\SilverStripe\Waf\Tests\Services;

use Psr\SimpleCache\CacheInterface;
use Restruct\SilverStripe\Waf\Models\BannedIp;
use Restruct\SilverStripe\Waf\Models\BlockedRequest;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;

/**
 * The admin-facing list methods of WafStorageService, in database and file mode, on both majors.
 *
 * Regression cover for two defects fixed in 1.6.0:
 * - database mode returned a DataList from methods typed `: ArrayList` (TypeError on every major);
 * - Silverstripe 6 moved ArrayList/ArrayData, so the SS5 class names fatal there.
 */
class WafStorageServiceListsTest extends SapphireTest
{
    protected $usesDatabase = true;

    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        # File mode writes to TEMP_PATH by default; point it at a private directory instead.
        $this->tmpDir = sys_get_temp_dir() . '/waf-lists-' . uniqid();
        mkdir($this->tmpDir);
        Config::modify()->set(WafStorageService::class, 'bans_file', $this->tmpDir . '/bans.json');
        Config::modify()->set(WafStorageService::class, 'blocked_log_file', $this->tmpDir . '/blocked.jsonl');
        Config::modify()->set(WafStorageService::class, 'high_load_threshold', 0);
    }

    protected function tearDown(): void
    {
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        foreach (glob($this->tmpDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tmpDir);
        parent::tearDown();
    }

    public function testDatabaseModeBansAreListed(): void
    {
        $service = $this->service('database');
        $service->banIp('203.0.113.9', 3600, 'test ban');

        $this->assertSame(1, BannedIp::get()->filter('IpAddress', '203.0.113.9')->count());
        $bans = $service->getActiveBans();
        $this->assertSame(['203.0.113.9'], $bans->column('IpAddress'));
        $this->assertTrue($service->isBanned('203.0.113.9'));
    }

    public function testDatabaseModeBlockedRequestsAreListed(): void
    {
        $service = $this->service('database');
        $service->logBlockedRequest('203.0.113.10', '/wp-login.php', 'curl', 'blocked_pattern', 'probe');

        $this->assertSame(1, BlockedRequest::get()->count());
        $this->assertSame(['/wp-login.php'], $service->getBlockedRequests(10)->column('Uri'));
    }

    /**
     * A long manual-ban reason must still be persisted. Silverstripe 6 validates Varchar length on
     * write and throws; the service swallows DB exceptions, so without truncation the ban was lost.
     */
    public function testDatabaseModeLongBanReasonIsPersisted(): void
    {
        $service = $this->service('database');
        $service->banIp('203.0.113.11', 3600, str_repeat('r', 300));

        $ban = BannedIp::get()->filter('IpAddress', '203.0.113.11')->first();
        $this->assertNotNull($ban, 'ban with a 300-character reason should be stored');
        $this->assertSame(255, strlen($ban->Reason));
    }

    /**
     * A blocked-request reason longer than its Varchar(50) must still be logged, cut to 50 characters
     * on a character boundary. Silverstripe 6 validates Varchar length on write and throws; the service
     * swallows DB exceptions, so without truncation the log row was lost. The reason is multibyte so a
     * byte-based substr (which would split a character and not yield these 50 characters) also fails.
     */
    public function testDatabaseModeLongMultibyteBlockedReasonIsPersisted(): void
    {
        $service = $this->service('database');
        # 60 characters, 120 bytes: each 'é' is two bytes in UTF-8.
        $reason = str_repeat('é', 60);
        $service->logBlockedRequest('203.0.113.13', '/xmlrpc.php', 'curl', $reason, 'probe');

        $log = BlockedRequest::get()->filter('IpAddress', '203.0.113.13')->first();
        $this->assertNotNull($log, 'blocked request with a 60-character reason should be stored');
        $this->assertSame(str_repeat('é', 50), $log->Reason);
    }

    public function testFileModeListsAreArrayListsOfTheRunningMajor(): void
    {
        $service = $this->service('file');
        $service->banIp('203.0.113.12', 3600, 'file ban');
        $service->logBlockedRequest('203.0.113.12', '/.env', 'curl', 'blocked_pattern', 'probe');

        $expectedList = class_exists('SilverStripe\\Model\\List\\ArrayList')
            ? 'SilverStripe\\Model\\List\\ArrayList'
            : 'SilverStripe\\ORM\\ArrayList';
        $expectedItem = class_exists('SilverStripe\\Model\\ArrayData')
            ? 'SilverStripe\\Model\\ArrayData'
            : 'SilverStripe\\View\\ArrayData';

        $bans = $service->getActiveBans();
        $this->assertInstanceOf($expectedList, $bans);
        $this->assertInstanceOf($expectedItem, $bans->first());
        $this->assertSame('203.0.113.12', $bans->first()->IpAddress);

        $blocked = $service->getBlockedRequests(10);
        $this->assertInstanceOf($expectedList, $blocked);
        $this->assertSame(['/.env'], $blocked->column('Uri'));
    }

    public function testEmptyListsInEveryMode(): void
    {
        foreach (['cache', 'file', 'database'] as $mode) {
            $service = $this->service($mode);
            $this->assertSame(0, $service->getActiveBans()->count(), "$mode bans");
            $this->assertSame(0, $service->getBlockedRequests()->count(), "$mode blocked");
        }
    }

    private function service(string $mode): WafStorageService
    {
        Config::modify()->set(WafStorageService::class, 'storage_mode', $mode);
        return WafStorageService::create();
    }
}
