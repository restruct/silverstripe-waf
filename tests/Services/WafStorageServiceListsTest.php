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

    /**
     * A multibyte manual-ban reason over the Varchar(255) must be stored as its first 255 characters.
     * 300 x 'é' is 600 bytes: a byte cut (substr) at 255 splits the 128th character, so the stored
     * value is not these 255 characters (MySQL keeps 127 of them and stores the split one as '?').
     */
    public function testDatabaseModeLongMultibyteBanReasonIsPersisted(): void
    {
        $service = $this->service('database');
        $service->banIp('203.0.113.14', 3600, str_repeat('é', 300));

        $ban = BannedIp::get()->filter('IpAddress', '203.0.113.14')->first();
        $this->assertNotNull($ban, 'ban with a 300-character multibyte reason should be stored');
        $this->assertSame(str_repeat('é', 255), $ban->Reason);
    }

    /**
     * A multibyte blocked-request Uri over its Varchar(255) must be stored as its first 255 characters.
     */
    public function testDatabaseModeLongMultibyteBlockedUriIsPersisted(): void
    {
        $service = $this->service('database');
        $service->logBlockedRequest('203.0.113.15', '/' . str_repeat('é', 299), 'curl', 'blocked_pattern', 'probe');

        $log = BlockedRequest::get()->filter('IpAddress', '203.0.113.15')->first();
        $this->assertNotNull($log, 'blocked request with a 300-character multibyte URI should be stored');
        $this->assertSame('/' . str_repeat('é', 254), $log->Uri);
    }

    /**
     * A multibyte blocked-request UserAgent over its Varchar(255) must be stored as its first 255 characters.
     */
    public function testDatabaseModeLongMultibyteBlockedUserAgentIsPersisted(): void
    {
        $service = $this->service('database');
        $service->logBlockedRequest('203.0.113.16', '/xmlrpc.php', str_repeat('é', 300), 'blocked_pattern', 'probe');

        $log = BlockedRequest::get()->filter('IpAddress', '203.0.113.16')->first();
        $this->assertNotNull($log, 'blocked request with a 300-character multibyte user agent should be stored');
        $this->assertSame(str_repeat('é', 255), $log->UserAgent);
    }

    /**
     * A multibyte blocked-request Detail over its Varchar(255) must be stored as its first 255 characters.
     */
    public function testDatabaseModeLongMultibyteBlockedDetailIsPersisted(): void
    {
        $service = $this->service('database');
        $service->logBlockedRequest('203.0.113.17', '/xmlrpc.php', 'curl', 'blocked_pattern', str_repeat('é', 300));

        $log = BlockedRequest::get()->filter('IpAddress', '203.0.113.17')->first();
        $this->assertNotNull($log, 'blocked request with a 300-character multibyte detail should be stored');
        $this->assertSame(str_repeat('é', 255), $log->Detail);
    }

    /**
     * File mode: a multibyte blocked-request URI over 255 characters must be logged as its first 255.
     * 300 x 'é' is 600 bytes: a byte cut (substr) at 255 splits the 128th character, json_encode()
     * fails on the invalid UTF-8 and the JSONL entry is lost (a blank line is written instead).
     */
    public function testFileModeLongMultibyteBlockedUriIsLogged(): void
    {
        $service = $this->service('file');
        $service->logBlockedRequest('203.0.113.18', str_repeat('é', 300), 'curl', 'blocked_pattern', 'probe');

        $blocked = $service->getBlockedRequests(10);
        $this->assertSame(['203.0.113.18'], $blocked->column('IpAddress'), 'entry should be in the JSONL log');
        $this->assertSame(str_repeat('é', 255), $blocked->first()->Uri);
    }

    /**
     * File mode: a multibyte blocked-request user agent over 255 characters must be logged as its first 255.
     */
    public function testFileModeLongMultibyteBlockedUserAgentIsLogged(): void
    {
        $service = $this->service('file');
        $service->logBlockedRequest('203.0.113.19', '/xmlrpc.php', str_repeat('é', 300), 'blocked_pattern', 'probe');

        $blocked = $service->getBlockedRequests(10);
        $this->assertSame(['203.0.113.19'], $blocked->column('IpAddress'), 'entry should be in the JSONL log');
        $this->assertSame(str_repeat('é', 255), $blocked->first()->UserAgent);
    }

    /**
     * File mode: a multibyte blocked-request detail over 255 characters must be logged as its first 255.
     */
    public function testFileModeLongMultibyteBlockedDetailIsLogged(): void
    {
        $service = $this->service('file');
        $service->logBlockedRequest('203.0.113.20', '/xmlrpc.php', 'curl', 'blocked_pattern', str_repeat('é', 300));

        $blocked = $service->getBlockedRequests(10);
        $this->assertSame(['203.0.113.20'], $blocked->column('IpAddress'), 'entry should be in the JSONL log');
        $this->assertSame(str_repeat('é', 255), $blocked->first()->Detail);
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
