<?php

namespace Restruct\SilverStripe\Waf\Tests\Middleware;

use Psr\SimpleCache\CacheInterface;
use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\Security\SecurityToken;
use SilverStripe\Versioned\Versioned;

/**
 * A ban or unban made in the CMS must reach the next visitor request, with silverstripe/versioned installed.
 *
 * Versioned swaps the core CacheFactory for one that wraps every cache in VersionedCacheAdapter, which
 * suffixes each key with the current reading mode. The admin runs in draft (AdminController::init sets
 * Stage.Stage), while WafMiddleware runs as the first Director middleware, before VersionedHTTPMiddleware
 * has chosen a stage, so on a visitor request the reading mode is still null (unsuffixed keys). A ban key
 * written by the CMS and the key the middleware reads were therefore two different cache entries.
 *
 * Each scenario runs per storage mode: in 'cache' mode the cache is the only store, in 'file' and
 * 'database' mode it sits in front of the persisted list and can shadow it (a cached "not banned"
 * for 60 seconds, a cached "banned" for the rest of the ban).
 */
class VersionedBanCacheTest extends FunctionalTest
{
    protected $usesDatabase = true;

    private const STORAGE_MODES = ['file', 'database', 'cache'];

    /**
     * The reading modes a visitor request can be evaluated in: null is what WafMiddleware sees on a
     * real request (it runs before VersionedHTTPMiddleware), Stage.Live is the stage a visitor ends up on.
     */
    private const VISITOR_MODES = [null, 'Stage.Live'];

    private string $bansFile;
    private string $logFile;
    private string|false $errorLog;

    protected function setUp(): void
    {
        parent::setUp();
        # The ban and unban actions check the token; FunctionalTest disables it by default
        SecurityToken::enable();

        $this->cache()->clear();
        # Private files, so the shared temp files are left alone
        $this->bansFile = sys_get_temp_dir() . '/waf-versioned-test-bans-' . getmypid() . '.json';
        $this->logFile = sys_get_temp_dir() . '/waf-versioned-test-log-' . getmypid() . '.jsonl';
        Config::modify()->set(WafStorageService::class, 'bans_file', $this->bansFile);
        Config::modify()->set(WafStorageService::class, 'blocked_log_file', $this->logFile);
        Config::modify()->set(IpBlocklistService::class, 'blocklist_sources', []);
        Config::modify()->set(IpBlocklistService::class, 'sync_enabled', false);
        Config::modify()->set(WafMiddleware::class, 'whitelisted_ips', []);
        Config::modify()->set(WafMiddleware::class, 'log_blocked_requests', false);
        Config::modify()->set(WafMiddleware::class, 'use_styled_error_pages', false);
        Config::modify()->set(WafMiddleware::class, 'rate_limit_enabled', false);
        # Two bad requests make an auto-ban, so a visitor can be banned by the middleware itself
        Config::modify()->set(WafMiddleware::class, 'auto_ban_enabled', true);
        Config::modify()->set(WafMiddleware::class, 'ban_threshold', 2);
        # The middleware logs violations and bans with error_log(); keep that out of the test output
        $this->errorLog = ini_set('error_log', '/dev/null');

        # Same storage service, but it records the reading mode each ban/unban runs in (see postToAdmin)
        ReadingModeRecordingStorage::$lastReadingMode = 'none recorded';
        Injector::inst()->registerService(new ReadingModeRecordingStorage(), WafStorageService::class);

        $this->logInWithPermission('WAF_ADMIN');
    }

    protected function tearDown(): void
    {
        $this->cache()->clear();
        @unlink($this->bansFile);
        @unlink($this->logFile);
        if ($this->errorLog !== false) {
            ini_set('error_log', $this->errorLog);
        }
        parent::tearDown();
    }

    private function cache(): CacheInterface
    {
        return Injector::inst()->get(CacheInterface::class . '.Waf');
    }

    /**
     * Start a storage mode from a clean slate: no cached entries, no persisted bans.
     */
    private function useStorageMode(string $mode): void
    {
        Config::modify()->set(WafStorageService::class, 'storage_mode', $mode);
        $this->cache()->clear();
        @unlink($this->bansFile);
    }

    /**
     * POST a ban or unban to the admin, as the CMS screen does: a logged-in WAF admin, with the token.
     * FunctionalTest requests have no client IP, so WafMiddleware lets them through unchecked.
     */
    private function postToAdmin(string $action, array $data): void
    {
        $response = $this->get('admin/waf');
        $this->assertSame(200, $response->getStatusCode(), 'the admin screen loads');
        $inputs = $this->cssParser()->getByXpath('//form[@id="Form_EditForm"]//input[@name="SecurityID"]');
        $this->assertNotEmpty($inputs, 'the edit form carries a SecurityID');

        $response = $this->post('admin/waf/' . $action, $data + ['SecurityID' => (string) $inputs[0]['value']]);
        $this->assertLessThan(400, $response->getStatusCode(), "admin/waf/$action succeeded");

        # Control: the ban/unban really ran in draft. Without this, a CMS request that happened to run
        # in the visitor's reading mode would make every assertion below pass for the wrong reason.
        # Read from the recording storage service: Director::test() restores the reading mode after
        # the request, so it cannot be read afterwards.
        if (class_exists(Versioned::class)) {
            $this->assertSame(
                'Stage.' . Versioned::DRAFT,
                ReadingModeRecordingStorage::$lastReadingMode,
                "the CMS $action ran in draft"
            );
        }
    }

    /**
     * Run one visitor request through WafMiddleware in the given reading mode and return its status.
     * The reading mode is reset as a new PHP process would have it: nothing chosen yet, Live as default
     * (AdminController has changed both statics during the admin request of this same test process).
     */
    private function visitorStatus(string $ip, ?string $readingMode, string $userAgent = 'Mozilla/5.0'): int
    {
        if (class_exists(Versioned::class)) {
            Versioned::set_default_reading_mode('Stage.' . Versioned::LIVE);
            Versioned::set_reading_mode($readingMode);
        }
        $request = new HTTPRequest('GET', '/');
        $request->setIP($ip);
        $request->addHeader('User-Agent', $userAgent);

        return WafMiddleware::create()
            ->process($request, fn() => HTTPResponse::create('delegated', 200))
            ->getStatusCode();
    }

    private function modeLabel(?string $readingMode): string
    {
        return $readingMode ?? 'null';
    }

    /**
     * A ban placed in the CMS blocks the visitor on the next request.
     */
    public function testCmsBanBlocksVisitor(): void
    {
        $expected = $actual = [];
        foreach (self::STORAGE_MODES as $i => $storage) {
            foreach (self::VISITOR_MODES as $j => $visitorMode) {
                $this->useStorageMode($storage);
                $ip = '192.0.2.' . (100 + $i * 10 + $j);

                $this->postToAdmin('ban', ['ip' => $ip, 'hours' => 1, 'reason' => 'test']);

                $label = $storage . '/' . $this->modeLabel($visitorMode);
                $expected[$label] = 403;
                $actual[$label] = $this->visitorStatus($ip, $visitorMode);
            }
        }
        $this->assertSame($expected, $actual, 'visitor status after a CMS ban, per storage/reading mode');
    }

    /**
     * A ban placed in the CMS also blocks a visitor who was checked just before it: that check caches
     * "not banned" for 60 seconds, and the CMS ban has to replace it, not sit beside it.
     */
    public function testCmsBanBlocksVisitorWhoseCleanResultWasCached(): void
    {
        $expected = $actual = [];
        foreach (self::STORAGE_MODES as $i => $storage) {
            foreach (self::VISITOR_MODES as $j => $visitorMode) {
                $this->useStorageMode($storage);
                $ip = '192.0.2.' . (150 + $i * 10 + $j);
                $label = $storage . '/' . $this->modeLabel($visitorMode);

                # Primes the negative cache entry in the visitor's reading mode
                $this->assertSame(200, $this->visitorStatus($ip, $visitorMode), "$label: not banned yet");

                $this->postToAdmin('ban', ['ip' => $ip, 'hours' => 1, 'reason' => 'test']);

                $expected[$label] = 403;
                $actual[$label] = $this->visitorStatus($ip, $visitorMode);
            }
        }
        $this->assertSame($expected, $actual, 'visitor status after a CMS ban over a cached clean result');
    }

    /**
     * An auto-ban by the middleware (cached as "banned" for the whole ban duration, in the visitor's
     * reading mode) is lifted for the visitor when an admin unbans the IP in the CMS.
     */
    public function testCmsUnbanLetsAutoBannedVisitorBackIn(): void
    {
        $expected = $actual = [];
        foreach (self::STORAGE_MODES as $i => $storage) {
            foreach (self::VISITOR_MODES as $j => $visitorMode) {
                $this->useStorageMode($storage);
                $ip = '192.0.2.' . (200 + $i * 10 + $j);
                $label = $storage . '/' . $this->modeLabel($visitorMode);

                # Two blocked user-agent requests reach ban_threshold: the middleware bans the IP
                $this->visitorStatus($ip, $visitorMode, 'sqlmap/1.0');
                $this->visitorStatus($ip, $visitorMode, 'sqlmap/1.0');
                $this->assertSame(403, $this->visitorStatus($ip, $visitorMode), "$label: auto-banned");

                $this->postToAdmin('unban', ['ip' => $ip]);

                $expected[$label] = 200;
                $actual[$label] = $this->visitorStatus($ip, $visitorMode);
            }
        }
        $this->assertSame($expected, $actual, 'visitor status after a CMS unban of an auto-ban');
    }
}

/**
 * WafStorageService unchanged, except that it records the reading mode a ban or unban runs in.
 */
class ReadingModeRecordingStorage extends WafStorageService
{
    public static ?string $lastReadingMode = null;

    public function banIp(string $ip, int $duration, string $reason): void
    {
        static::$lastReadingMode = class_exists(Versioned::class) ? Versioned::get_reading_mode() : null;
        parent::banIp($ip, $duration, $reason);
    }

    public function unbanIp(string $ip): void
    {
        static::$lastReadingMode = class_exists(Versioned::class) ? Versioned::get_reading_mode() : null;
        parent::unbanIp($ip);
    }
}
