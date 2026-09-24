<?php

namespace Restruct\SilverStripe\Waf\Tests\Middleware;

use Psr\SimpleCache\CacheInterface;
use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;

/**
 * WafMiddleware::process() end to end, with a booted framework, on both majors.
 */
class WafMiddlewareRequestTest extends SapphireTest
{
    protected $usesDatabase = false;

    protected function setUp(): void
    {
        parent::setUp();
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        # Keep the checks deterministic: no blocklist feeds, cache-only storage, empty whitelist.
        Config::modify()->set(WafStorageService::class, 'storage_mode', 'cache');
        Config::modify()->set(WafMiddleware::class, 'whitelisted_ips', []);
        Config::modify()->set(WafMiddleware::class, 'log_blocked_requests', false);
        Config::modify()->set('Restruct\\SilverStripe\\Waf\\Services\\IpBlocklistService', 'sync_enabled', false);
    }

    protected function tearDown(): void
    {
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        parent::tearDown();
    }

    /**
     * An in-process request (Director::test(), which ErrorPage uses during dev/build) has no IP.
     * That used to reach string-typed checks and throw a TypeError.
     */
    public function testRequestWithoutIpIsPassedThrough(): void
    {
        $request = new HTTPRequest('GET', '/');
        $request->addHeader('User-Agent', 'sqlmap/1.0');   # would be blocked if it were checked
        $this->assertNull($request->getIP());

        $response = WafMiddleware::create()->process($request, fn() => HTTPResponse::create('delegated', 200));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('delegated', $response->getBody());
    }

    public function testBlockedUserAgentIsRefusedWithAClientIp(): void
    {
        $request = new HTTPRequest('GET', '/');
        $request->setIP('192.0.2.50');
        $request->addHeader('User-Agent', 'sqlmap/1.0');

        $response = WafMiddleware::create()->process($request, fn() => HTTPResponse::create('delegated', 200));

        $this->assertSame(403, $response->getStatusCode());
    }

    public function testHardRateLimitReturns429(): void
    {
        Config::modify()->set(WafMiddleware::class, 'rate_limit_requests', 3);
        Config::modify()->set(WafMiddleware::class, 'use_styled_error_pages', false);
        Config::modify()->set(WafMiddleware::class, 'auto_ban_enabled', false);
        Config::modify()->set(WafMiddleware::class, 'rate_limit_exempt_verified_bots', false);
        $middleware = WafMiddleware::create();

        $codes = [];
        for ($i = 0; $i < 4; $i++) {
            $request = new HTTPRequest('GET', '/');
            $request->setIP('192.0.2.51');
            $request->addHeader('User-Agent', 'Mozilla/5.0');
            $codes[] = $middleware->process($request, fn() => HTTPResponse::create('ok', 200))->getStatusCode();
        }

        $this->assertSame([200, 200, 200, 429], $codes);
    }
}
