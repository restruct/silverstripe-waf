<?php

namespace Restruct\SilverStripe\Waf\Tests\Middleware;

use Psr\Log\LoggerInterface;
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

    /**
     * The no-IP pass-through skips every check, so it logs at debug level each time it is taken,
     * and a request that has an IP does not log it.
     */
    public function testRequestWithoutIpIsLoggedAtDebugLevel(): void
    {
        $messages = [];
        # A mock rather than a logger class: psr/log's method signatures differ between the majors
        $logger = $this->createMock(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(function ($message) use (&$messages) {
            $messages[] = (string) $message;
        });
        Injector::inst()->registerService($logger, LoggerInterface::class);

        $request = new HTTPRequest('GET', '/some/page');
        WafMiddleware::create()->process($request, fn() => HTTPResponse::create('delegated', 200));

        $skipped = array_values(array_filter($messages, fn($m) => str_contains($m, 'no client IP')));
        $this->assertCount(1, $skipped, 'the no-IP branch logs once: ' . implode(' | ', $messages));
        $this->assertStringContainsString('some/page', $skipped[0]);

        # A request with a client IP goes through the checks and does not log the skip
        $messages = [];
        $request = new HTTPRequest('GET', '/some/page');
        $request->setIP('192.0.2.49');
        $request->addHeader('User-Agent', 'Mozilla/5.0');
        WafMiddleware::create()->process($request, fn() => HTTPResponse::create('delegated', 200));
        $this->assertSame([], array_filter($messages, fn($m) => str_contains($m, 'no client IP')));
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
