<?php

namespace Restruct\SilverStripe\Waf\Tests\Middleware;

use Psr\SimpleCache\CacheInterface;
use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\TrustedProxyMiddleware;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;

/**
 * Behind a trusted reverse proxy (SS_TRUSTED_PROXY_IPS set), the WAF judges the visitor, not the proxy.
 *
 * HTTPRequest::getIP() starts out as REMOTE_ADDR (the proxy) and only becomes the client address from
 * X-Forwarded-For once TrustedProxyMiddleware has run. Requests go through the Director's real
 * middleware list, in its configured order, so the test fails if the WAF reads the IP too early.
 */
class TrustedProxyIpTest extends SapphireTest
{
    protected $usesDatabase = false;

    private const PROXY = '10.0.0.1';
    private const ATTACKER = '203.0.113.7';
    private const VISITOR = '203.0.113.8';

    private string|false $errorLog;
    private string $bansFile;
    private string $logFile;

    protected function setUp(): void
    {
        parent::setUp();
        $this->cache()->clear();
        $this->bansFile = sys_get_temp_dir() . '/waf-proxy-test-bans-' . getmypid() . '.json';
        $this->logFile = sys_get_temp_dir() . '/waf-proxy-test-log-' . getmypid() . '.jsonl';
        Config::modify()->set(WafStorageService::class, 'storage_mode', 'cache');
        Config::modify()->set(WafStorageService::class, 'bans_file', $this->bansFile);
        Config::modify()->set(WafStorageService::class, 'blocked_log_file', $this->logFile);
        Config::modify()->set(IpBlocklistService::class, 'blocklist_sources', []);
        Config::modify()->set(IpBlocklistService::class, 'sync_enabled', false);
        Config::modify()->set(WafMiddleware::class, 'whitelisted_ips', []);
        Config::modify()->set(WafMiddleware::class, 'log_blocked_requests', false);
        Config::modify()->set(WafMiddleware::class, 'use_styled_error_pages', false);
        Config::modify()->set(WafMiddleware::class, 'rate_limit_enabled', false);
        Config::modify()->set(WafMiddleware::class, 'auto_ban_enabled', true);
        Config::modify()->set(WafMiddleware::class, 'ban_threshold', 2);
        # The middleware logs violations and bans with error_log(); keep that out of the test output
        $this->errorLog = ini_set('error_log', '/dev/null');

        # The proxy is trusted the way a site configures it: SS_TRUSTED_PROXY_IPS, read by the
        # TrustedProxyMiddleware service definition. Drop the cached Director and middleware so both
        # are rebuilt from the environment set here.
        Environment::setEnv('SS_TRUSTED_PROXY_IPS', self::PROXY);
        Injector::inst()->unregisterObjects([Director::class, TrustedProxyMiddleware::class]);
    }

    protected function tearDown(): void
    {
        $this->cache()->clear();
        @unlink($this->bansFile);
        @unlink($this->logFile);
        if ($this->errorLog !== false) {
            ini_set('error_log', $this->errorLog);
        }
        Environment::setEnv('SS_TRUSTED_PROXY_IPS', '');
        Injector::inst()->unregisterObjects([Director::class, TrustedProxyMiddleware::class]);
        parent::tearDown();
    }

    private function cache(): CacheInterface
    {
        return Injector::inst()->get(CacheInterface::class . '.Waf');
    }

    /**
     * Send one request from $client through the proxy, through every Director middleware in order,
     * and return the status plus the IP the application finally saw (null when it was not reached).
     *
     * @return array{int, ?string}
     */
    private function throughProxy(string $client, string $userAgent = 'Mozilla/5.0'): array
    {
        $request = new HTTPRequest('GET', '/');
        $request->setIP(self::PROXY);                        # REMOTE_ADDR: the proxy connects to us
        $request->addHeader('X-Forwarded-For', $client);
        $request->addHeader('Host', 'localhost');
        $request->addHeader('User-Agent', $userAgent);
        $request->setSession(new Session([]));

        $seenIp = null;
        $next = function (HTTPRequest $request) use (&$seenIp) {
            $seenIp = $request->getIP();
            return HTTPResponse::create('app', 200);
        };
        # Same wrapping as HTTPMiddlewareAware::callMiddleware(): the first middleware runs first
        $middlewares = Injector::inst()->get(Director::class)->getMiddlewares();
        foreach (array_reverse($middlewares) as $middleware) {
            $next = fn(HTTPRequest $request) => $middleware->process($request, $next);
        }
        $response = $next($request);

        return [$response->getStatusCode(), $seenIp];
    }

    /**
     * Control: the proxy set-up in this test works, the application sees the client address.
     * Without it, the tests below could pass or fail on a misconfigured proxy rather than on the WAF.
     */
    public function testApplicationSeesTheClientAddress(): void
    {
        $this->assertSame([200, self::VISITOR], $this->throughProxy(self::VISITOR));
    }

    /**
     * A banned visitor is blocked when arriving through the proxy.
     */
    public function testBannedClientBehindProxyIsBlocked(): void
    {
        Injector::inst()->get(WafStorageService::class)->banIp(self::ATTACKER, 3600, 'test');

        $this->assertSame(403, $this->throughProxy(self::ATTACKER)[0], 'the banned client is blocked');
        $this->assertSame(200, $this->throughProxy(self::VISITOR)[0], 'another client of the proxy is not');
    }

    /**
     * An auto-ban hits the attacker only: other visitors behind the same proxy keep access.
     */
    public function testAutoBanBehindProxyBansTheClientNotTheProxy(): void
    {
        # Two blocked user-agent requests reach ban_threshold
        $this->throughProxy(self::ATTACKER, 'sqlmap/1.0');
        $this->throughProxy(self::ATTACKER, 'sqlmap/1.0');

        $storage = Injector::inst()->get(WafStorageService::class);
        $this->assertSame(
            ['attacker' => true, 'proxy' => false],
            ['attacker' => $storage->isBanned(self::ATTACKER), 'proxy' => $storage->isBanned(self::PROXY)],
            'the ban was recorded against the client address'
        );
        $this->assertSame(200, $this->throughProxy(self::VISITOR)[0], 'another client of the proxy is not banned');
    }
}
