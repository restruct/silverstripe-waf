<?php

namespace Restruct\SilverStripe\Waf\Tests;

use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\TrustedProxyMiddleware;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;

/**
 * The early filter (_waf_early_filter.php) behind a reverse proxy or CDN: it bans and counts the client
 * from X-Forwarded-For when, and only when, REMOTE_ADDR is a trusted proxy (SS_TRUSTED_PROXY_IPS).
 *
 * The filter runs at the top of public/index.php and exits on a block, so each case runs it in its own
 * PHP process, with its own TMPDIR (the filter keeps its ban and violation files under the temp dir)
 * and an explicit environment, so nothing from this process or the machine leaks in.
 */
class EarlyFilterProxyTest extends SapphireTest
{
    protected $usesDatabase = false;

    private const PROXY = '10.0.0.1';
    private const CLIENT = '8.8.8.8';
    private const OTHER = '9.9.9.9';

    private string $tmpDir;
    private string $script;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . '/waf-early-proxy-' . getmypid() . '-' . mt_rand();
        mkdir($this->tmpDir, 0755, true);
        # A request handler in miniature: fill $_SERVER, run the filter, report if it let the request on
        $this->script = $this->tmpDir . '/run.php';
        file_put_contents($this->script, '<?php' . "\n"
            . '$_SERVER = array_merge($_SERVER, json_decode(getenv("WAF_TEST_SERVER"), true));' . "\n"
            . 'require ' . var_export(dirname(__DIR__) . '/_waf_early_filter.php', true) . ';' . "\n"
            . 'echo "PASSED";' . "\n");
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
        parent::tearDown();
    }

    private function removeDir(string $dir): void
    {
        foreach (glob($dir . '/{,.}[!.,!..]*', GLOB_BRACE) ?: [] as $path) {
            is_dir($path) ? $this->removeDir($path) : @unlink($path);
        }
        @rmdir($dir);
    }

    /**
     * The filter's data dir as the filter computes it, under this test's TMPDIR.
     */
    private function dataDir(): string
    {
        $dir = $this->tmpDir . '/waf_' . substr(md5(dirname(__DIR__)), 0, 8);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        return $dir;
    }

    private function ban(string $ip): void
    {
        file_put_contents($this->dataDir() . '/ban_' . md5($ip), (string) (time() + 3600));
    }

    /**
     * The config file the middleware writes for the filter (see WafMiddleware::writeEarlyFilterConfig()).
     */
    private function writeFilterConfig(array $config): void
    {
        file_put_contents($this->dataDir() . '/config.json', json_encode($config + [
            'early_ban_enabled' => true, 'ban_threshold' => 10, 'ban_duration' => 3600,
        ]));
    }

    /**
     * Run the filter once. $headers are HTTP header names and values; $env is the process environment
     * on top of TMPDIR (nothing else is inherited). Returns 'FORBIDDEN' or 'PASSED'.
     */
    private function runFilter(string $remoteAddr, array $headers, array $env = [], string $path = '/'): string
    {
        $server = ['REMOTE_ADDR' => $remoteAddr, 'REQUEST_URI' => $path, 'HTTP_USER_AGENT' => 'Mozilla/5.0'];
        foreach ($headers as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }
        $env = ['TMPDIR' => $this->tmpDir, 'WAF_TEST_SERVER' => json_encode($server)] + $env;

        $process = proc_open(
            [PHP_BINARY, '-n', $this->script],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            $env
        );
        $out = stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);   # the filter's error_log() lines
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        return match (trim((string) $out)) {
            'Forbidden' => 'FORBIDDEN',
            'PASSED' => 'PASSED',
            default => 'UNEXPECTED: ' . $out,
        };
    }

    /**
     * The client address Silverstripe's own TrustedProxyMiddleware picks for this request.
     */
    private function frameworkClientIp(string $remoteAddr, array $headers, string $trusted): ?string
    {
        $request = new HTTPRequest('GET', '/');
        $request->setIP($remoteAddr);
        foreach ($headers as $name => $value) {
            $request->addHeader($name, $value);
        }
        $middleware = new TrustedProxyMiddleware();
        $middleware->setTrustedProxyIPs($trusted);
        $middleware->process($request, fn() => HTTPResponse::create());
        return $request->getIP();
    }

    /**
     * A ban on the client blocks it through a proxy trusted by SS_TRUSTED_PROXY_IPS in the environment.
     */
    public function testBannedClientIsBlockedThroughProxyTrustedByEnvironment(): void
    {
        $this->ban(self::CLIENT);
        $env = ['SS_TRUSTED_PROXY_IPS' => self::PROXY];

        $this->assertSame(
            ['client' => 'FORBIDDEN', 'other client' => 'PASSED'],
            [
                'client' => $this->runFilter(self::PROXY, ['X-Forwarded-For' => self::CLIENT], $env),
                'other client' => $this->runFilter(self::PROXY, ['X-Forwarded-For' => self::OTHER], $env),
            ]
        );
    }

    /**
     * SS_TRUSTED_PROXY_IPS usually lives in .env, which is only loaded by the framework, after the filter.
     * The middleware passes the value on in the filter's config file; the filter uses it from there.
     */
    public function testBannedClientIsBlockedThroughProxyTrustedByMiddlewareConfigFile(): void
    {
        $this->ban(self::CLIENT);
        $this->writeFilterConfig(['trusted_proxy_ips' => '10.0.0.0/8']);

        $this->assertSame('FORBIDDEN', $this->runFilter(self::PROXY, ['X-Forwarded-For' => self::CLIENT]));
    }

    /**
     * A probe through a trusted proxy counts as a violation of the client, never of the proxy
     * (a proxy that collects violations is banned, and with it every visitor behind it).
     */
    public function testProbeThroughTrustedProxyCountsAgainstTheClient(): void
    {
        $env = ['SS_TRUSTED_PROXY_IPS' => self::PROXY];
        $this->assertSame(
            'FORBIDDEN',
            $this->runFilter(self::PROXY, ['X-Forwarded-For' => self::CLIENT], $env, '/wp-login.php'),
            'the probe is blocked'
        );

        $this->assertSame(
            ['client' => true, 'proxy' => false],
            [
                'client' => file_exists($this->dataDir() . '/viol_' . md5(self::CLIENT)),
                'proxy' => file_exists($this->dataDir() . '/viol_' . md5(self::PROXY)),
            ],
            'the violation is recorded against the client'
        );
    }

    /**
     * A sender that is not a trusted proxy cannot pick its address with X-Forwarded-For: a banned
     * sender stays banned, and naming a banned address does not get someone else blocked.
     */
    public function testUntrustedSenderCannotSpoofForwardedFor(): void
    {
        $sender = '1.1.1.1';
        $env = ['SS_TRUSTED_PROXY_IPS' => self::PROXY];
        $this->ban(self::CLIENT);

        $this->assertSame('PASSED', $this->runFilter($sender, ['X-Forwarded-For' => self::CLIENT], $env));

        $this->ban($sender);
        $this->assertSame('FORBIDDEN', $this->runFilter($sender, ['X-Forwarded-For' => self::OTHER], $env));
    }

    /**
     * With no trusted proxies known (not in the environment, no config file yet), the filter uses
     * REMOTE_ADDR and ignores the header. So is 'none', the framework's explicit off switch.
     */
    public function testWithoutTrustedProxiesTheHeaderIsIgnored(): void
    {
        $this->ban(self::CLIENT);
        $results = [
            'nothing configured' => $this->runFilter(self::PROXY, ['X-Forwarded-For' => self::CLIENT]),
            'none' => $this->runFilter(self::PROXY, ['X-Forwarded-For' => self::CLIENT], ['SS_TRUSTED_PROXY_IPS' => 'none']),
        ];
        $this->ban(self::PROXY);
        $results['ban on REMOTE_ADDR'] = $this->runFilter(self::PROXY, ['X-Forwarded-For' => self::OTHER]);

        $this->assertSame(
            ['nothing configured' => 'PASSED', 'none' => 'PASSED', 'ban on REMOTE_ADDR' => 'FORBIDDEN'],
            $results
        );
    }

    /**
     * The filter picks the same client address as TrustedProxyMiddleware, so the early filter and the
     * middleware ban the same visitor: same headers (Client-IP before X-Forwarded-For), same choice
     * from a list, same matching of the trusted list (single IPs, CIDR ranges, IPv6, '*').
     */
    public function testClientAddressMatchesTheFramework(): void
    {
        $cases = [
            'single' => [self::PROXY, ['X-Forwarded-For' => '8.8.4.4'], self::PROXY],
            'list, private first' => [self::PROXY, ['X-Forwarded-For' => '192.168.1.5, 8.8.4.4, 1.0.0.1'], self::PROXY],
            'list, public first' => [self::PROXY, ['X-Forwarded-For' => '1.0.0.2, 8.8.4.4'], self::PROXY],
            'only private' => [self::PROXY, ['X-Forwarded-For' => '192.168.1.6'], self::PROXY],
            'Client-IP wins' => [self::PROXY, ['Client-IP' => '1.0.0.3', 'X-Forwarded-For' => '8.8.4.4'], self::PROXY],
            'CIDR list' => ['172.16.5.4', ['X-Forwarded-For' => '1.0.0.4'], '10.0.0.0/8, 172.16.0.0/12'],
            'IPv6' => ['2001:db8::1', ['X-Forwarded-For' => '2606:4700::1111'], '2001:db8::/32'],
            'trust all' => ['4.4.4.4', ['X-Forwarded-For' => '1.0.0.5'], '*'],
        ];
        $expected = $actual = [];
        foreach ($cases as $label => [$remoteAddr, $headers, $trusted]) {
            $client = $this->frameworkClientIp($remoteAddr, $headers, $trusted);
            # Control: the framework does take a forwarded address in each case
            $this->assertNotSame($remoteAddr, $client, "$label: the framework uses the header");

            $this->removeDir($this->dataDir());
            $this->ban((string) $client);
            $expected[$label] = 'FORBIDDEN';
            $actual[$label] = $this->runFilter($remoteAddr, $headers, ['SS_TRUSTED_PROXY_IPS' => $trusted]);
        }
        $this->assertSame($expected, $actual, 'the filter blocks the address the framework picks');
    }

    /**
     * The middleware passes the trusted proxy list, as TrustedProxyMiddleware has it from
     * SS_TRUSTED_PROXY_IPS, on to the filter in the config file.
     */
    public function testMiddlewareWritesTrustedProxiesForTheFilter(): void
    {
        $middleware = Injector::inst()->get(TrustedProxyMiddleware::class);
        $original = $middleware->getTrustedProxyIPs();
        $middleware->setTrustedProxyIPs('10.0.0.0/8');

        $configFile = sys_get_temp_dir() . '/waf_' . substr(md5(dirname(__DIR__)), 0, 8) . '/config.json';
        @unlink($configFile);   # it is only rewritten once an hour otherwise
        try {
            $method = new \ReflectionMethod(WafMiddleware::class, 'writeEarlyFilterConfig');
            $method->setAccessible(true);
            $method->invoke(WafMiddleware::create());
            $written = json_decode((string) @file_get_contents($configFile), true);
        } finally {
            $middleware->setTrustedProxyIPs($original);
            @unlink($configFile);
        }

        $this->assertSame('10.0.0.0/8', $written['trusted_proxy_ips'] ?? null);
    }
}
