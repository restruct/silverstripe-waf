<?php

namespace Restruct\SilverStripe\Waf\Tests;

use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use SilverStripe\Control\Middleware\TrustedProxyMiddleware;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;

/**
 * Where the early filter keeps its ban files, violation counters and config.json (waf#9).
 *
 * Up to 1.7.0 that was a 0755 dir with 0644 files at a predictable name in the shared system temp dir,
 * so on a host where several users or sites share it, anyone could read the files or plant their own:
 * switch early bans off, ban an address, or (since 1.7.0) trust every proxy and pick the banned address
 * through X-Forwarded-For. The filter and the middleware now only use a dir that is private to the
 * process user (0700, not a symlink, owned by us), with 0600 files written atomically; WAF_DATA_DIR
 * moves it elsewhere.
 *
 * Like EarlyFilterProxyTest, each filter run is its own PHP process with its own TMPDIR and an
 * explicit environment.
 */
class EarlyFilterDataDirTest extends SapphireTest
{
    protected $usesDatabase = false;

    private const PROXY = '10.0.0.1';
    private const CLIENT = '8.8.8.8';
    private const OTHER = '9.9.9.9';

    private string $tmpDir;
    private string $script;
    /** @var string|false WAF_DATA_DIR of this process before the test */
    private $originalDataDirEnv;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . '/waf-early-datadir-' . getmypid() . '-' . mt_rand();
        mkdir($this->tmpDir, 0755, true);
        $this->script = $this->tmpDir . '/run.php';
        file_put_contents($this->script, '<?php' . "\n"
            . '$_SERVER = array_merge($_SERVER, json_decode(getenv("WAF_TEST_SERVER"), true));' . "\n"
            . 'require ' . var_export($this->moduleRoot() . '/_waf_early_filter.php', true) . ';' . "\n"
            . 'echo "PASSED";' . "\n");
        $this->originalDataDirEnv = getenv('WAF_DATA_DIR');
    }

    protected function tearDown(): void
    {
        $this->originalDataDirEnv === false
            ? putenv('WAF_DATA_DIR')
            : putenv('WAF_DATA_DIR=' . $this->originalDataDirEnv);
        @chmod($this->tmpDir, 0755);
        $this->removeDir($this->tmpDir);
        parent::tearDown();
    }

    private function moduleRoot(): string
    {
        return dirname(__DIR__);
    }

    private function removeDir(string $dir): void
    {
        if (is_link($dir)) {
            @unlink($dir);
            return;
        }
        foreach (glob($dir . '/{,.}[!.,!..]*', GLOB_BRACE) ?: [] as $path) {
            is_dir($path) && !is_link($path) ? $this->removeDir($path) : @unlink($path);
        }
        @rmdir($dir);
    }

    /**
     * Run the filter once, as EarlyFilterProxyTest does. Returns 'FORBIDDEN' or 'PASSED'.
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
        stream_get_contents($pipes[2]);
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
     * Files the way someone else on the host leaves them for us: a world-writable dir with a ban on
     * $bannedIp and a config.json that trusts every proxy.
     */
    private function plantAttackerFiles(string $dir, string $bannedIp): void
    {
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        chmod($dir, 0777);
        file_put_contents($dir . '/ban_' . md5($bannedIp), (string) (time() + 3600));
        file_put_contents($dir . '/config.json', json_encode([
            'early_ban_enabled' => true, 'ban_threshold' => 10, 'ban_duration' => 3600,
            'trusted_proxy_ips' => '*',
        ]));
    }

    /**
     * Permissions of everything under $dir except the test's own run.php, as 'path' => '0700'.
     */
    private function permsUnder(string $dir): array
    {
        $result = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $path => $info) {
            if ($path === $this->script) {
                continue;
            }
            $result[substr($path, strlen($dir) + 1)] = sprintf('%04o', fileperms($path) & 0777);
        }
        ksort($result);
        return $result;
    }

    /**
     * What the filter creates is private to its user: the dir 0700, the files 0600. Nothing else on the
     * host can read the counters and bans, or the trusted proxy list in config.json.
     */
    public function testFilterKeepsItsFilesPrivate(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->assertSame('FORBIDDEN', $this->runFilter(self::CLIENT, [], [], '/wp-login.php'));
        }
        $this->assertSame('FORBIDDEN', $this->runFilter(self::CLIENT, []), 'control: the client is early-banned');

        $perms = $this->permsUnder($this->tmpDir);
        $this->assertNotEmpty($perms, 'the filter wrote its files under TMPDIR');
        $open = array_filter($perms, fn($mode) => (octdec($mode) & 0077) !== 0);
        $this->assertSame([], $open, 'no file or dir of the filter is open to group or others');
    }

    /**
     * The dir 1.7.0 and earlier used (waf_<hash> in the shared temp dir) is not read any more: a ban or
     * a trust-everyone config.json planted there by someone else has no effect.
     */
    public function testFilesPlantedAtTheOldSharedLocationAreIgnored(): void
    {
        $oldDir = $this->tmpDir . '/waf_' . substr(md5($this->moduleRoot()), 0, 8);
        $this->plantAttackerFiles($oldDir, self::OTHER);
        file_put_contents($oldDir . '/ban_' . md5(self::CLIENT), (string) (time() + 3600));

        $this->assertSame(
            ['banned by the planted file' => 'PASSED', 'spoofed via the planted trusted proxies' => 'PASSED'],
            [
                'banned by the planted file' => $this->runFilter(self::CLIENT, []),
                'spoofed via the planted trusted proxies' => $this->runFilter('1.1.1.1', ['X-Forwarded-For' => self::OTHER]),
            ]
        );
    }

    /**
     * A symlink at the data dir's path (someone else pointing it at a dir of theirs) is refused: its
     * files are not read, and the filter writes nothing through it.
     */
    public function testSymlinkAtTheDataDirIsRefused(): void
    {
        require_once $this->moduleRoot() . '/_waf_datadir.php';
        $attackerDir = $this->tmpDir . '/attacker';
        $this->plantAttackerFiles($attackerDir, self::CLIENT);
        # The default path as the filter's process sees it (TMPDIR is this test's dir)
        $dataDir = $this->tmpDir . '/' . basename(wafEarlyDataDirPath($this->moduleRoot()));
        symlink($attackerDir, $dataDir);
        $before = $this->permsUnder($attackerDir);

        $this->assertSame('PASSED', $this->runFilter(self::CLIENT, []), 'the planted ban is not read');
        $this->assertSame('FORBIDDEN', $this->runFilter(self::OTHER, [], [], '/wp-login.php'), 'control: probes still blocked');
        $this->assertSame($before, $this->permsUnder($attackerDir), 'nothing was written through the symlink');
        $this->assertTrue(is_link($dataDir), 'the symlink is left alone');
    }

    /**
     * A data dir that others can write to is refused, whoever made it: its contents may be anyone's.
     * One that is ours and only readable by others is tightened to 0700 and used.
     */
    public function testOpenDataDirIsRefusedAndReadableOneIsTightened(): void
    {
        $custom = $this->tmpDir . '/custom';
        $env = ['WAF_DATA_DIR' => $custom];

        $this->plantAttackerFiles($custom, self::CLIENT);
        $this->assertSame('PASSED', $this->runFilter(self::CLIENT, [], $env), 'a world-writable dir is not trusted');

        chmod($custom, 0755);
        $this->assertSame('FORBIDDEN', $this->runFilter(self::CLIENT, [], $env), 'our own 0755 dir is used');
        clearstatcache();
        $this->assertSame('0700', sprintf('%04o', fileperms($custom) & 0777), 'and tightened to 0700');
    }

    /**
     * WAF_DATA_DIR (a real environment variable: the filter runs before .env is loaded) moves the data
     * dir, for the filter and the middleware alike: the filter finds the config the middleware wrote.
     */
    public function testWafDataDirIsSharedByMiddlewareAndFilter(): void
    {
        $custom = $this->tmpDir . '/project-private/waf';
        putenv('WAF_DATA_DIR=' . $custom);
        $this->invokeWriteEarlyFilterConfig('10.0.0.0/8');

        $this->assertFileExists($custom . '/config.json', 'the middleware wrote to WAF_DATA_DIR');
        clearstatcache();
        $this->assertSame(
            ['dir' => '0700', 'config.json' => '0600'],
            [
                'dir' => sprintf('%04o', fileperms($custom) & 0777),
                'config.json' => sprintf('%04o', fileperms($custom . '/config.json') & 0777),
            ]
        );

        file_put_contents($custom . '/ban_' . md5(self::CLIENT), (string) (time() + 3600));
        $this->assertSame(
            'FORBIDDEN',
            $this->runFilter(self::PROXY, ['X-Forwarded-For' => self::CLIENT], ['WAF_DATA_DIR' => $custom]),
            'the filter used the trusted proxies from the config the middleware wrote there'
        );
    }

    /**
     * Without WAF_DATA_DIR both layers compute the same default dir, so the filter reads what the
     * middleware wrote.
     */
    public function testMiddlewareWritesWhereTheFilterReadsByDefault(): void
    {
        putenv('WAF_DATA_DIR');
        require_once $this->moduleRoot() . '/_waf_datadir.php';
        $dataDir = wafEarlyDataDirPath($this->moduleRoot());
        $configFile = $dataDir . '/config.json';
        @unlink($configFile);
        try {
            $this->invokeWriteEarlyFilterConfig('10.0.0.0/8');
            $written = json_decode((string) @file_get_contents($configFile), true);
            clearstatcache();
            $mode = sprintf('%04o', @fileperms($configFile) & 0777);
        } finally {
            @unlink($configFile);
        }
        $this->assertSame(['trusted' => '10.0.0.0/8', 'mode' => '0600'], [
            'trusted' => $written['trusted_proxy_ips'] ?? null,
            'mode' => $mode,
        ]);
    }

    /**
     * The middleware removes the dir 1.7.0 and earlier left in the shared temp dir, when it is ours:
     * its config.json listed the trusted proxies for anyone to read.
     */
    public function testMiddlewareRemovesTheOldSharedDir(): void
    {
        $oldDir = sys_get_temp_dir() . '/waf_' . substr(md5($this->moduleRoot()), 0, 8);
        if (!is_dir($oldDir)) {
            mkdir($oldDir, 0755);
        }
        file_put_contents($oldDir . '/config.json', '{}');
        file_put_contents($oldDir . '/ban_' . md5(self::CLIENT), (string) (time() + 3600));

        putenv('WAF_DATA_DIR=' . $this->tmpDir . '/new');
        $this->invokeWriteEarlyFilterConfig('');

        clearstatcache();
        $this->assertDirectoryDoesNotExist($oldDir);
    }

    private function invokeWriteEarlyFilterConfig(string $trustedProxies): void
    {
        $proxyMiddleware = Injector::inst()->get(TrustedProxyMiddleware::class);
        $original = $proxyMiddleware->getTrustedProxyIPs();
        $proxyMiddleware->setTrustedProxyIPs($trustedProxies);
        try {
            $method = new \ReflectionMethod(WafMiddleware::class, 'writeEarlyFilterConfig');
            $method->setAccessible(true);
            $method->invoke(WafMiddleware::create());
        } finally {
            $proxyMiddleware->setTrustedProxyIPs($original);
        }
    }
}
