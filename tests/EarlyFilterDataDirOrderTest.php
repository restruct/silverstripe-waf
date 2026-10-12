<?php

namespace Restruct\SilverStripe\Waf\Tests;

use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use SilverStripe\Control\Middleware\TrustedProxyMiddleware;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;

/**
 * Where the early filter's data dir goes since 1.9.0: in the order the framework picks its own temp
 * folder (constants.php, TempFolder::getTempParentFolder()), from what the early filter can see:
 *   1. WAF_DATA_DIR (real env), as in 1.8.0;
 *   2. SS_TEMP_PATH (real env: $_ENV, $_SERVER or getenv(), never .env); relative = under the project root;
 *   3. <project>/silverstripe-cache when it exists and is a safe parent (the framework makes it 0777, which
 *      is not; 1777 is);
 *   4. the system temp dir, as in 1.8.0.
 * The private-dir checks of 1.8.0 (EarlyFilterDataDirTest) apply on every branch.
 *
 * The project root comes from the module's own path (<root>/vendor/<vendor>/<package>), so each test
 * installs a copy of the filter files into a scratch project's vendor dir and runs the filter from there,
 * in its own PHP process with an explicit environment (nothing inherited from the test runner) and its
 * own TMPDIR.
 */
class EarlyFilterDataDirOrderTest extends SapphireTest
{
    protected $usesDatabase = false;

    private const PROXY = '10.0.0.1';
    private const CLIENT = '8.8.8.8';

    private string $tmpDir;
    private string $project;
    private string $moduleCopy;
    private string $sysTemp;
    /** @var array Saved SS_TEMP_PATH / WAF_DATA_DIR of this process: [getenv, $_ENV, $_SERVER] per name */
    private array $savedEnv = [];

    protected function setUp(): void
    {
        parent::setUp();
        $tmp = sys_get_temp_dir() . '/waf-datadir-order-' . getmypid() . '-' . mt_rand();
        mkdir($tmp, 0755, true);
        # A realpath, like the filter's __DIR__ (on macOS the temp dir sits behind the /var symlink), so
        # paths built here match the ones the filter builds
        $this->tmpDir = realpath($tmp);
        $this->project = $this->tmpDir . '/project';
        $this->moduleCopy = $this->installModuleCopy($this->project . '/vendor/restruct/silverstripe-waf');
        $this->sysTemp = $this->tmpDir . '/systemp';
        mkdir($this->sysTemp, 0755);

        # This process must not bring its own values to the middleware tests
        foreach (['SS_TEMP_PATH', 'WAF_DATA_DIR'] as $name) {
            $this->savedEnv[$name] = [getenv($name), $_ENV[$name] ?? null, $_SERVER[$name] ?? null];
            putenv($name);
            unset($_ENV[$name], $_SERVER[$name]);
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->savedEnv as $name => [$env, $envArray, $server]) {
            $env === false ? putenv($name) : putenv($name . '=' . $env);
            if ($envArray !== null) {
                $_ENV[$name] = $envArray;
            }
            if ($server !== null) {
                $_SERVER[$name] = $server;
            }
        }
        $this->chmodTree($this->tmpDir);
        $this->removeDir($this->tmpDir);
        parent::tearDown();
    }

    private function moduleRoot(): string
    {
        return dirname(__DIR__);
    }

    /**
     * Copy the early filter's files to $dir, as a Composer install (not a symlink) would have them.
     */
    private function installModuleCopy(string $dir): string
    {
        mkdir($dir, 0755, true);
        foreach (['_waf_early_filter.php', '_waf_datadir.php', '_waf_matching.php'] as $file) {
            copy($this->moduleRoot() . '/' . $file, $dir . '/' . $file);
        }
        return $dir;
    }

    private function chmodTree(string $dir): void
    {
        if (!is_dir($dir) || is_link($dir)) {
            return;
        }
        @chmod($dir, 0755);
        foreach (glob($dir . '/{,.}[!.,!..]*', GLOB_BRACE) ?: [] as $path) {
            $this->chmodTree($path);
        }
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
     * The data dir's own name (waf-<uid>-<hash>) for a module at $moduleDir.
     */
    private function dataDirName(string $moduleDir): string
    {
        require_once $this->moduleRoot() . '/_waf_datadir.php';
        return wafEarlyDataDirName($moduleDir);
    }

    /**
     * Run the filter at $moduleDir once in its own process. $env is the whole environment apart from
     * TMPDIR (the test's own system temp dir); $server is merged into $_SERVER before the filter runs, the
     * way a web server's fastcgi_param arrives. Returns 'FORBIDDEN' or 'PASSED'.
     */
    private function runFilter(string $moduleDir, string $remoteAddr, string $path, array $env, array $server = []): string
    {
        $script = $this->tmpDir . '/run.php';
        file_put_contents($script, '<?php' . "\n"
            . '$_SERVER = array_merge($_SERVER, json_decode(getenv("WAF_TEST_SERVER"), true));' . "\n"
            . 'require ' . var_export($moduleDir . '/_waf_early_filter.php', true) . ';' . "\n"
            . 'echo "PASSED";' . "\n");
        $server = ['REMOTE_ADDR' => $remoteAddr, 'REQUEST_URI' => $path, 'HTTP_USER_AGENT' => 'Mozilla/5.0'] + $server;
        $process = proc_open(
            [PHP_BINARY, '-n', $script],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            ['TMPDIR' => $this->sysTemp, 'WAF_TEST_SERVER' => json_encode($server)] + $env
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
     * Probe ten times from CLIENT (the default threshold), then make one clean request: 'FORBIDDEN' when the
     * filter had a data dir to count and ban in.
     */
    private function banClient(array $env, array $server = [], ?string $moduleDir = null): string
    {
        $moduleDir ??= $this->moduleCopy;
        for ($i = 0; $i < 10; $i++) {
            $this->runFilter($moduleDir, self::CLIENT, '/wp-login.php', $env, $server);
        }
        return $this->runFilter($moduleDir, self::CLIENT, '/', $env, $server);
    }

    /**
     * Where a data dir of the filter (a waf-* dir) exists under the candidate parents, as
     * 'parent label' => 'mode of the dir', for the parents that have one.
     */
    private function dataDirsIn(array $parents): array
    {
        clearstatcache();
        $found = [];
        foreach ($parents as $label => $parent) {
            foreach (glob($parent . '/waf-*', GLOB_ONLYDIR) ?: [] as $dir) {
                $found[$label] = sprintf('%04o', fileperms($dir) & 0777);
            }
        }
        return $found;
    }

    /**
     * The candidate parents of a test: the system temp dir, the project's silverstripe-cache, and any
     * extra ones.
     */
    private function parents(array $extra = []): array
    {
        return ['system temp' => $this->sysTemp, 'silverstripe-cache' => $this->project . '/silverstripe-cache'] + $extra;
    }

    /**
     * Control: with none of the steps before it in play, the data dir is in the system temp dir, as in
     * 1.8.0. Every test below differs from this one in one input only.
     */
    public function testWithoutSsTempPathOrSilverstripeCacheTheSystemTempDirIsUsed(): void
    {
        $this->assertSame('FORBIDDEN', $this->banClient([]));
        $this->assertSame(['system temp' => '0700'], $this->dataDirsIn($this->parents()));
    }

    /**
     * Step 2: an absolute SS_TEMP_PATH from the real environment is the parent, as it is the framework's
     * TEMP_PATH. Nothing is written in the system temp dir.
     */
    public function testAbsoluteSsTempPathIsUsed(): void
    {
        $tempPath = $this->tmpDir . '/ss-temp';
        mkdir($tempPath, 0755);

        $this->assertSame('FORBIDDEN', $this->banClient(['SS_TEMP_PATH' => $tempPath]));
        $this->assertSame(['SS_TEMP_PATH' => '0700'], $this->dataDirsIn($this->parents(['SS_TEMP_PATH' => $tempPath])));
        $this->assertDirectoryExists($tempPath . '/' . $this->dataDirName($this->moduleCopy));
    }

    /**
     * Step 2: a relative SS_TEMP_PATH is under the project root, as the framework resolves it (against
     * BASE_PATH, not the cwd of public/index.php).
     */
    public function testRelativeSsTempPathIsUnderTheProjectRoot(): void
    {
        mkdir($this->project . '/var-cache', 0755);

        $this->assertSame('FORBIDDEN', $this->banClient(['SS_TEMP_PATH' => 'var-cache']));
        $this->assertSame(
            ['project/var-cache' => '0700'],
            $this->dataDirsIn($this->parents(['project/var-cache' => $this->project . '/var-cache']))
        );
    }

    /**
     * Step 2 reads SS_TEMP_PATH where the framework does, short of .env: a value that only reaches
     * $_SERVER (a web server's fastcgi_param, not in getenv()) counts too.
     */
    public function testSsTempPathFromServerVariablesIsUsed(): void
    {
        $tempPath = $this->tmpDir . '/ss-temp';
        mkdir($tempPath, 0755);

        $this->assertSame('FORBIDDEN', $this->banClient([], ['SS_TEMP_PATH' => $tempPath]));
        $this->assertSame(['SS_TEMP_PATH' => '0700'], $this->dataDirsIn($this->parents(['SS_TEMP_PATH' => $tempPath])));
    }

    /**
     * Step 1 before step 2: WAF_DATA_DIR wins over SS_TEMP_PATH.
     */
    public function testWafDataDirWinsOverSsTempPath(): void
    {
        $tempPath = $this->tmpDir . '/ss-temp';
        $wafDataDir = $this->tmpDir . '/waf-data';
        mkdir($tempPath, 0755);
        mkdir($wafDataDir, 0755);

        $this->assertSame('FORBIDDEN', $this->banClient(['SS_TEMP_PATH' => $tempPath, 'WAF_DATA_DIR' => $wafDataDir]));
        $this->assertSame(
            ['WAF_DATA_DIR' => '0700'],
            $this->dataDirsIn($this->parents(['SS_TEMP_PATH' => $tempPath, 'WAF_DATA_DIR' => $wafDataDir]))
        );
    }

    /**
     * Step 3: the project's silverstripe-cache, the framework's first choice, is used when it is a safe
     * parent. 1777 is what the framework leaves alone (its test is mode & 0777) and sticky is safe: nobody
     * can rename our dir in it. The dir is private (0700) like everywhere else.
     */
    public function testStickySilverstripeCacheIsUsed(): void
    {
        mkdir($this->project . '/silverstripe-cache', 01777);
        chmod($this->project . '/silverstripe-cache', 01777);

        $this->assertSame('FORBIDDEN', $this->banClient([]));
        $this->assertSame(['silverstripe-cache' => '0700'], $this->dataDirsIn($this->parents()));
    }

    /**
     * Step 3 is passed over when silverstripe-cache is writable by others and not sticky, which is how the
     * framework leaves it (it chmods it to 0777 on boot): anyone could swap our dir in it right after the
     * checks. The filter goes on to the system temp dir instead of switching the early ban off, and a ban
     * planted in silverstripe-cache is not read.
     */
    public function testSilverstripeCacheOthersCanWriteToIsPassedOver(): void
    {
        $cacheDir = $this->project . '/silverstripe-cache';
        mkdir($cacheDir, 0777);
        chmod($cacheDir, 0777);
        $planted = $cacheDir . '/' . $this->dataDirName($this->moduleCopy);
        mkdir($planted, 0700);
        file_put_contents($planted . '/ban_' . md5(self::PROXY), (string) (time() + 3600));

        $this->assertSame(
            ['planted ban in silverstripe-cache' => 'PASSED', 'early ban still works' => 'FORBIDDEN'],
            [
                'planted ban in silverstripe-cache' => $this->runFilter($this->moduleCopy, self::PROXY, '/', []),
                'early ban still works' => $this->banClient([]),
            ]
        );
        $this->assertSame('0700', $this->dataDirsIn(['system temp' => $this->sysTemp])['system temp'] ?? null);
        $this->assertSame(['ban_' . md5(self::PROXY)], array_values(array_diff(scandir($planted), ['.', '..'])), 'nothing written in silverstripe-cache');
    }

    /**
     * Step 2 before step 3: SS_TEMP_PATH wins over a (usable) silverstripe-cache, as in the framework.
     */
    public function testSsTempPathWinsOverSilverstripeCache(): void
    {
        mkdir($this->project . '/silverstripe-cache', 01777);
        chmod($this->project . '/silverstripe-cache', 01777);
        $tempPath = $this->tmpDir . '/ss-temp';
        mkdir($tempPath, 0755);

        $this->assertSame('FORBIDDEN', $this->banClient(['SS_TEMP_PATH' => $tempPath]));
        $this->assertSame(['SS_TEMP_PATH' => '0700'], $this->dataDirsIn($this->parents(['SS_TEMP_PATH' => $tempPath])));
    }

    /**
     * The private-dir checks hold on the new branches too: an SS_TEMP_PATH others can write to (and not
     * sticky) is refused like such a WAF_DATA_DIR, so no early ban there rather than files anyone could
     * have planted.
     */
    public function testSsTempPathOthersCanWriteToIsRefused(): void
    {
        $tempPath = $this->tmpDir . '/ss-temp';
        mkdir($tempPath, 0777);
        chmod($tempPath, 0777);
        $planted = $tempPath . '/' . $this->dataDirName($this->moduleCopy);
        mkdir($planted, 0700);
        file_put_contents($planted . '/ban_' . md5(self::PROXY), (string) (time() + 3600));

        $this->assertSame('PASSED', $this->runFilter($this->moduleCopy, self::PROXY, '/', ['SS_TEMP_PATH' => $tempPath]), 'the planted ban is not read');
        $this->assertSame('PASSED', $this->banClient(['SS_TEMP_PATH' => $tempPath]), 'refused: no early ban');
        $this->assertSame([], $this->dataDirsIn(['system temp' => $this->sysTemp]), 'and no fall-back to the system temp dir');

        # Control: the same dir made sticky is used
        chmod($tempPath, 01777);
        $this->assertSame('FORBIDDEN', $this->runFilter($this->moduleCopy, self::PROXY, '/', ['SS_TEMP_PATH' => $tempPath]));
    }

    /**
     * A module that is not under a vendor dir (a path repository symlinked in for development) has no
     * project root to go on: a relative SS_TEMP_PATH and silverstripe-cache are skipped, the system temp dir
     * is used. Nothing is guessed from the cwd, which differs between the filter and the middleware.
     */
    public function testModuleOutsideAVendorDirSkipsTheProjectSteps(): void
    {
        $elsewhere = $this->installModuleCopy($this->tmpDir . '/elsewhere/silverstripe-waf');
        mkdir($this->tmpDir . '/elsewhere/var-cache', 0755);
        mkdir($this->tmpDir . '/elsewhere/silverstripe-cache', 01777);
        chmod($this->tmpDir . '/elsewhere/silverstripe-cache', 01777);

        $this->assertSame('FORBIDDEN', $this->banClient(['SS_TEMP_PATH' => 'var-cache'], [], $elsewhere));
        $this->assertSame(
            ['system temp' => '0700'],
            $this->dataDirsIn([
                'system temp' => $this->sysTemp,
                'var-cache' => $this->tmpDir . '/elsewhere/var-cache',
                'silverstripe-cache' => $this->tmpDir . '/elsewhere/silverstripe-cache',
            ])
        );
    }

    /**
     * The middleware resolves the same dir as the filter on the new branches: with SS_TEMP_PATH in the real
     * environment it writes config.json there, and the filter (given the same environment) reads the
     * trusted proxies from it and bans the client behind the proxy.
     */
    public function testMiddlewareAndFilterShareTheSsTempPathDir(): void
    {
        $tempPath = $this->tmpDir . '/ss-temp';
        mkdir($tempPath, 0755);
        putenv('SS_TEMP_PATH=' . $tempPath);
        $dataDir = $tempPath . '/' . $this->dataDirName($this->moduleRoot());

        $this->invokeWriteEarlyFilterConfig('10.0.0.0/8');
        $this->assertFileExists($dataDir . '/config.json', 'the middleware wrote to SS_TEMP_PATH');

        file_put_contents($dataDir . '/ban_' . md5(self::CLIENT), (string) (time() + 3600));
        chmod($dataDir . '/ban_' . md5(self::CLIENT), 0600);
        $server = ['HTTP_X_FORWARDED_FOR' => self::CLIENT];
        $this->assertSame(
            ['client behind the trusted proxy' => 'FORBIDDEN'],
            ['client behind the trusted proxy' => $this->runFilter($this->moduleRoot(), self::PROXY, '/', ['SS_TEMP_PATH' => $tempPath], $server)],
            'the filter used the trusted proxies from the config the middleware wrote there'
        );
    }

    /**
     * SS_TEMP_PATH only in .env moves the framework's caches but not the WAF's data dir (the filter cannot
     * see it): the middleware stays with the filter and logs a warning saying so. The same value in the
     * real environment as well is followed and not warned about.
     */
    public function testSsTempPathOnlyInDotEnvIsWarnedAbout(): void
    {
        $tempPath = $this->tmpDir . '/ss-temp';
        mkdir($tempPath, 0755);
        # The default dir is this process's real one (system temp): its config.json must be stale or absent,
        # or the middleware returns before it gets to the warnings (it writes at most hourly)
        require_once $this->moduleRoot() . '/_waf_datadir.php';
        $defaultConfig = sys_get_temp_dir() . '/' . $this->dataDirName($this->moduleRoot()) . '/config.json';

        $envBackup = Environment::getVariables();
        $warnings = [];
        $logger = $this->createMock(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(function ($message) use (&$warnings) {
            $warnings[] = (string) $message;
        });
        Injector::inst()->registerService($logger, LoggerInterface::class);
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        try {
            Environment::setEnv('SS_TEMP_PATH', $tempPath);
            @unlink($defaultConfig);
            $this->invokeWriteEarlyFilterConfig('');
            $onlyInDotEnv = [
                'warned' => count(array_filter($warnings, fn($w) => str_contains($w, 'SS_TEMP_PATH is set in .env'))),
                'written to SS_TEMP_PATH' => is_dir($tempPath . '/' . $this->dataDirName($this->moduleRoot())),
                'written to the default dir' => file_exists($defaultConfig),
            ];

            # Control: the same value in the real environment too
            $warnings = [];
            putenv('SS_TEMP_PATH=' . $tempPath);
            $this->invokeWriteEarlyFilterConfig('');
            $inRealEnv = [
                'warned' => count(array_filter($warnings, fn($w) => str_contains($w, 'SS_TEMP_PATH is set in .env'))),
                'written to SS_TEMP_PATH' => is_dir($tempPath . '/' . $this->dataDirName($this->moduleRoot())),
            ];
        } finally {
            Environment::setVariables($envBackup);
            @unlink($defaultConfig);
        }

        $this->assertSame(
            [
                'only in .env' => ['warned' => 1, 'written to SS_TEMP_PATH' => false, 'written to the default dir' => true],
                'control: in the real env' => ['warned' => 0, 'written to SS_TEMP_PATH' => true],
            ],
            ['only in .env' => $onlyInDotEnv, 'control: in the real env' => $inRealEnv]
        );
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
