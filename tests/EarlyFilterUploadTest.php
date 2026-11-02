<?php

namespace Restruct\SilverStripe\Waf\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use SilverStripe\Admin\AdminRootController;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;

/**
 * The early filter's upload checks (waf#15): webshell drop attempts through any endpoint that accepts
 * files, and bursts of multipart POSTs from one address. Both are opt-in.
 *
 * The matcher (_waf_upload.php) is pure functions and is tested directly. The filter itself exits on a
 * block, so, as in EarlyFilterProxyTest, each request runs it in its own PHP process with its own TMPDIR
 * and an explicit environment; $_FILES is filled the way PHP fills it, pointing at fixture files.
 */
class EarlyFilterUploadTest extends SapphireTest
{
    protected $usesDatabase = false;

    private const CLIENT = '8.8.8.8';
    private const UA = 'ProbeBot/1.0';

    private string $tmpDir;
    private string $script;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        require_once dirname(__DIR__) . '/_waf_upload.php';
        require_once dirname(__DIR__) . '/_waf_datadir.php';
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . '/waf-early-upload-' . getmypid() . '-' . mt_rand();
        mkdir($this->tmpDir, 0755, true);
        # A request handler in miniature: fill $_SERVER and $_FILES, run the filter, report if it let the
        # request on
        $this->script = $this->tmpDir . '/run.php';
        file_put_contents($this->script, '<?php' . "\n"
            . '$_SERVER = array_merge($_SERVER, json_decode(getenv("WAF_TEST_SERVER"), true));' . "\n"
            . '$_FILES = json_decode(getenv("WAF_TEST_FILES"), true);' . "\n"
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
     * The filter's data dir under this test's TMPDIR (see EarlyFilterProxyTest::dataDir()).
     */
    private function dataDir(): string
    {
        $dir = $this->tmpDir . '/' . wafEarlyDataDirName(dirname(__DIR__));
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        return $dir;
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

    // ========================================================================
    // Fixtures
    // ========================================================================

    /**
     * A real JPEG of noise (deterministic): compressed, high-entropy bytes, the kind a byte-pattern check
     * misfires on. GD is in the CI image; a fixed JFIF header with filler stands in without it.
     */
    private static function jpegBytes(): string
    {
        if (!function_exists('imagejpeg')) {
            return "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
                . str_repeat("\x13\x37\xC0\xDE", 1024) . "\xFF\xD9";
        }
        mt_srand(15);
        $image = imagecreatetruecolor(96, 96);
        for ($x = 0; $x < 96; $x++) {
            for ($y = 0; $y < 96; $y++) {
                imagesetpixel($image, $x, $y, mt_rand(0, 0xFFFFFF));
            }
        }
        mt_srand();
        ob_start();
        imagejpeg($image, null, 90);
        return (string) ob_get_clean();
    }

    private static function pdfBytes(): string
    {
        return "%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            . "2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
            . "xref\n0 3\ntrailer << /Root 1 0 R >>\n%%EOF\n";
    }

    /**
     * An SVG with a script in it passes: the check looks for PHP only, and SVG sanitising belongs to
     * the svg-images module (waf#15).
     */
    private static function svgBytes(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
            . '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
            . '<script>alert(1)</script><rect width="10" height="10"/></svg>';
    }

    /**
     * A GIF/JPEG polyglot as droppers send it: image magic bytes, then PHP.
     */
    private static function phpInImageBytes(): string
    {
        return "GIF89a\x01\x00\x01\x00<?php system(\$_GET['c']); ?>";
    }

    private function fixture(string $name, string $bytes): string
    {
        $path = $this->tmpDir . '/php' . substr(md5($name . $bytes), 0, 8);
        file_put_contents($path, $bytes);
        return $path;
    }

    /**
     * $_FILES as PHP fills it for one plain file field.
     */
    private function filesFor(string $clientName, string $bytes): array
    {
        $tmp = $this->fixture($clientName, $bytes);
        return ['upload' => [
            'name' => $clientName, 'full_path' => $clientName, 'type' => 'application/octet-stream',
            'tmp_name' => $tmp, 'error' => 0, 'size' => strlen($bytes),
        ]];
    }

    /**
     * Run the filter once. Returns ['result' => 'FORBIDDEN'|'PASSED', 'log' => the filter's error_log()].
     */
    private function runFilter(
        array $files,
        array $env = [],
        string $method = 'POST',
        string $contentType = 'multipart/form-data; boundary=----waf15',
        string $path = '/Security/login/default/LoginForm'
    ): array {
        $server = [
            'REMOTE_ADDR' => self::CLIENT, 'REQUEST_URI' => $path,
            'HTTP_USER_AGENT' => self::UA, 'REQUEST_METHOD' => $method, 'CONTENT_TYPE' => $contentType,
        ];
        $env = [
            'TMPDIR' => $this->tmpDir,
            'WAF_TEST_SERVER' => json_encode($server),
            'WAF_TEST_FILES' => json_encode($files),
        ] + $env;

        $process = proc_open(
            [PHP_BINARY, '-n', $this->script],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            $env
        );
        $out = stream_get_contents($pipes[1]);
        $log = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        $result = match (trim((string) $out)) {
            'Forbidden' => 'FORBIDDEN',
            'PASSED' => 'PASSED',
            default => 'UNEXPECTED: ' . $out . $log,
        };
        return ['result' => $result, 'log' => $log];
    }

    private function hasViolation(): bool
    {
        return file_exists($this->dataDir() . '/viol_' . md5(self::CLIENT));
    }

    // ========================================================================
    // Filename check (pure)
    // ========================================================================

    public static function probeNameProvider(): array
    {
        return array_map(fn($n) => [$n], [
            'shell.php', 'SHELL.PHP', 'x.php.jpg', 'x.PhP5.png', 'x.phtml', 'x.phar', 'x.pht', 'x.phps',
            'x.php3', 'x.php4', 'x.php6', 'x.php7', 'x.php8', 'archive.phar.zip',
            'x.php.', 'x.php ', "x.php\0.jpg", '.php',
            '.htaccess', '.HTACCESS', '.user.ini', 'sub/dir/.htaccess', 'C:\\upload\\shell.php',
        ]);
    }

    /** @dataProvider probeNameProvider */
    #[DataProvider('probeNameProvider')]
    public function testExecutableAndServerConfigNamesAreCaught(string $name): void
    {
        $this->assertNotNull(wafUploadNameProbe($name), "should be caught: $name");
    }

    public static function cleanNameProvider(): array
    {
        return array_map(fn($n) => [$n], [
            'photo.jpg', 'IMG_0001.JPEG', 'report.pdf', 'logo.svg', 'cv.docx', 'archive.tar.gz',
            # "php" as the name, or inside a longer part, is not an extension
            'php.jpg', 'phpinfo-guide.pdf', 'my.phpstorm.settings.zip', 'x.phpx', 'x.php9.txt',
            'htaccess.txt', 'user.ini.txt', 'my.htaccess.bak', 'php.ini.txt',
        ]);
    }

    /** @dataProvider cleanNameProvider */
    #[DataProvider('cleanNameProvider')]
    public function testOrdinaryNamesPass(string $name): void
    {
        $this->assertNull(wafUploadNameProbe($name), "must not be caught: $name");
    }

    // ========================================================================
    // Content check (pure, plus the file read)
    // ========================================================================

    public static function phpContentProvider(): array
    {
        return [
            'php open tag' => ['<?php echo 1;', '<?php'],
            'upper case' => ['<?PHP system($_GET[0]);', '<?php'],
            'after image magic bytes' => [self::phpInImageBytes(), '<?php'],
            'short echo, function' => ['<?=system($_GET[0]);?>', '<?='],
            'short echo, spaced variable' => ['<?= $x ?>', '<?='],
            'short echo, backtick' => ['<?=`$_GET[0]`?>', '<?='],
            'script language' => ['<script language="php">eval($_POST[1]);</script>', '<script language=php'],
            'script language, upper, unquoted' => ['<SCRIPT LANGUAGE=php>x</SCRIPT>', '<script language=php'],
        ];
    }

    /** @dataProvider phpContentProvider */
    #[DataProvider('phpContentProvider')]
    public function testPhpInContentIsCaught(string $data, string $expected): void
    {
        $this->assertSame($expected, wafUploadContentMarker($data));
    }

    public function testContentWithoutPhpPasses(): void
    {
        $this->assertSame(
            ['jpeg' => null, 'pdf' => null, 'svg' => null, 'xmp' => null, 'short tag then binary' => null, 'text' => null],
            [
                'jpeg' => wafUploadContentMarker(self::jpegBytes()),
                'pdf' => wafUploadContentMarker(self::pdfBytes()),
                'svg' => wafUploadContentMarker(self::svgBytes()),
                'xmp' => wafUploadContentMarker("\xFF\xD8<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>"),
                # '<?=' by chance in compressed data: what follows is not code
                'short tag then binary' => wafUploadContentMarker("\x89PNG\r\n\x1a\n\x00<?=\x00\xff\x13\x88"),
                'text' => wafUploadContentMarker("Notes about <? and ?= in a text file\n"),
            ]
        );
    }

    /**
     * Only the first 4 KB are read: PHP further in is not looked for (droppers put it at the start, and
     * reading whole files would slow every upload down).
     */
    public function testOnlyTheStartOfTheFileIsRead(): void
    {
        $early = $this->fixture('early', str_repeat('A', 4000) . '<?php x();');
        $late = $this->fixture('late', str_repeat('A', 4096) . '<?php x();');

        $this->assertSame(
            ['early' => '<?php', 'late' => null, 'missing file' => null, 'no file' => null],
            [
                'early' => wafUploadContentProbe($early),
                'late' => wafUploadContentProbe($late),
                'missing file' => wafUploadContentProbe($this->tmpDir . '/does-not-exist'),
                'no file' => wafUploadContentProbe(''),
            ]
        );
    }

    // ========================================================================
    // $_FILES shapes (pure)
    // ========================================================================

    public function testNestedFileFieldsAreWalked(): void
    {
        $clean = $this->fixture('clean', self::jpegBytes());
        $php = $this->fixture('php', self::phpInImageBytes());
        $files = [
            'plain' => ['name' => 'a.jpg', 'tmp_name' => $clean, 'error' => 0, 'size' => 1, 'type' => 'image/jpeg'],
            # name="files[]"
            'files' => [
                'name' => ['b.jpg', 'c.jpg'], 'tmp_name' => [$clean, $clean],
                'error' => [0, 0], 'size' => [1, 1], 'type' => ['image/jpeg', 'image/jpeg'],
            ],
            # name="form[gallery][0][image]", and a failed upload (no tmp file) next to it
            'form' => [
                'name' => ['gallery' => [['image' => 'd.jpg'], ['image' => 'e.jpg']]],
                'tmp_name' => ['gallery' => [['image' => $php], ['image' => '']]],
                'error' => ['gallery' => [['image' => 0], ['image' => 4]]],
            ],
            # what PHP sends for an empty file input
            'empty' => ['name' => '', 'tmp_name' => '', 'error' => 4, 'size' => 0, 'type' => ''],
        ];

        $this->assertSame(
            [
                ['name' => 'a.jpg', 'tmp_name' => $clean],
                ['name' => 'b.jpg', 'tmp_name' => $clean],
                ['name' => 'c.jpg', 'tmp_name' => $clean],
                ['name' => 'd.jpg', 'tmp_name' => $php],
                ['name' => 'e.jpg', 'tmp_name' => ''],
            ],
            wafUploadedFiles($files)
        );
        $this->assertSame(['file' => 'd.jpg', 'pattern' => 'content:<?php'], wafMatchUploadProbe($files));

        $files['files']['name'][1] = 'c.php.jpg';
        $this->assertSame(
            ['file' => 'c.php.jpg', 'pattern' => 'ext:php'],
            wafMatchUploadProbe($files),
            'a bad name is reported before any file is opened'
        );
    }

    // ========================================================================
    // The filter: upload probe
    // ========================================================================

    public function testProbeUploadsAreBlockedAndCountAsViolations(): void
    {
        $this->writeFilterConfig(['upload_probe_enabled' => true]);

        $byName = $this->runFilter($this->filesFor('x.php.jpg', self::jpegBytes()));
        $this->assertSame('FORBIDDEN', $byName['result'], 'double extension');
        $this->assertTrue($this->hasViolation(), 'the block counts towards ban_threshold');

        $byContent = $this->runFilter($this->filesFor('photo.jpg', self::phpInImageBytes()));
        $this->assertSame('FORBIDDEN', $byContent['result'], 'PHP in a .jpg');
        $this->assertSame(
            '2:',
            substr((string) file_get_contents($this->dataDir() . '/viol_' . md5(self::CLIENT)), 0, 2),
            'both blocks counted'
        );
    }

    /**
     * The log line names IP, user agent and filename, and never carries the file's content.
     */
    public function testProbeIsLoggedWithoutTheFileContent(): void
    {
        $this->writeFilterConfig(['upload_probe_enabled' => true]);
        $log = $this->runFilter($this->filesFor('photo.jpg', self::phpInImageBytes()))['log'];

        $this->assertStringContainsString('[WAF] BLOCKED reason=upload_probe', $log);
        $this->assertStringContainsString('pattern="content:<?php file=photo.jpg"', $log);
        $this->assertStringContainsString('ip=' . self::CLIENT, $log);
        $this->assertStringContainsString('ua="' . self::UA . '"', $log);
        $this->assertStringNotContainsString('system(', $log, 'file content stays out of the log');
    }

    public function testCleanUploadsPass(): void
    {
        $this->writeFilterConfig(['upload_probe_enabled' => true]);

        $this->assertSame(
            ['jpeg' => 'PASSED', 'pdf' => 'PASSED', 'svg' => 'PASSED'],
            [
                'jpeg' => $this->runFilter($this->filesFor('photo.jpg', self::jpegBytes()))['result'],
                'pdf' => $this->runFilter($this->filesFor('report.pdf', self::pdfBytes()))['result'],
                'svg' => $this->runFilter($this->filesFor('logo.svg', self::svgBytes()))['result'],
            ]
        );
        $this->assertFalse($this->hasViolation());
    }

    /**
     * Only multipart/form-data POSTs are looked at. $_FILES is only ever filled for those, so this fills
     * it by hand to prove the gate is the method and content type, not the presence of files.
     */
    public function testRequestsThatAreNotMultipartPostsAreUntouched(): void
    {
        $this->writeFilterConfig(['upload_probe_enabled' => true]);
        $files = $this->filesFor('shell.php', self::phpInImageBytes());

        $this->assertSame(
            ['urlencoded POST' => 'PASSED', 'JSON POST' => 'PASSED', 'multipart PUT' => 'PASSED', 'multipart POST' => 'FORBIDDEN'],
            [
                'urlencoded POST' => $this->runFilter($files, [], 'POST', 'application/x-www-form-urlencoded')['result'],
                'JSON POST' => $this->runFilter($files, [], 'POST', 'application/json')['result'],
                'multipart PUT' => $this->runFilter($files, [], 'PUT')['result'],
                'multipart POST' => $this->runFilter($files)['result'],
            ]
        );
    }

    /**
     * Off by default: without config.json, and with the options written off, nothing is blocked or
     * counted, and no per-IP upload counter is written.
     */
    public function testWithTheOptionsOffNothingIsBlocked(): void
    {
        $files = $this->filesFor('x.php.jpg', self::phpInImageBytes());
        $noConfig = $this->runFilter($files)['result'];
        $this->writeFilterConfig(['upload_probe_enabled' => false, 'upload_burst_enabled' => false]);
        $configOff = $this->runFilter($files)['result'];

        $this->assertSame(['no config' => 'PASSED', 'config off' => 'PASSED'], ['no config' => $noConfig, 'config off' => $configOff]);
        $this->assertFalse($this->hasViolation());
        $this->assertFileDoesNotExist($this->dataDir() . '/upl_' . md5(self::CLIENT));
    }

    /**
     * WAF_UPLOAD_PROBE in the real environment switches the check on or off over config.json, as
     * WAF_EARLY_BAN does for the early ban.
     */
    public function testEnvironmentVariableOverridesTheConfigFile(): void
    {
        $files = $this->filesFor('x.php.jpg', self::jpegBytes());
        $onByEnv = $this->runFilter($files, ['WAF_UPLOAD_PROBE' => 'true'])['result'];
        $this->writeFilterConfig(['upload_probe_enabled' => true]);
        $offByEnv = $this->runFilter($files, ['WAF_UPLOAD_PROBE' => 'false'])['result'];

        $this->assertSame(['on by env' => 'FORBIDDEN', 'off by env' => 'PASSED'], ['on by env' => $onByEnv, 'off by env' => $offByEnv]);
    }

    /**
     * The point of the check (waf#15): the prober is banned by the existing ban_threshold, for every URL.
     */
    public function testRepeatedProbesBanTheSender(): void
    {
        $this->writeFilterConfig(['upload_probe_enabled' => true, 'ban_threshold' => 2]);
        $files = $this->filesFor('shell.phtml', self::jpegBytes());
        $this->runFilter($files);
        $this->runFilter($files);

        $this->assertFileExists($this->dataDir() . '/ban_' . md5(self::CLIENT));
        $this->assertSame(
            'FORBIDDEN',
            $this->runFilter([], [], 'GET', '')['result'],
            'a plain GET from the banned sender is blocked too'
        );
    }

    // ========================================================================
    // The filter: upload burst
    // ========================================================================

    /**
     * Every multipart POST past upload_burst_limit within the window counts as a violation. The request
     * itself goes through (a burst is a signal, not proof); the ban follows from ban_threshold.
     */
    public function testUploadBurstCountsAsViolation(): void
    {
        $this->writeFilterConfig(['upload_burst_enabled' => true, 'upload_burst_limit' => 3, 'upload_burst_window' => 60]);
        $files = $this->filesFor('photo.jpg', self::jpegBytes());

        $results = [];
        for ($i = 1; $i <= 3; $i++) {
            $results[] = $this->runFilter($files)['result'];
        }
        $this->assertFalse($this->hasViolation(), 'up to the limit nothing is counted');

        $fourth = $this->runFilter($files);
        $results[] = $fourth['result'];
        $this->assertSame(['PASSED', 'PASSED', 'PASSED', 'PASSED'], $results, 'the burst is not blocked');
        $this->assertTrue($this->hasViolation(), 'the POST past the limit is a violation');
        $this->assertStringContainsString('[WAF] VIOLATION reason=upload_burst ip=' . self::CLIENT . ' count=4', $fourth['log']);
    }

    /**
     * Burst off (the probe check on): no counter, no violations, however many uploads.
     */
    public function testUploadBurstIsOffByDefault(): void
    {
        $this->writeFilterConfig(['upload_probe_enabled' => true]);
        $files = $this->filesFor('photo.jpg', self::jpegBytes());
        for ($i = 1; $i <= 7; $i++) {
            $this->runFilter($files);
        }

        $this->assertFileDoesNotExist($this->dataDir() . '/upl_' . md5(self::CLIENT));
        $this->assertFalse($this->hasViolation());
    }

    /**
     * Once the window has passed the count starts over; a counter that is not ours is not continued.
     */
    public function testUploadBurstWindowStartsOver(): void
    {
        $this->writeFilterConfig(['upload_burst_enabled' => true, 'upload_burst_limit' => 3, 'upload_burst_window' => 60]);
        $counter = $this->dataDir() . '/upl_' . md5(self::CLIENT);
        file_put_contents($counter, '3:' . (time() - 120));
        $this->runFilter($this->filesFor('photo.jpg', self::jpegBytes()));

        $this->assertFalse($this->hasViolation());
        $this->assertStringStartsWith('1:', (string) file_get_contents($counter));
    }

    /**
     * CMS admin URLs are left out of the burst count (mic, PR #16: editors bulk-upload one POST per file),
     * at the framework's default /admin until the middleware has passed the real route on. The same POSTs
     * to a public URL do count (the must-fail control), and so does a longer word like /administrator.
     */
    public function testUploadBurstLeavesTheCmsAdminOut(): void
    {
        $this->writeFilterConfig(['upload_burst_enabled' => true, 'upload_burst_limit' => 2, 'upload_burst_window' => 60]);
        $files = $this->filesFor('photo.jpg', self::jpegBytes());
        $post = fn(string $path) => $this->runFilter($files, [], 'POST', 'multipart/form-data; boundary=x', $path)['result'];

        foreach (['/admin/assets/api/createFile', '/admin', '/ADMIN/assets/api/createFile', '/admin/pages/edit/EditForm/1/field/Image/upload'] as $path) {
            $this->assertSame('PASSED', $post($path));
        }
        $this->assertFileDoesNotExist($this->dataDir() . '/upl_' . md5(self::CLIENT), 'admin uploads are not counted');
        $this->assertFalse($this->hasViolation());

        foreach (['/administrator/upload', '/administrator/upload', '/administrator/upload'] as $path) {
            $post($path);
        }
        $this->assertTrue($this->hasViolation(), 'a public URL (here /administrator) past the limit counts');
    }

    /**
     * The admin route the middleware writes (a site that routes the CMS elsewhere) replaces /admin.
     */
    public function testUploadBurstFollowsTheAdminRouteFromTheConfigFile(): void
    {
        $this->writeFilterConfig([
            'upload_burst_enabled' => true, 'upload_burst_limit' => 2, 'upload_burst_window' => 60, 'admin_path' => '/beheer',
        ]);
        $files = $this->filesFor('photo.jpg', self::jpegBytes());
        $post = fn(string $path) => $this->runFilter($files, [], 'POST', 'multipart/form-data; boundary=x', $path)['result'];

        for ($i = 0; $i < 4; $i++) {
            $post('/beheer/assets/api/createFile');
        }
        $this->assertFalse($this->hasViolation(), 'the configured route is left out');

        for ($i = 0; $i < 3; $i++) {
            $post('/admin/assets/api/createFile');
        }
        $this->assertTrue($this->hasViolation(), '/admin is an ordinary URL on this site and counts');
    }

    /**
     * The probe check is not relaxed for the admin: a webshell upload there is blocked like anywhere else.
     */
    public function testProbeCheckStillAppliesToTheCmsAdmin(): void
    {
        $this->writeFilterConfig(['upload_probe_enabled' => true, 'upload_burst_enabled' => true]);
        $this->assertSame(
            'FORBIDDEN',
            $this->runFilter($this->filesFor('x.php.jpg', self::jpegBytes()), [], 'POST', 'multipart/form-data; boundary=x', '/admin/assets/api/createFile')['result']
        );
    }

    /**
     * Housekeeping treats the counter as one of the filter's own files (and nothing like it as one).
     */
    public function testUploadCounterIsAFilterDataFile(): void
    {
        $this->assertTrue(wafIsDataFileName('upl_' . md5(self::CLIENT)));
        $this->assertFalse(wafIsDataFileName('upl_' . md5(self::CLIENT) . '.bak'));
        $this->assertFalse(wafIsDataFileName('upload_' . md5(self::CLIENT)));
    }

    // ========================================================================
    // The middleware passes the options on
    // ========================================================================

    public function testMiddlewareWritesTheUploadOptionsForTheFilter(): void
    {
        $original = getenv('WAF_DATA_DIR');
        # The default dir, as in EarlyFilterProxyTest::testMiddlewareWritesTrustedProxiesForTheFilter()
        putenv('WAF_DATA_DIR');
        $configFile = wafEarlyDataDirPath(dirname(__DIR__)) . '/config.json';
        $write = function () use ($configFile): array {
            @unlink($configFile);   # it is only rewritten once an hour otherwise
            $method = new \ReflectionMethod(WafMiddleware::class, 'writeEarlyFilterConfig');
            $method->setAccessible(true);
            $method->invoke(WafMiddleware::create());
            return array_intersect_key(
                (array) json_decode((string) @file_get_contents($configFile), true),
                array_flip(['upload_probe_enabled', 'upload_burst_enabled', 'upload_burst_limit', 'upload_burst_window', 'admin_path'])
            );
        };
        try {
            $defaults = $write();
            Config::modify()->set(WafMiddleware::class, 'upload_probe_enabled', true);
            Config::modify()->set(WafMiddleware::class, 'upload_burst_enabled', true);
            Config::modify()->set(WafMiddleware::class, 'upload_burst_limit', 8);
            Config::modify()->set(WafMiddleware::class, 'upload_burst_window', 4);
            # The CMS routed elsewhere: get_admin_route() reads the Director rule first
            Config::modify()->set(Director::class, 'rules', ['beheer' => AdminRootController::class]);
            $set = $write();
        } finally {
            @unlink($configFile);
            $original === false ? putenv('WAF_DATA_DIR') : putenv('WAF_DATA_DIR=' . $original);
        }

        $this->assertSame(
            ['upload_probe_enabled' => false, 'upload_burst_enabled' => false, 'upload_burst_limit' => 5, 'upload_burst_window' => 10, 'admin_path' => '/admin'],
            $defaults
        );
        $this->assertSame(
            ['upload_probe_enabled' => true, 'upload_burst_enabled' => true, 'upload_burst_limit' => 8, 'upload_burst_window' => 4, 'admin_path' => '/beheer'],
            $set
        );
    }
}
