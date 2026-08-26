<?php

namespace Restruct\SilverStripe\Waf\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Tests for the early filter's typed path matching (_waf_matching.php).
 *
 * Since 1.5.0 the inventory and matcher are shared code with no exit()/globals,
 * so these tests exercise the REAL production list — no more duplicated copy
 * that drifts from the shipped one (the pre-1.5.0 test list had exactly that
 * problem, which is how the waf#3 false positives went unnoticed).
 */
class EarlyFilterTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        require_once dirname(__DIR__) . '/_waf_matching.php';
    }

    // ========================================================================
    // Matching-type semantics (one focused test per type)
    // ========================================================================

    public function testExactMatchesWholePathOnly(): void
    {
        $e = [['pattern' => '/artisan', 'match' => 'exact', 'class' => 't']];
        $this->assertNotNull(wafMatchBlockedPath('/artisan', $e));
        $this->assertNotNull(wafMatchBlockedPath('/ARTISAN', $e), 'case-insensitive');
        $this->assertNull(wafMatchBlockedPath('/artisan-bakker', $e));
        $this->assertNull(wafMatchBlockedPath('/artisan/x', $e));
        $this->assertNull(wafMatchBlockedPath('/x/artisan', $e));
    }

    public function testPrefixMatchesStems(): void
    {
        $e = [['pattern' => '/wp-admin', 'match' => 'prefix', 'class' => 't']];
        $this->assertNotNull(wafMatchBlockedPath('/wp-admin', $e));
        $this->assertNotNull(wafMatchBlockedPath('/wp-admin/setup-config.php', $e));
        $this->assertNotNull(wafMatchBlockedPath('/wp-admin.php', $e));
        $this->assertNull(wafMatchBlockedPath('/xwp-admin', $e));
    }

    public function testSegmentMatchesNameOrSubtreeButNotLongerWords(): void
    {
        $e = [['pattern' => '/plesk', 'match' => 'segment', 'class' => 't']];
        $this->assertNotNull(wafMatchBlockedPath('/plesk', $e));
        $this->assertNotNull(wafMatchBlockedPath('/plesk/login.php', $e));
        $this->assertNull(wafMatchBlockedPath('/pleskens', $e), 'surname must not match');
        $this->assertNull(wafMatchBlockedPath('/team/plesk', $e), 'not path-start');
    }

    public function testSuffixIsBasenameAnchored(): void
    {
        $e = [['pattern' => '/config.php', 'match' => 'suffix', 'class' => 't']];
        $this->assertNotNull(wafMatchBlockedPath('/config.php', $e));
        $this->assertNotNull(wafMatchBlockedPath('/app/config.php', $e));
        $this->assertNull(wafMatchBlockedPath('/xconfig.php', $e), 'leading slash anchors the basename');
    }

    public function testTraversalMatchesRawAndDecodedForms(): void
    {
        $entries = wafBlockedPathEntries();
        $this->assertNotNull(wafMatchBlockedPath('/..%2fetc/passwd', $entries), 'encoded, raw view');
        $this->assertNotNull(wafMatchBlockedPath('/%2e%2e/%2e%2e/etc/passwd', $entries));
        $this->assertNotNull(wafMatchBlockedPath('/etc/../etc/passwd', $entries), 'plain form');
    }

    // ========================================================================
    // Probe battery — genuine attack paths must all block (real inventory)
    // ========================================================================

    public function probeProvider(): array
    {
        return array_map(fn($u) => [$u], [
            '/wp-login.php', '/wp-admin/setup-config.php', '/xmlrpc.php', '/wp-json/wp/v2/users',
            '/administrator/index.php', '/htaccess.txt',
            '/core/install.php', '/update.php',
            '/app/etc/local.xml', '/downloader/',
            '/artisan', '/storage/logs/laravel.log', '/.env', '/.env.production',
            '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
            '/shell.php', '/old/shell.php', '/WSO.php', '/adminer.php',
            '/.git/config', '/.aws/credentials', '/id_rsa', '/backup/id_rsa',
            '/config.php', '/app/config.php', '/composer.json', '/web.config',
            '/phpmyadmin/index.php', '/phpMyAdmin/', '/pma/index.php',
            '/cgi-bin/test.cgi', '/cpanel', '/plesk/login.php', '/webmin/',
            '/~root/.ssh/id_rsa',
            '/admin.php', '/test.php', '/phpinfo.php', '/old/phpinfo.php',
            '/_profiler/phpinfo', '/telescope/requests', '/actuator/env',
            '/index.php.bak', '/wp-config.php.orig', '/.index.php.swp',
            '/site.env', '/config/prod.env',
            // mail-probe (waf#1)
            '/autodiscover/autodiscover.xml', '/Autodiscover/Autodiscover.xml', '/FPURL.xml',
        ]);
    }

    /** @dataProvider probeProvider */
    public function testGenuineProbesAreBlocked(string $path): void
    {
        $this->assertNotNull(
            wafMatchBlockedPath($path),
            "Probe path should be blocked: $path"
        );
    }

    // ========================================================================
    // False-positive battery — waf#3/waf#5 regressions. Every entry is a plausible
    // real URL on SOME Silverstripe site (goflex is a vacancy site, hence the
    // healthcare/artisan slugs). None may match the shipped inventory.
    // ========================================================================

    public function legitProvider(): array
    {
        return array_map(fn($u) => [$u], [
            // content vocabulary that used to collide (waf#3/waf#5)
            '/vacatures/healthcare-manager-utrecht',
            '/vacatures/item/9695/omscholen-tot-monteur',
            '/en/health-and-safety-officer',
            '/metrics-analist-vacature',
            '/vacatures/artisan-bakker-amsterdam',
            '/team/pleskens',
            '/webminar-aanmelden',
            '/nieuws/database-trends-2026',
            '/console-operator-vacature',
            '/over-ons/~historie~',
            // downloads + protected-asset extensions (dropped from the block list)
            '/downloads/brochure-2026.zip',
            '/assets/uploads/jaarrapport.tar.gz',
            '/assets/Uploads/backup-foto.sql',
            '/documenten/cao.old',
            // framework-legit / site-legit paths
            '/', '/index.php', '/search', '/admin/pages', '/Security/login',
            '/vacatures/xmlroc',
            '/mbo-opleidingen/gezondheidszorg',
            '/api/testimonials',
        ]);
    }

    /** @dataProvider legitProvider */
    public function testLegitimateUrlsAreNotBlocked(string $path): void
    {
        $this->assertNull(
            wafMatchBlockedPath($path),
            "Legitimate URL must not be blocked: $path"
        );
    }

    // ========================================================================
    // The inventory itself is well-formed (guards against a malformed entry
    // shipping — every pattern needs a known match type and a class).
    // ========================================================================

    public function testInventoryIsWellFormed(): void
    {
        $validTypes = ['exact', 'prefix', 'segment', 'suffix', 'contains', 'traversal'];
        foreach (wafBlockedPathEntries() as $i => $e) {
            $this->assertArrayHasKey('pattern', $e, "entry $i missing pattern");
            $this->assertArrayHasKey('match', $e, "entry {$e['pattern']} missing match");
            $this->assertArrayHasKey('class', $e, "entry {$e['pattern']} missing class");
            $this->assertContains($e['match'], $validTypes, "entry {$e['pattern']} bad match type");
            $this->assertNotSame('', $e['pattern'], "empty pattern at $i");
        }
    }

    public function testQueryStringIsNeverPartOfTheMatch(): void
    {
        // The caller passes only the path; prove a hostile query can't trigger a block
        // even when it contains a probe string (the pre-1.5.0 REQUEST_URI bug).
        $this->assertNull(wafMatchBlockedPath('/search'), 'baseline');
        // simulate what the filter does: parse_url path only
        $uri = '/search?q=/wp-admin+and+.env+and+../etc';
        $path = parse_url($uri, PHP_URL_PATH);
        $this->assertNull(wafMatchBlockedPath($path), 'probe strings in query must not block');
    }

    // ========================================================================
    // Export-shape guard (waf#2). The forge-helper consumer pins our
    // resources/blocklist.json as a fixture, so a schema drift breaks its suite;
    // this pins the same invariants on our side so it breaks here first.
    // ========================================================================

    public function testExportShapeIsStable(): void
    {
        $json = shell_exec(
            'php ' . escapeshellarg(dirname(__DIR__) . '/bin/export-blocklist.php') . ' 9.9.9 --stdout'
        );
        $doc = json_decode($json, true);

        $this->assertSame(1, $doc['schema'], 'export schema must stay 1 unless consumers are told');
        $this->assertNotEmpty($doc['entries']);

        // The export match set is exactly {exact, prefix, suffix, contains}: no 'segment'
        // (flattened), no 'traversal'/dotfiles (not exported), and crucially no
        // 'extension' — suffix must stay suffix so /shell.php is not conflated with .bak.
        $allowed = ['exact', 'prefix', 'suffix', 'contains'];
        foreach ($doc['entries'] as $e) {
            $this->assertContains($e['match'], $allowed, "unexpected export match type {$e['match']} for {$e['pattern']}");
        }

        $byPattern = [];
        foreach ($doc['entries'] as $e) {
            $byPattern[$e['pattern']] = $e['match'];
        }
        // The distinction the consumer relies on:
        $this->assertSame('suffix', $byPattern['/shell.php'] ?? null, 'basename-suffix must export as suffix');
        $this->assertSame('suffix', $byPattern['.bak'] ?? null, 'true extension also exports as suffix');
        // Excluded classes must not leak:
        $this->assertArrayNotHasKey('/.env', $byPattern, 'dotfiles are export:false');
        $this->assertArrayNotHasKey('../', $byPattern, 'traversal is not exported');
        $this->assertArrayNotHasKey('/autodiscover/autodiscover.xml', $byPattern,
            'autodiscover is export:false — nginx parasite block owns it, a dup location = [emerg]');
    }
}
