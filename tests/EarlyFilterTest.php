<?php

namespace Restruct\SilverStripe\Waf\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the early filter's pattern matching logic
 *
 * Note: The actual _waf_early_filter.php can't be tested directly as it
 * uses exit() and global state. These tests verify the pattern matching
 * logic in isolation.
 */
class EarlyFilterTest extends TestCase
{
    protected array $blockedPaths = [
        // WordPress probes
        '/wp-admin', '/wp-login', '/wp-content', '/wp-includes',
        '/xmlrpc.php', '/wp-config', '/wp-cron.php', '/wp-json',

        // PHP backdoors/webshells
        '/eval-stdin.php', '/alfacgiapi', '/alfa-rex',
        '/shell.php', '/c99.php', '/r57.php', '/wso.php',

        // Config/sensitive files
        '/.env', '/.git', '/.svn', '/.htpasswd', '/.htaccess',
        '/config.php', '/configuration.php',

        // Env config variants (not caught by /.env)
        'config.env', 'stripe.env', '/env.js', '/env.backup', '/__env.js',

        // Build tool / framework dev probes
        '/@vite/', '/.vite/', '/node_modules/', '/asset-manifest.json',

        // Database tools
        '/phpmyadmin', '/pma/', '/myadmin/', '/adminer',

        // Path traversal
        '../', '..%2f', '..%252f',

        // Backup files
        '.bak', '.backup', '.old', '.sql', '.zip',
    ];

    // ========================================================================
    // Path Pattern Matching Tests
    // ========================================================================

    /**
     * Test WordPress probe detection
     */
    public function testBlocksWordPressProbes(): void
    {
        $this->assertBlocked('/wp-admin/');
        $this->assertBlocked('/wp-admin/admin.php');
        $this->assertBlocked('/wp-login.php');
        $this->assertBlocked('/wp-content/uploads/2024/');
        $this->assertBlocked('/wp-includes/js/jquery.js');
        $this->assertBlocked('/xmlrpc.php');
        $this->assertBlocked('/wp-config.php');
        $this->assertBlocked('/WP-ADMIN/'); // Case insensitive
    }

    /**
     * Test webshell probe detection
     */
    public function testBlocksWebshellProbes(): void
    {
        $this->assertBlocked('/eval-stdin.php');
        $this->assertBlocked('/shell.php');
        $this->assertBlocked('/c99.php');
        $this->assertBlocked('/r57.php');
        $this->assertBlocked('/wso.php');
        $this->assertBlocked('/images/shell.php');
        $this->assertBlocked('/SHELL.PHP'); // Case insensitive
    }

    /**
     * Test config file probe detection
     */
    public function testBlocksConfigFileProbes(): void
    {
        $this->assertBlocked('/.env');
        $this->assertBlocked('/.env.backup');
        $this->assertBlocked('/.git/config');
        $this->assertBlocked('/.git/HEAD');
        $this->assertBlocked('/.svn/entries');
        $this->assertBlocked('/.htpasswd');
        $this->assertBlocked('/.htaccess');
        $this->assertBlocked('/config.php');
        $this->assertBlocked('/app/config.php');
    }

    /**
     * Test database admin tool detection
     */
    public function testBlocksDatabaseAdminProbes(): void
    {
        $this->assertBlocked('/phpmyadmin/');
        $this->assertBlocked('/phpMyAdmin/index.php');
        $this->assertBlocked('/pma/index.php');
        $this->assertBlocked('/myadmin/');
        $this->assertBlocked('/adminer.php');
        $this->assertBlocked('/adminer/');
    }

    /**
     * Test path traversal detection
     */
    public function testBlocksPathTraversal(): void
    {
        $this->assertBlocked('/../etc/passwd');
        $this->assertBlocked('/images/../../etc/passwd');
        $this->assertBlocked('/..%2f..%2fetc/passwd');
        $this->assertBlocked('/..%252f..%252fetc/passwd');
    }

    /**
     * Test backup file detection
     */
    public function testBlocksBackupFiles(): void
    {
        $this->assertBlocked('/config.php.bak');
        $this->assertBlocked('/database.sql');
        $this->assertBlocked('/backup.zip');
        $this->assertBlocked('/site.backup');
        $this->assertBlocked('/db.old');
    }

    /**
     * Test env config variant detection (files using .env as extension)
     */
    public function testBlocksEnvConfigVariants(): void
    {
        $this->assertBlocked('/config.env');
        $this->assertBlocked('/stripe.env');
        $this->assertBlocked('/env.js');
        $this->assertBlocked('/__env.js');
        $this->assertBlocked('/env.backup');
        $this->assertBlocked('/app/config.env');
        $this->assertBlocked('/assets/stripe.env');
    }

    /**
     * Test build tool / framework dev probe detection
     */
    public function testBlocksBuildToolProbes(): void
    {
        $this->assertBlocked('/@vite/client');
        $this->assertBlocked('/.vite/deps/react.js');
        $this->assertBlocked('/node_modules/lodash/index.js');
        $this->assertBlocked('/asset-manifest.json');
    }

    /**
     * Test legitimate paths are allowed
     */
    public function testAllowsLegitimatePaths(): void
    {
        $this->assertNotBlocked('/');
        $this->assertNotBlocked('/about/');
        $this->assertNotBlocked('/contact/');
        $this->assertNotBlocked('/admin/');  // SilverStripe admin
        $this->assertNotBlocked('/Security/login');
        $this->assertNotBlocked('/assets/image.jpg');
        $this->assertNotBlocked('/resources/script.js');
        $this->assertNotBlocked('/api/v1/users');
    }

    // ========================================================================
    // PHP Probe Detection Tests
    // ========================================================================

    /**
     * Test random PHP file probe detection pattern
     *
     * Note: The pattern matches short PHP filenames. The actual filter
     * has a whitelist to allow legitimate files like /index.php.
     * This test validates pattern matching, not the whitelist logic.
     */
    public function testRandomPhpProbePattern(): void
    {
        $pattern = '/^\/[a-z0-9_]{2,8}\.php$/i';

        // These should match the probe pattern (potential probes)
        $this->assertMatchesPattern($pattern, '/ab.php');
        $this->assertMatchesPattern($pattern, '/abc.php');
        $this->assertMatchesPattern($pattern, '/test1234.php');
        $this->assertMatchesPattern($pattern, '/xyz_abc.php');
        $this->assertMatchesPattern($pattern, '/index.php');  // Matches pattern, but whitelisted in filter

        // These should NOT match (too short, too long, or wrong structure)
        $this->assertNotMatchesPattern($pattern, '/a.php');         // Too short (1 char)
        $this->assertNotMatchesPattern($pattern, '/abcdefghi.php'); // Too long (9 chars)
        $this->assertNotMatchesPattern($pattern, '/dir/file.php');  // Has subdirectory
        $this->assertNotMatchesPattern($pattern, '/file.txt');      // Not PHP
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Assert that a URI would be blocked
     */
    protected function assertBlocked(string $uri): void
    {
        $uriLower = strtolower($uri);
        foreach ($this->blockedPaths as $pattern) {
            if (stripos($uriLower, strtolower($pattern)) !== false) {
                $this->assertTrue(true);
                return;
            }
        }
        $this->fail("URI should be blocked: {$uri}");
    }

    /**
     * Assert that a URI would NOT be blocked
     */
    protected function assertNotBlocked(string $uri): void
    {
        $uriLower = strtolower($uri);
        foreach ($this->blockedPaths as $pattern) {
            if (stripos($uriLower, strtolower($pattern)) !== false) {
                $this->fail("URI should NOT be blocked: {$uri} (matched: {$pattern})");
            }
        }
        $this->assertTrue(true);
    }

    /**
     * Assert that a URI matches a regex pattern
     */
    protected function assertMatchesPattern(string $pattern, string $uri): void
    {
        $this->assertMatchesRegularExpression($pattern, $uri, "URI should match pattern: {$uri}");
    }

    /**
     * Assert that a URI does NOT match a regex pattern
     */
    protected function assertNotMatchesPattern(string $pattern, string $uri): void
    {
        $this->assertDoesNotMatchRegularExpression($pattern, $uri, "URI should NOT match pattern: {$uri}");
    }
}
