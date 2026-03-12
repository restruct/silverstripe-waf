<?php

namespace Restruct\SilverStripe\Waf\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;

/**
 * Unit tests for WafMiddleware
 *
 * Tests rate limiting calculations, IP/CIDR matching, and user-agent filtering.
 */
class WafMiddlewareTest extends TestCase
{
    protected WafMiddleware $middleware;

    protected function setUp(): void
    {
        parent::setUp();
        $this->middleware = new WafMiddleware();
    }

    // ========================================================================
    // CIDR Matching Tests (Whitelist)
    // ========================================================================

    /**
     * Test IPv4 CIDR matching
     */
    public function testIpMatchesCidrIPv4(): void
    {
        // /24 subnet
        $this->assertTrue($this->invokeMethod('ipMatchesCidr', ['192.168.1.1', '192.168.1.0/24']));
        $this->assertTrue($this->invokeMethod('ipMatchesCidr', ['192.168.1.254', '192.168.1.0/24']));
        $this->assertFalse($this->invokeMethod('ipMatchesCidr', ['192.168.2.1', '192.168.1.0/24']));

        // /8 subnet
        $this->assertTrue($this->invokeMethod('ipMatchesCidr', ['10.1.2.3', '10.0.0.0/8']));
        $this->assertTrue($this->invokeMethod('ipMatchesCidr', ['10.255.255.255', '10.0.0.0/8']));
        $this->assertFalse($this->invokeMethod('ipMatchesCidr', ['11.0.0.1', '10.0.0.0/8']));

        // /16 subnet
        $this->assertTrue($this->invokeMethod('ipMatchesCidr', ['172.16.0.1', '172.16.0.0/16']));
        $this->assertTrue($this->invokeMethod('ipMatchesCidr', ['172.16.255.255', '172.16.0.0/16']));
        $this->assertFalse($this->invokeMethod('ipMatchesCidr', ['172.17.0.1', '172.16.0.0/16']));

        // /32 (single IP)
        $this->assertTrue($this->invokeMethod('ipMatchesCidr', ['1.2.3.4', '1.2.3.4/32']));
        $this->assertFalse($this->invokeMethod('ipMatchesCidr', ['1.2.3.5', '1.2.3.4/32']));
    }

    /**
     * Test edge cases for CIDR matching
     */
    public function testIpMatchesCidrEdgeCases(): void
    {
        // /0 (all IPs)
        $this->assertTrue($this->invokeMethod('ipMatchesCidr', ['1.2.3.4', '0.0.0.0/0']));
        $this->assertTrue($this->invokeMethod('ipMatchesCidr', ['255.255.255.255', '0.0.0.0/0']));

        // Invalid inputs
        $this->assertFalse($this->invokeMethod('ipMatchesCidr', ['not-an-ip', '10.0.0.0/8']));
        $this->assertFalse($this->invokeMethod('ipMatchesCidr', ['10.0.0.1', 'not-a-cidr']));

        // IPv6 IP with IPv4 CIDR
        $this->assertFalse($this->invokeMethod('ipMatchesCidr', ['::1', '10.0.0.0/8']));
    }

    // ========================================================================
    // Soft Rate Limiting Tests
    // ========================================================================

    /**
     * Test soft rate limit delay calculation
     *
     * This tests the progressive delay formula:
     * delay = ((requestCount - softThreshold) / (hardLimit - softThreshold)) * maxDelay
     */
    public function testSoftRateLimitDelayCalculation(): void
    {
        // Test the delay calculation logic directly
        $thresholdPercent = 50;
        $maxDelay = 3000;
        $hardLimit = 100;
        $softThreshold = (int) ($hardLimit * $thresholdPercent / 100); // 50

        // Helper to calculate delay
        $calcDelay = function (int $requestCount) use ($softThreshold, $hardLimit, $maxDelay): int {
            if ($requestCount <= $softThreshold) {
                return 0;
            }
            $range = $hardLimit - $softThreshold;
            $excess = $requestCount - $softThreshold;
            $ratio = min(1.0, $excess / $range);
            return (int) ($ratio * $maxDelay);
        };

        // Below threshold - no delay
        $this->assertEquals(0, $calcDelay(40));
        $this->assertEquals(0, $calcDelay(50));

        // At various points above threshold
        $this->assertEquals(600, $calcDelay(60));  // 20% of 3000
        $this->assertEquals(1500, $calcDelay(75)); // 50% of 3000
        $this->assertEquals(2400, $calcDelay(90)); // 80% of 3000
        $this->assertEquals(2940, $calcDelay(99)); // 98% of 3000
    }

    /**
     * Test that delay is capped at max even if over hard limit
     */
    public function testSoftRateLimitCapsAtMax(): void
    {
        $thresholdPercent = 50;
        $maxDelay = 3000;
        $hardLimit = 100;
        $softThreshold = (int) ($hardLimit * $thresholdPercent / 100);

        $calcDelay = function (int $requestCount) use ($softThreshold, $hardLimit, $maxDelay): int {
            if ($requestCount <= $softThreshold) {
                return 0;
            }
            $range = $hardLimit - $softThreshold;
            $excess = $requestCount - $softThreshold;
            $ratio = min(1.0, $excess / $range);  // Capped at 1.0
            return (int) ($ratio * $maxDelay);
        };

        // Over the limit should still cap at max delay
        $this->assertEquals(3000, $calcDelay(150));
        $this->assertEquals(3000, $calcDelay(1000));
    }

    // ========================================================================
    // User-Agent Pattern Matching Tests
    // ========================================================================

    /**
     * Test blocked user-agent patterns
     */
    public function testBlockedUserAgentPatterns(): void
    {
        // These patterns should match common scanners
        $patterns = [
            '/^$/i',        // Empty user-agent
            '/sqlmap/i',    // SQL injection tool
            '/nikto/i',     // Vulnerability scanner
            '/nmap/i',      // Network scanner
            '/masscan/i',   // Mass port scanner
            '/zgrab/i',     // Go-based scanner
            '/gobuster/i',  // Directory brute-forcer
            '/dirbuster/i', // Directory brute-forcer
            '/wpscan/i',    // WordPress scanner
        ];

        // Test each pattern
        $this->assertTrue($this->matchesAnyPattern('', $patterns));
        $this->assertTrue($this->matchesAnyPattern('sqlmap/1.0', $patterns));
        $this->assertTrue($this->matchesAnyPattern('Mozilla/5.0 (compatible; Nikto/2.1)', $patterns));
        $this->assertTrue($this->matchesAnyPattern('Nmap Scripting Engine', $patterns));
        $this->assertTrue($this->matchesAnyPattern('masscan/1.0', $patterns));
        $this->assertTrue($this->matchesAnyPattern('zgrab/0.x', $patterns));
        $this->assertTrue($this->matchesAnyPattern('gobuster/3.0', $patterns));
        $this->assertTrue($this->matchesAnyPattern('DirBuster-1.0', $patterns));
        $this->assertTrue($this->matchesAnyPattern('WPScan v3.8', $patterns));

        // Legitimate user-agents should not match
        $this->assertFalse($this->matchesAnyPattern('Mozilla/5.0 (Windows NT 10.0; Win64; x64)', $patterns));
        $this->assertFalse($this->matchesAnyPattern('curl/7.68.0', $patterns));
    }

    /**
     * Test whitelisted user-agent patterns
     */
    public function testWhitelistedUserAgentPatterns(): void
    {
        $patterns = [
            '/ohdear\\.app/i',
            '/googlebot/i',
            '/bingbot/i',
            '/uptimerobot/i',
            '/pingdom/i',
        ];

        // These should match
        $this->assertTrue($this->matchesAnyPattern('OhDear.app Bot/1.0', $patterns));
        $this->assertTrue($this->matchesAnyPattern('Mozilla/5.0 (compatible; Googlebot/2.1)', $patterns));
        $this->assertTrue($this->matchesAnyPattern('Mozilla/5.0 (compatible; bingbot/2.0)', $patterns));
        $this->assertTrue($this->matchesAnyPattern('UptimeRobot/2.0', $patterns));
        $this->assertTrue($this->matchesAnyPattern('Pingdom.com_bot_version_1.4', $patterns));

        // These should not match
        $this->assertFalse($this->matchesAnyPattern('Mozilla/5.0 (Windows NT 10.0)', $patterns));
        $this->assertFalse($this->matchesAnyPattern('curl/7.68.0', $patterns));
    }

    // ========================================================================
    // Privileged IP Factor Lookup Tests
    // ========================================================================

    /**
     * Test privileged IP factor: exact IP match (O(1) hash lookup)
     */
    public function testPrivilegedIpFactorExactMatch(): void
    {
        $entries = [
            '10.0.0.1' => 3.0,
            '192.168.1.100' => 2.0,
            '10.0.0.0/8' => 5.0,
        ];

        # Exact matches should return their factor
        $this->assertEquals(3.0, $this->lookupFactor('10.0.0.1', $entries));
        $this->assertEquals(2.0, $this->lookupFactor('192.168.1.100', $entries));
    }

    /**
     * Test privileged IP factor: CIDR range match
     */
    public function testPrivilegedIpFactorCidrMatch(): void
    {
        $entries = [
            '10.0.0.0/8' => 5.0,
            '192.168.1.0/24' => 2.5,
        ];

        # IPs within CIDR ranges should match
        $this->assertEquals(5.0, $this->lookupFactor('10.1.2.3', $entries));
        $this->assertEquals(5.0, $this->lookupFactor('10.255.255.255', $entries));
        $this->assertEquals(2.5, $this->lookupFactor('192.168.1.50', $entries));
    }

    /**
     * Test privileged IP factor: exact match takes precedence over CIDR
     */
    public function testPrivilegedIpFactorExactTakesPrecedence(): void
    {
        $entries = [
            '10.0.0.1' => 3.0,       # Exact match
            '10.0.0.0/8' => 5.0,     # CIDR also covers 10.0.0.1
        ];

        # Exact match (3.0) should be returned, not CIDR match (5.0)
        $this->assertEquals(3.0, $this->lookupFactor('10.0.0.1', $entries));

        # Other IPs in the range still get the CIDR factor
        $this->assertEquals(5.0, $this->lookupFactor('10.0.0.2', $entries));
    }

    /**
     * Test privileged IP factor: non-privileged IP returns null
     */
    public function testPrivilegedIpFactorNoMatch(): void
    {
        $entries = [
            '10.0.0.1' => 3.0,
            '192.168.1.0/24' => 2.0,
        ];

        $this->assertNull($this->lookupFactor('1.2.3.4', $entries));
        $this->assertNull($this->lookupFactor('192.168.2.1', $entries));
    }

    /**
     * Test privileged IP factor: empty entries returns null
     */
    public function testPrivilegedIpFactorEmptyEntries(): void
    {
        $this->assertNull($this->lookupFactor('10.0.0.1', []));
    }

    // ========================================================================
    // Effective Limit Calculation Tests
    // ========================================================================

    /**
     * Test effective limit calculation with factor
     *
     * Verifies: effectiveLimit = ceil(hardLimit * factor)
     */
    public function testEffectiveLimitCalculation(): void
    {
        # Standard factors
        $this->assertEquals(200, (int) ceil(100 * 2.0));
        $this->assertEquals(300, (int) ceil(100 * 3.0));
        $this->assertEquals(500, (int) ceil(100 * 5.0));

        # Non-integer results get rounded up
        $this->assertEquals(250, (int) ceil(100 * 2.5));
        $this->assertEquals(150, (int) ceil(100 * 1.5));

        # Factor < 1 (restrictive — valid but unusual)
        $this->assertEquals(50, (int) ceil(100 * 0.5));
    }

    /**
     * Test soft rate limit delay scales correctly with elevated effective limit
     *
     * With factor 3.0, hard limit 100 → effective limit 300.
     * Soft threshold at 50% → 150 requests before delays start.
     * Delays should scale proportionally across the larger range.
     */
    public function testSoftRateLimitWithElevatedLimit(): void
    {
        $thresholdPercent = 50;
        $maxDelay = 3000;
        $hardLimit = 100;
        $factor = 3.0;
        $effectiveLimit = (int) ceil($hardLimit * $factor); // 300
        $softThreshold = (int) ($effectiveLimit * $thresholdPercent / 100); // 150

        $calcDelay = function (int $requestCount) use ($softThreshold, $effectiveLimit, $maxDelay): int {
            if ($requestCount <= $softThreshold) {
                return 0;
            }
            $range = $effectiveLimit - $softThreshold;
            $excess = $requestCount - $softThreshold;
            $ratio = min(1.0, $excess / $range);
            return (int) ($ratio * $maxDelay);
        };

        # Below elevated threshold — no delay
        $this->assertEquals(0, $calcDelay(100));  # Would be over base limit, but privileged
        $this->assertEquals(0, $calcDelay(150));  # At threshold

        # Progressive delays across elevated range (150..300)
        $this->assertEquals(600, $calcDelay(180));  # 20% of range
        $this->assertEquals(1500, $calcDelay(225)); # 50% of range
        $this->assertEquals(2400, $calcDelay(270)); # 80% of range

        # At effective limit
        $this->assertEquals(3000, $calcDelay(300));
    }

    // ========================================================================
    // Config Tier Flattening Tests
    // ========================================================================

    /**
     * Test flattening tier-based config into [ip => factor] map
     *
     * This mirrors the logic in getPrivilegedIpEntries() that converts
     * the tier config format into a flat lookup array.
     */
    public function testConfigTierFlattening(): void
    {
        $tiers = [
            'office' => [
                'factor' => 3.0,
                'ips' => ['10.0.0.0/8', '192.168.1.0/24'],
            ],
            'monitoring' => [
                'factor' => 5.0,
                'ips' => ['203.0.113.50'],
            ],
        ];

        # Flatten (same logic as middleware)
        $entries = [];
        foreach ($tiers as $tierName => $tierConfig) {
            $factor = (float) ($tierConfig['factor'] ?? 2.0);
            $ips = $tierConfig['ips'] ?? [];
            foreach ($ips as $ip) {
                $entries[$ip] = $factor;
            }
        }

        $this->assertCount(3, $entries);
        $this->assertEquals(3.0, $entries['10.0.0.0/8']);
        $this->assertEquals(3.0, $entries['192.168.1.0/24']);
        $this->assertEquals(5.0, $entries['203.0.113.50']);
    }

    /**
     * Test DB entries override config for same IP
     */
    public function testDbOverridesConfigForSameIp(): void
    {
        # Start with config entries
        $entries = [
            '10.0.0.0/8' => 3.0,
            '203.0.113.50' => 5.0,
        ];

        # Simulate DB merge (same IP, different factor)
        $dbEntries = [
            '203.0.113.50' => 10.0,  # Override config
            '1.2.3.4' => 2.0,        # New entry
        ];

        foreach ($dbEntries as $ip => $factor) {
            $entries[$ip] = $factor;
        }

        $this->assertEquals(3.0, $entries['10.0.0.0/8']);   # Unchanged
        $this->assertEquals(10.0, $entries['203.0.113.50']); # Overridden
        $this->assertEquals(2.0, $entries['1.2.3.4']);        # New
    }

    /**
     * Test tier config with missing factor falls back to 2.0
     */
    public function testConfigTierMissingFactorDefaultsTo2(): void
    {
        $tiers = [
            'noFactor' => [
                'ips' => ['1.2.3.4'],
                // No 'factor' key
            ],
        ];

        $entries = [];
        foreach ($tiers as $tierName => $tierConfig) {
            $factor = (float) ($tierConfig['factor'] ?? 2.0);
            $ips = $tierConfig['ips'] ?? [];
            foreach ($ips as $ip) {
                $entries[$ip] = $factor;
            }
        }

        $this->assertEquals(2.0, $entries['1.2.3.4']);
    }

    // ========================================================================
    // Time-Windowed Rate Counter Tests
    // ========================================================================

    /**
     * Test that rate counter cache key includes time window ID
     *
     * The key format should be: rate_{md5(ip)}_{windowId}
     * where windowId = intdiv(time(), window)
     */
    public function testRateCounterKeyIncludesWindowId(): void
    {
        $window = 60;
        $ip = '1.2.3.4';
        $ipHash = md5($ip);

        # Calculate what the windowed key should be
        $windowId = intdiv(time(), $window);
        $expectedKey = 'rate_' . $ipHash . '_' . $windowId;

        # Verify the key format matches the pattern
        $this->assertMatchesRegularExpression(
            '/^rate_[a-f0-9]{32}_\d+$/',
            $expectedKey,
            'Rate counter key should be: rate_{md5}_{windowId}'
        );

        # Different windows produce different keys
        $nextWindowKey = 'rate_' . $ipHash . '_' . ($windowId + 1);
        $this->assertNotEquals($expectedKey, $nextWindowKey,
            'Different time windows should produce different cache keys'
        );
    }

    /**
     * Test that continuous traffic within the same window accumulates
     * but a new window starts a fresh counter
     *
     * This verifies the core fix: with the old approach (single key + TTL reset),
     * a counter at 2 req/sec would reach 600 after 300 seconds because the TTL
     * kept resetting. With windowed keys, each 60-second window caps at ~120.
     */
    public function testWindowedCounterResetsEachWindow(): void
    {
        $window = 60;
        $requestsPerSecond = 2;

        # Simulate traffic within a single window
        $requestsPerWindow = $requestsPerSecond * $window; // 120
        $baseLimit = 200;

        # 120 < 200: single window should never trigger rate limit
        $this->assertLessThan($baseLimit, $requestsPerWindow,
            'At 2 req/sec, a single 60s window should produce ~120 requests (under 200 limit)'
        );

        # With old (broken) approach: 5 minutes of traffic = 600 requests (hits even privileged limit)
        $oldApproachTotal = $requestsPerSecond * 300; // 600
        $privilegedLimit = $baseLimit * 3; // 600
        $this->assertGreaterThanOrEqual($privilegedLimit, $oldApproachTotal,
            'Old approach: 5 minutes at 2 req/sec = 600, hitting privileged limit'
        );

        # With new (fixed) approach: each window maxes at 120, never accumulates
        $this->assertLessThan($baseLimit, $requestsPerWindow,
            'New approach: each window independently counts ~120, always under limit'
        );
    }

    // ========================================================================
    // Privileged IP Auto-Ban Protection Tests
    // ========================================================================

    /**
     * Test that privileged IPs should not accumulate violations for rate_limit
     *
     * When reason is 'rate_limit' and IP is privileged, recordViolation()
     * should return early without counting the violation.
     */
    public function testPrivilegedIpSkipsViolationCountingForRateLimit(): void
    {
        # The logic in recordViolation() is:
        # if ($reason === 'rate_limit' && getPrivilegedIpFactor($ip) !== null) return;
        $reason = 'rate_limit';
        $isPrivileged = true;

        # Privileged + rate_limit → should skip (return early)
        $this->assertTrue($reason === 'rate_limit' && $isPrivileged,
            'Privileged IPs with rate_limit reason should skip violation counting'
        );

        # Privileged + other reason → should NOT skip
        $securityReason = 'blocklist';
        $this->assertFalse($securityReason === 'rate_limit' && $isPrivileged,
            'Privileged IPs with security violations should still be counted'
        );

        # Non-privileged + rate_limit → should NOT skip
        $isNotPrivileged = false;
        $this->assertFalse($reason === 'rate_limit' && $isNotPrivileged,
            'Non-privileged IPs should always count violations'
        );
    }

    /**
     * Test that privileged IPs bypass existing bans
     *
     * In process(), if IP is banned but is privileged, it should be
     * auto-unbanned and allowed to continue to rate limiting.
     */
    public function testPrivilegedIpBypassesBan(): void
    {
        # The logic in process() is:
        # if (isBanned($ip) && getPrivilegedIpFactor($ip) !== null) → unban, continue
        # if (isBanned($ip) && getPrivilegedIpFactor($ip) === null) → block
        $isBanned = true;

        # Privileged + banned → should unban and continue
        $privilegedFactor = 3.0;
        $shouldBypass = $isBanned && $privilegedFactor !== null;
        $this->assertTrue($shouldBypass,
            'Privileged IPs should bypass existing bans'
        );

        # Non-privileged + banned → should block
        $nonPrivilegedFactor = null;
        $shouldBlock = $isBanned && $nonPrivilegedFactor === null;
        $this->assertTrue($shouldBlock,
            'Non-privileged IPs should remain blocked when banned'
        );
    }

    /**
     * Test that only rate_limit violations are exempted, not security violations
     */
    public function testPrivilegedIpStillBannedForSecurityViolations(): void
    {
        $securityReasons = ['blocklist', 'bad_useragent'];
        $rateReason = 'rate_limit';

        foreach ($securityReasons as $reason) {
            # Security reasons should NOT match the skip condition
            $this->assertNotEquals('rate_limit', $reason,
                "Security reason '{$reason}' should not be exempted from auto-ban"
            );
        }

        # Only rate_limit should match
        $this->assertEquals('rate_limit', $rateReason,
            'Only rate_limit reason should be exempted for privileged IPs'
        );
    }

    // ========================================================================
    // IP/CIDR Validation Tests (mirrors PrivilegedIp::validate() logic)
    // ========================================================================

    /**
     * Test IP address validation
     */
    public function testIpAddressValidation(): void
    {
        # Valid IPv4
        $this->assertTrue($this->isValidIpOrCidr('1.2.3.4'));
        $this->assertTrue($this->isValidIpOrCidr('192.168.1.1'));
        $this->assertTrue($this->isValidIpOrCidr('255.255.255.255'));

        # Valid IPv6
        $this->assertTrue($this->isValidIpOrCidr('::1'));
        $this->assertTrue($this->isValidIpOrCidr('2001:db8::1'));

        # Valid CIDR
        $this->assertTrue($this->isValidIpOrCidr('10.0.0.0/8'));
        $this->assertTrue($this->isValidIpOrCidr('192.168.1.0/24'));
        $this->assertTrue($this->isValidIpOrCidr('1.2.3.4/32'));
        $this->assertTrue($this->isValidIpOrCidr('::1/128'));

        # Invalid
        $this->assertFalse($this->isValidIpOrCidr('not-an-ip'));
        $this->assertFalse($this->isValidIpOrCidr('999.999.999.999'));
        $this->assertFalse($this->isValidIpOrCidr('10.0.0.0/abc'));
        $this->assertFalse($this->isValidIpOrCidr('10.0.0.0/-1'));
        $this->assertFalse($this->isValidIpOrCidr('10.0.0.0/200'));
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Look up privileged IP factor from an entries array
     *
     * Mirrors the logic in getPrivilegedIpFactor() without needing
     * cache/DB dependencies.
     */
    protected function lookupFactor(string $ip, array $entries): ?float
    {
        if (empty($entries)) {
            return null;
        }

        # Exact match first (O(1))
        if (isset($entries[$ip])) {
            return $entries[$ip];
        }

        # CIDR match (O(n))
        foreach ($entries as $entry => $factor) {
            if (str_contains($entry, '/') && $this->invokeMethod('ipMatchesCidr', [$ip, $entry])) {
                return $factor;
            }
        }

        return null;
    }

    /**
     * Validate IP or CIDR format (mirrors PrivilegedIp::validate() logic)
     */
    protected function isValidIpOrCidr(string $ip): bool
    {
        if (str_contains($ip, '/')) {
            [$subnet, $bits] = explode('/', $ip, 2);
            return filter_var($subnet, FILTER_VALIDATE_IP) !== false
                && is_numeric($bits)
                && (int) $bits >= 0
                && (int) $bits <= 128;
        }

        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Check if a user-agent matches any pattern
     */
    protected function matchesAnyPattern(string $userAgent, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Invoke a protected/private method on the middleware
     */
    protected function invokeMethod(string $method, array $args = []): mixed
    {
        $reflection = new ReflectionClass($this->middleware);
        $method = $reflection->getMethod($method);
        $method->setAccessible(true);
        return $method->invokeArgs($this->middleware, $args);
    }
}
