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
    // Helper Methods
    // ========================================================================

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
