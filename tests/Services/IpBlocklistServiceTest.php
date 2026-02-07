<?php

namespace Restruct\SilverStripe\Waf\Tests\Services;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Restruct\SilverStripe\Waf\Services\IpBlocklistService;

/**
 * Unit tests for IpBlocklistService
 *
 * These tests verify IP range handling works correctly, especially
 * numeric comparison of IP addresses stored as unsigned integer strings.
 */
class IpBlocklistServiceTest extends TestCase
{
    protected IpBlocklistService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new IpBlocklistService();
    }

    // ========================================================================
    // CIDR to Range Conversion Tests
    // ========================================================================

    /**
     * Test that CIDRs are correctly converted to IP ranges
     */
    public function testCidrsToSortedRanges(): void
    {
        $cidrs = [
            '192.168.1.0/24',  // 192.168.1.0 - 192.168.1.255
            '10.0.0.0/8',      // 10.0.0.0 - 10.255.255.255
        ];

        $ranges = $this->invokeMethod('cidrsToSortedRanges', [$cidrs]);

        $this->assertCount(2, $ranges);

        // Ranges should be sorted numerically (10.x.x.x comes before 192.x.x.x)
        // 10.0.0.0 = 167772160
        // 192.168.1.0 = 3232235776
        $this->assertEquals('167772160', $ranges[0][0]); // 10.0.0.0 start
        $this->assertEquals('184549375', $ranges[0][1]); // 10.255.255.255 end
        $this->assertEquals('3232235776', $ranges[1][0]); // 192.168.1.0 start
        $this->assertEquals('3232236031', $ranges[1][1]); // 192.168.1.255 end
    }

    /**
     * Test that ranges are sorted numerically, not lexicographically
     *
     * This tests the bug fix: "9" should come before "10" numerically,
     * but lexicographically "9" > "10" because '9' > '1'.
     */
    public function testRangesAreSortedNumerically(): void
    {
        // Create CIDRs that would fail with string sorting
        // Note: Adjacent IPs will be merged, so use non-adjacent values
        $cidrs = [
            '0.0.0.100/32',  // IP 100 (3 digits)
            '0.0.0.5/32',    // IP 5 (1 digit)
            '0.0.0.50/32',   // IP 50 (2 digits)
            '0.0.1.0/32',    // IP 256
        ];

        $ranges = $this->invokeMethod('cidrsToSortedRanges', [$cidrs]);

        // Should be sorted: 5, 50, 100, 256 (all separate, not adjacent)
        $this->assertCount(4, $ranges);
        $this->assertEquals('5', $ranges[0][0]);   // 0.0.0.5
        $this->assertEquals('50', $ranges[1][0]);  // 0.0.0.50
        $this->assertEquals('100', $ranges[2][0]); // 0.0.0.100
        $this->assertEquals('256', $ranges[3][0]); // 0.0.1.0
    }

    /**
     * Test overlapping ranges are merged correctly
     */
    public function testMergeOverlappingRanges(): void
    {
        // Ranges that overlap or are adjacent
        $ranges = [
            ['10', '20'],   // 10-20
            ['21', '30'],   // 21-30 (adjacent to previous)
            ['25', '35'],   // 25-35 (overlaps with previous)
            ['100', '200'], // 100-200 (separate)
        ];

        $merged = $this->invokeMethod('mergeOverlappingRanges', [$ranges]);

        // Should merge first three into one, keep fourth separate
        $this->assertCount(2, $merged);
        $this->assertEquals('10', $merged[0][0]);
        $this->assertEquals('35', $merged[0][1]);  // Merged 10-35
        $this->assertEquals('100', $merged[1][0]);
        $this->assertEquals('200', $merged[1][1]); // Separate 100-200
    }

    /**
     * Test merging with numeric comparison (not string)
     *
     * This verifies the fix: adjacent ranges should merge when
     * comparing numerically.
     */
    public function testMergeWorksWithVaryingDigitCounts(): void
    {
        // "9" adjacent to "10" - would fail with string comparison
        $ranges = [
            ['9', '9'],
            ['10', '10'],
        ];

        $merged = $this->invokeMethod('mergeOverlappingRanges', [$ranges]);

        // Should merge into single range 9-10
        $this->assertCount(1, $merged);
        $this->assertEquals('9', $merged[0][0]);
        $this->assertEquals('10', $merged[0][1]);
    }

    // ========================================================================
    // Binary Search Tests
    // ========================================================================

    /**
     * Test binary search finds IPs within ranges
     */
    public function testIpInRangesFindsMatch(): void
    {
        $ranges = [
            ['100', '200'],
            ['300', '400'],
            ['500', '600'],
        ];

        // IPs within ranges
        $this->assertTrue($this->invokeMethod('ipInRanges', ['0.0.0.150', $ranges]));
        $this->assertTrue($this->invokeMethod('ipInRanges', ['0.0.0.100', $ranges])); // Start boundary
        $this->assertTrue($this->invokeMethod('ipInRanges', ['0.0.0.200', $ranges])); // End boundary
        $this->assertTrue($this->invokeMethod('ipInRanges', ['0.0.1.94', $ranges]));  // 350 = 0.0.1.94
    }

    /**
     * Test binary search rejects IPs outside ranges
     */
    public function testIpInRangesRejectsNonMatch(): void
    {
        $ranges = [
            ['100', '200'],
            ['300', '400'],
        ];

        // IPs outside ranges
        $this->assertFalse($this->invokeMethod('ipInRanges', ['0.0.0.50', $ranges]));  // Below first
        $this->assertFalse($this->invokeMethod('ipInRanges', ['0.0.0.250', $ranges])); // Between ranges
        $this->assertFalse($this->invokeMethod('ipInRanges', ['0.0.2.0', $ranges]));   // Above last (512)
    }

    /**
     * Test binary search with varying digit string lengths
     *
     * This tests the bug fix: the binary search must compare numerically.
     */
    public function testBinarySearchWithVaryingDigits(): void
    {
        // Range that spans different digit counts
        $ranges = [
            ['5', '15'],   // Single to double digit
        ];

        $this->assertTrue($this->invokeMethod('ipInRanges', ['0.0.0.5', $ranges]));
        $this->assertTrue($this->invokeMethod('ipInRanges', ['0.0.0.9', $ranges]));
        $this->assertTrue($this->invokeMethod('ipInRanges', ['0.0.0.10', $ranges]));
        $this->assertTrue($this->invokeMethod('ipInRanges', ['0.0.0.15', $ranges]));
        $this->assertFalse($this->invokeMethod('ipInRanges', ['0.0.0.4', $ranges]));
        $this->assertFalse($this->invokeMethod('ipInRanges', ['0.0.0.16', $ranges]));
    }

    /**
     * Test binary search at maximum IP value (edge case)
     */
    public function testBinarySearchAtMaxIpValue(): void
    {
        // Range near maximum IPv4 value (255.255.255.255 = 4294967295)
        $ranges = [
            ['4294967290', '4294967295'],
        ];

        $this->assertTrue($this->invokeMethod('ipInRanges', ['255.255.255.250', $ranges]));
        $this->assertTrue($this->invokeMethod('ipInRanges', ['255.255.255.255', $ranges]));
        $this->assertFalse($this->invokeMethod('ipInRanges', ['255.255.255.249', $ranges]));
    }

    // ========================================================================
    // CIDR Matching Tests (Linear Fallback)
    // ========================================================================

    /**
     * Test direct CIDR matching for IPv4
     */
    public function testIpInCidrIPv4(): void
    {
        // Test /24 subnet
        $this->assertTrue($this->invokeMethod('ipInCidr', ['192.168.1.1', '192.168.1.0/24']));
        $this->assertTrue($this->invokeMethod('ipInCidr', ['192.168.1.255', '192.168.1.0/24']));
        $this->assertFalse($this->invokeMethod('ipInCidr', ['192.168.2.1', '192.168.1.0/24']));

        // Test /8 subnet
        $this->assertTrue($this->invokeMethod('ipInCidr', ['10.1.2.3', '10.0.0.0/8']));
        $this->assertTrue($this->invokeMethod('ipInCidr', ['10.255.255.255', '10.0.0.0/8']));
        $this->assertFalse($this->invokeMethod('ipInCidr', ['11.0.0.1', '10.0.0.0/8']));

        // Test /32 (single IP)
        $this->assertTrue($this->invokeMethod('ipInCidr', ['1.2.3.4', '1.2.3.4/32']));
        $this->assertFalse($this->invokeMethod('ipInCidr', ['1.2.3.5', '1.2.3.4/32']));
    }

    /**
     * Test CIDR matching for IPv6
     */
    public function testIpInCidrIPv6(): void
    {
        // Test /64 subnet
        $this->assertTrue($this->invokeMethod('ipInCidr', [
            '2001:db8:85a3::8a2e:370:7334',
            '2001:db8:85a3::/64'
        ]));

        $this->assertFalse($this->invokeMethod('ipInCidr', [
            '2001:db8:85a4::1',
            '2001:db8:85a3::/64'
        ]));
    }

    // ========================================================================
    // Blocklist Parsing Tests
    // ========================================================================

    /**
     * Test parsing IP-only format
     */
    public function testParseBlocklistFileIpFormat(): void
    {
        $content = <<<EOF
# Comment line
1.2.3.4
5.6.7.8
# Another comment
9.10.11.12
invalid-line
EOF;

        $result = $this->invokeMethod('parseBlocklistFile', [$content, 'ip']);

        $this->assertCount(3, $result['ips']);
        $this->assertEmpty($result['cidrs']);
        $this->assertContains('1.2.3.4', $result['ips']);
        $this->assertContains('5.6.7.8', $result['ips']);
        $this->assertContains('9.10.11.12', $result['ips']);
    }

    /**
     * Test parsing CIDR format
     */
    public function testParseBlocklistFileCidrFormat(): void
    {
        $content = <<<EOF
# FireHOL format
10.0.0.0/8
192.168.0.0/16
1.2.3.4
EOF;

        $result = $this->invokeMethod('parseBlocklistFile', [$content, 'cidr']);

        $this->assertCount(1, $result['ips']);
        $this->assertCount(2, $result['cidrs']);
        $this->assertContains('1.2.3.4', $result['ips']);
        $this->assertContains('10.0.0.0/8', $result['cidrs']);
        $this->assertContains('192.168.0.0/16', $result['cidrs']);
    }

    /**
     * Test parsing semicolon-separated format (Spamhaus style)
     */
    public function testParseBlocklistFileSemicolonFormat(): void
    {
        $content = <<<EOF
; Spamhaus DROP
10.0.0.0/8 ; SBL123456
192.168.0.0/16 ; SBL789012
EOF;

        $result = $this->invokeMethod('parseBlocklistFile', [$content, 'cidr_semicolon']);

        $this->assertCount(2, $result['cidrs']);
        $this->assertContains('10.0.0.0/8', $result['cidrs']);
        $this->assertContains('192.168.0.0/16', $result['cidrs']);
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Invoke a protected/private method on the service
     */
    protected function invokeMethod(string $method, array $args = []): mixed
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod($method);
        $method->setAccessible(true);
        return $method->invokeArgs($this->service, $args);
    }
}
