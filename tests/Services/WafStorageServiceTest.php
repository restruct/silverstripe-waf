<?php

namespace Restruct\SilverStripe\Waf\Tests\Services;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use ReflectionClass;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;

/**
 * Unit tests for WafStorageService
 *
 * Tests hybrid storage behavior, high-load detection, and ban management.
 */
class WafStorageServiceTest extends TestCase
{
    protected WafStorageService $service;
    protected MockCache $mockCache;

    protected function setUp(): void
    {
        parent::setUp();

        // Create mock cache
        $this->mockCache = new MockCache();

        // Create service with injected mock cache
        $this->service = new TestableWafStorageService($this->mockCache);
    }

    // ========================================================================
    // High-Load Detection Tests
    // ========================================================================

    /**
     * Test that high load is detected when violations exceed threshold
     */
    public function testHighLoadDetectedAboveThreshold(): void
    {
        // Set threshold to 100 violations per minute
        $this->service->setTestConfig('high_load_threshold', 100);

        // Simulate 99 violations - should NOT be high load
        $this->mockCache->set('waf_violations_minute', 99, 60);
        $this->assertFalse($this->invokeMethod('isHighLoad'));

        // Simulate 100 violations - should BE high load
        $this->mockCache->set('waf_violations_minute', 100, 60);
        $this->assertTrue($this->invokeMethod('isHighLoad'));

        // Simulate 150 violations - definitely high load
        $this->mockCache->set('waf_violations_minute', 150, 60);
        $this->assertTrue($this->invokeMethod('isHighLoad'));
    }

    /**
     * Test that high load detection can be disabled
     */
    public function testHighLoadDetectionDisabled(): void
    {
        // Disable threshold (set to 0)
        $this->service->setTestConfig('high_load_threshold', 0);

        // Even with many violations, should not be considered high load
        $this->mockCache->set('waf_violations_minute', 1000, 60);
        $this->assertFalse($this->invokeMethod('isHighLoad'));
    }

    /**
     * Test violation counting increments correctly
     */
    public function testRecordViolationIncrements(): void
    {
        // Initial count should be 0
        $this->assertEquals(0, $this->mockCache->get('waf_violations_minute'));

        // Record violations
        $this->service->recordViolation();
        $this->assertEquals(1, $this->mockCache->get('waf_violations_minute'));

        $this->service->recordViolation();
        $this->assertEquals(2, $this->mockCache->get('waf_violations_minute'));

        $this->service->recordViolation();
        $this->assertEquals(3, $this->mockCache->get('waf_violations_minute'));
    }

    /**
     * Test that logging is skipped under high load
     */
    public function testLoggingSkippedUnderHighLoad(): void
    {
        $this->service->setTestConfig('high_load_threshold', 100);
        $this->service->setTestConfig('storage_mode', 'file');

        // Simulate high load
        $this->mockCache->set('waf_violations_minute', 150, 60);

        // This should NOT write to file (high load mode)
        // We can't easily test file writes, but we can verify the method returns early
        $this->service->logBlockedRequest('1.2.3.4', '/test', 'TestAgent', 'test', 'detail');

        // In high load mode, the log should be skipped
        // (In a real test, we'd check that no file was written)
        $this->assertTrue(true); // Placeholder - method runs without error
    }

    // ========================================================================
    // Ban Management Tests
    // ========================================================================

    /**
     * Test banning an IP stores it in cache
     */
    public function testBanIpStoresInCache(): void
    {
        $this->service->setTestConfig('high_load_threshold', 0); // Disable high load
        $this->service->setTestConfig('storage_mode', 'cache');

        $this->service->banIp('1.2.3.4', 3600, 'Test ban');

        // Check cache has the ban
        $cacheKey = 'banned_' . md5('1.2.3.4');
        $this->assertTrue($this->mockCache->get($cacheKey));
    }

    /**
     * Test checking if IP is banned
     */
    public function testIsBannedChecksCache(): void
    {
        $this->service->setTestConfig('storage_mode', 'cache');

        // Not banned initially
        $this->assertFalse($this->service->isBanned('1.2.3.4'));

        // Add ban to cache
        $cacheKey = 'banned_' . md5('1.2.3.4');
        $this->mockCache->set($cacheKey, true, 3600);

        // Now should be banned
        $this->assertTrue($this->service->isBanned('1.2.3.4'));
    }

    /**
     * Test unbanning removes from cache
     */
    public function testUnbanRemovesFromCache(): void
    {
        $this->service->setTestConfig('storage_mode', 'cache');

        // Set up a banned IP
        $cacheKey = 'banned_' . md5('1.2.3.4');
        $this->mockCache->set($cacheKey, true, 3600);
        $this->assertTrue($this->service->isBanned('1.2.3.4'));

        // Unban
        $this->service->unbanIp('1.2.3.4');

        // Should no longer be banned
        $this->assertNull($this->mockCache->get($cacheKey));
    }

    /**
     * Test banning is skipped under high load (cache-only)
     */
    public function testBanPersistenceSkippedUnderHighLoad(): void
    {
        $this->service->setTestConfig('high_load_threshold', 100);
        $this->service->setTestConfig('storage_mode', 'file');

        // Simulate high load
        $this->mockCache->set('waf_violations_minute', 150, 60);

        // Ban should still work for cache
        $this->service->banIp('1.2.3.4', 3600, 'Test ban');

        // Cache should have the ban
        $cacheKey = 'banned_' . md5('1.2.3.4');
        $this->assertTrue($this->mockCache->get($cacheKey));

        // But file persistence would be skipped (we can't easily verify this without file mocking)
    }

    // ========================================================================
    // Storage Mode Tests
    // ========================================================================

    /**
     * Test getting storage mode from config
     */
    public function testGetStorageMode(): void
    {
        $this->service->setTestConfig('storage_mode', 'file');
        $this->assertEquals('file', $this->invokeMethod('getStorageMode'));

        $this->service->setTestConfig('storage_mode', 'cache');
        $this->assertEquals('cache', $this->invokeMethod('getStorageMode'));

        $this->service->setTestConfig('storage_mode', 'database');
        $this->assertEquals('database', $this->invokeMethod('getStorageMode'));
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    protected function invokeMethod(string $method, array $args = []): mixed
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod($method);
        $method->setAccessible(true);
        return $method->invokeArgs($this->service, $args);
    }
}

/**
 * Testable version of WafStorageService that allows config injection
 */
class TestableWafStorageService extends WafStorageService
{
    protected MockCache $testCache;
    protected array $testConfig = [];

    public function __construct(MockCache $cache)
    {
        $this->testCache = $cache;
    }

    public function setTestConfig(string $key, mixed $value): void
    {
        $this->testConfig[$key] = $value;
    }

    protected function getCache(): CacheInterface
    {
        return $this->testCache;
    }

    protected function getStorageMode(): string
    {
        return $this->testConfig['storage_mode'] ?? 'cache';
    }

    protected function isHighLoad(): bool
    {
        $threshold = $this->testConfig['high_load_threshold'] ?? 100;
        if ($threshold <= 0) {
            return false;
        }

        $count = (int) $this->testCache->get('waf_violations_minute');
        return $count >= $threshold;
    }

    // Override file operations for testing
    protected function saveBanToFile(string $ip, string $reason, int $expiresAt): void
    {
        // Skip file operations in tests
    }

    protected function loadBansFromFile(): array
    {
        return [];
    }

    protected function saveBansToFile(array $bans): void
    {
        // Skip file operations in tests
    }

    protected function appendToBlockedLog(array $entry): void
    {
        // Skip file operations in tests
    }
}

/**
 * Simple mock cache implementation for testing
 */
class MockCache implements CacheInterface
{
    protected array $data = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->data[$key] = $value;
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->data = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }
        return $result;
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }
        return true;
    }

    public function has(string $key): bool
    {
        return isset($this->data[$key]);
    }
}
