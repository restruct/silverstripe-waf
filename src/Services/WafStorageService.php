<?php

namespace Restruct\SilverStripe\Waf\Services;

use Psr\SimpleCache\CacheInterface;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Core\TempFolder;
use SilverStripe\ORM\ArrayList;
use SilverStripe\View\ArrayData;

/**
 * Hybrid storage service for WAF data
 *
 * Operates in three modes:
 * - 'cache': Pure cache, no DB, no file writes (fastest, data volatile)
 * - 'file': Cache + JSON file backup (admin can view, survives cache clear)
 * - 'database': Cache + DB persistence (full CMS admin, highest overhead)
 *
 * Under high load (attack), automatically falls back to cache-only.
 */
class WafStorageService
{
    use Configurable;
    use Injectable;

    // Storage mode: 'cache', 'file', or 'database'
    private static string $storage_mode = 'file';

    // File storage filenames (stored in TEMP_PATH, same as framework cache)
    private static string $blocked_log_file = 'waf_blocked.jsonl';
    private static string $bans_file = 'waf_bans.json';

    // Max entries to keep in log file
    private static int $max_log_entries = 1000;

    // High load threshold - if violations per minute exceed this, skip persistence
    private static int $high_load_threshold = 100;

    // ========================================================================
    // Ban Management
    // ========================================================================

    /**
     * Check if an IP is banned
     */
    public function isBanned(string $ip): bool
    {
        $cache = $this->getCache();
        $cacheKey = 'banned_' . md5($ip);

        // Cache is always checked first (fast)
        $cached = $cache->get($cacheKey);
        if ($cached !== null) {
            return (bool) $cached;
        }

        // In file mode, check bans file
        if ($this->getStorageMode() === 'file') {
            $bans = $this->loadBansFromFile();
            if (isset($bans[$ip]) && $bans[$ip]['expires'] > time()) {
                // Warm the cache
                $cache->set($cacheKey, true, $bans[$ip]['expires'] - time());
                return true;
            }
        }

        // In database mode, check DB
        if ($this->getStorageMode() === 'database') {
            return $this->checkBanInDatabase($ip, $cache, $cacheKey);
        }

        // Cache the negative result briefly to avoid repeated lookups
        $cache->set($cacheKey, false, 60);
        return false;
    }

    /**
     * Ban an IP address
     */
    public function banIp(string $ip, int $duration, string $reason): void
    {
        $cache = $this->getCache();
        $cacheKey = 'banned_' . md5($ip);
        $expiresAt = time() + $duration;

        // Always cache (primary storage)
        $cache->set($cacheKey, true, $duration);

        // Skip persistence under high load
        if ($this->isHighLoad()) {
            return;
        }

        $mode = $this->getStorageMode();

        if ($mode === 'file') {
            $this->saveBanToFile($ip, $reason, $expiresAt);
        } elseif ($mode === 'database') {
            $this->saveBanToDatabase($ip, $reason, $expiresAt);
        }
    }

    /**
     * Unban an IP address
     */
    public function unbanIp(string $ip): void
    {
        $cache = $this->getCache();
        $cacheKey = 'banned_' . md5($ip);

        // Clear from cache
        $cache->delete($cacheKey);

        $mode = $this->getStorageMode();

        if ($mode === 'file') {
            $bans = $this->loadBansFromFile();
            unset($bans[$ip]);
            $this->saveBansToFile($bans);
        } elseif ($mode === 'database') {
            $this->removeBanFromDatabase($ip);
        }
    }

    /**
     * Get all active bans (for admin display)
     */
    public function getActiveBans(): ArrayList
    {
        $list = ArrayList::create();
        $mode = $this->getStorageMode();

        if ($mode === 'file') {
            $bans = $this->loadBansFromFile();
            foreach ($bans as $ip => $data) {
                if ($data['expires'] > time()) {
                    $list->push(ArrayData::create([
                        'IpAddress' => $ip,
                        'Reason' => $data['reason'] ?? 'Unknown',
                        'ExpiresAt' => date('Y-m-d H:i:s', $data['expires']),
                        'CreatedAt' => date('Y-m-d H:i:s', $data['created'] ?? $data['expires']),
                    ]));
                }
            }
        } elseif ($mode === 'database') {
            // Delegate to existing model
            return $this->getBansFromDatabase();
        }

        return $list;
    }

    // ========================================================================
    // Blocked Request Logging
    // ========================================================================

    /**
     * Log a blocked request
     */
    public function logBlockedRequest(
        string $ip,
        string $uri,
        string $userAgent,
        string $reason,
        string $detail
    ): void {
        // Skip under high load
        if ($this->isHighLoad()) {
            return;
        }

        $mode = $this->getStorageMode();

        if ($mode === 'file') {
            $this->appendToBlockedLog([
                'timestamp' => time(),
                'datetime' => date('Y-m-d H:i:s'),
                'ip' => $ip,
                'uri' => substr($uri, 0, 255),
                'user_agent' => substr($userAgent, 0, 255),
                'reason' => $reason,
                'detail' => substr($detail, 0, 255),
            ]);
        } elseif ($mode === 'database') {
            $this->saveBlockedRequestToDatabase($ip, $uri, $userAgent, $reason, $detail);
        }
    }

    /**
     * Get blocked requests (for admin display)
     */
    public function getBlockedRequests(int $limit = 100): ArrayList
    {
        $list = ArrayList::create();
        $mode = $this->getStorageMode();

        if ($mode === 'file') {
            $entries = $this->readBlockedLog($limit);
            foreach ($entries as $entry) {
                $list->push(ArrayData::create([
                    'Created' => $entry['datetime'] ?? date('Y-m-d H:i:s', $entry['timestamp'] ?? 0),
                    'IpAddress' => $entry['ip'] ?? '',
                    'Uri' => $entry['uri'] ?? '',
                    'UserAgent' => $entry['user_agent'] ?? '',
                    'Reason' => $entry['reason'] ?? '',
                    'Detail' => $entry['detail'] ?? '',
                ]));
            }
        } elseif ($mode === 'database') {
            return $this->getBlockedRequestsFromDatabase($limit);
        }

        return $list;
    }

    // ========================================================================
    // File Storage Implementation
    // ========================================================================

    protected function getBansFilePath(): string
    {
        $filename = $this->config()->get('bans_file');
        if ($filename[0] === '/') {
            return $filename; // Absolute path
        }
        return TempFolder::getTempFolder(BASE_PATH) . '/' . $filename;
    }

    protected function getBlockedLogPath(): string
    {
        $filename = $this->config()->get('blocked_log_file');
        if ($filename[0] === '/') {
            return $filename; // Absolute path
        }
        return TempFolder::getTempFolder(BASE_PATH) . '/' . $filename;
    }

    protected function loadBansFromFile(): array
    {
        $path = $this->getBansFilePath();
        if (!file_exists($path)) {
            return [];
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            return [];
        }

        $data = json_decode($content, true);
        return is_array($data) ? $data : [];
    }

    protected function saveBansToFile(array $bans): void
    {
        $path = $this->getBansFilePath();
        $dir = dirname($path);

        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        // Clean expired bans
        $bans = array_filter($bans, fn($ban) => ($ban['expires'] ?? 0) > time());

        @file_put_contents($path, json_encode($bans, JSON_PRETTY_PRINT), LOCK_EX);
    }

    protected function saveBanToFile(string $ip, string $reason, int $expiresAt): void
    {
        $bans = $this->loadBansFromFile();
        $bans[$ip] = [
            'reason' => $reason,
            'expires' => $expiresAt,
            'created' => time(),
        ];
        $this->saveBansToFile($bans);
    }

    protected function appendToBlockedLog(array $entry): void
    {
        $path = $this->getBlockedLogPath();
        $dir = dirname($path);

        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        // Append as JSONL (one JSON object per line)
        @file_put_contents($path, json_encode($entry) . "\n", FILE_APPEND | LOCK_EX);

        // Rotate if too large (simple approach: truncate)
        $this->rotateBlockedLogIfNeeded($path);
    }

    protected function rotateBlockedLogIfNeeded(string $path): void
    {
        $maxEntries = $this->config()->get('max_log_entries');

        // Check file size as proxy for entry count (rough estimate)
        $size = @filesize($path);
        if ($size === false || $size < $maxEntries * 200) {
            return; // Assume ~200 bytes per entry
        }

        // Read all, keep last N entries
        $entries = $this->readBlockedLog($maxEntries);
        $content = implode("\n", array_map('json_encode', $entries)) . "\n";
        @file_put_contents($path, $content, LOCK_EX);
    }

    protected function readBlockedLog(int $limit = 100): array
    {
        $path = $this->getBlockedLogPath();
        if (!file_exists($path)) {
            return [];
        }

        $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return [];
        }

        // Get last N entries (most recent first)
        $lines = array_slice($lines, -$limit);
        $lines = array_reverse($lines);

        $entries = [];
        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if ($entry) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    // ========================================================================
    // Database Storage Implementation
    // ========================================================================

    protected function checkBanInDatabase(string $ip, CacheInterface $cache, string $cacheKey): bool
    {
        // Only import if needed to avoid autoload overhead
        $banClass = 'Restruct\\SilverStripe\\Waf\\Models\\BannedIp';
        if (!class_exists($banClass)) {
            return false;
        }

        $ban = $banClass::get()->filter([
            'IpAddress' => $ip,
            'ExpiresAt:GreaterThan' => date('Y-m-d H:i:s'),
        ])->first();

        if ($ban) {
            $ttl = strtotime($ban->ExpiresAt) - time();
            if ($ttl > 0) {
                $cache->set($cacheKey, true, $ttl);
            }
            return true;
        }

        return false;
    }

    protected function saveBanToDatabase(string $ip, string $reason, int $expiresAt): void
    {
        $banClass = 'Restruct\\SilverStripe\\Waf\\Models\\BannedIp';
        if (!class_exists($banClass)) {
            return;
        }

        try {
            $ban = $banClass::create();
            $ban->IpAddress = $ip;
            $ban->Reason = $reason;
            $ban->ExpiresAt = date('Y-m-d H:i:s', $expiresAt);
            $ban->write();
        } catch (\Exception $e) {
            // Ignore DB errors
        }
    }

    protected function removeBanFromDatabase(string $ip): void
    {
        $banClass = 'Restruct\\SilverStripe\\Waf\\Models\\BannedIp';
        if (!class_exists($banClass)) {
            return;
        }

        try {
            $bans = $banClass::get()->filter('IpAddress', $ip);
            foreach ($bans as $ban) {
                $ban->delete();
            }
        } catch (\Exception $e) {
            // Ignore DB errors
        }
    }

    protected function getBansFromDatabase(): ArrayList
    {
        $banClass = 'Restruct\\SilverStripe\\Waf\\Models\\BannedIp';
        if (!class_exists($banClass)) {
            return ArrayList::create();
        }

        return $banClass::get()->filterAny([
            'IsPermanent' => true,
            'ExpiresAt:GreaterThan' => date('Y-m-d H:i:s'),
        ]);
    }

    protected function saveBlockedRequestToDatabase(
        string $ip,
        string $uri,
        string $userAgent,
        string $reason,
        string $detail
    ): void {
        $logClass = 'Restruct\\SilverStripe\\Waf\\Models\\BlockedRequest';
        if (!class_exists($logClass)) {
            return;
        }

        try {
            $log = $logClass::create();
            $log->IpAddress = $ip;
            $log->Uri = substr($uri, 0, 255);
            $log->UserAgent = substr($userAgent, 0, 255);
            $log->Reason = $reason;
            $log->Detail = substr($detail, 0, 255);
            $log->write();
        } catch (\Exception $e) {
            // Ignore DB errors
        }
    }

    protected function getBlockedRequestsFromDatabase(int $limit): ArrayList
    {
        $logClass = 'Restruct\\SilverStripe\\Waf\\Models\\BlockedRequest';
        if (!class_exists($logClass)) {
            return ArrayList::create();
        }

        return $logClass::get()->sort('Created', 'DESC')->limit($limit);
    }

    // ========================================================================
    // High Load Detection
    // ========================================================================

    /**
     * Check if we're under high load (likely attack)
     *
     * When true, skip all persistence to maintain performance
     */
    protected function isHighLoad(): bool
    {
        $threshold = $this->config()->get('high_load_threshold');
        if ($threshold <= 0) {
            return false; // Disabled
        }

        $cache = $this->getCache();
        $count = (int) $cache->get('waf_violations_minute');

        return $count >= $threshold;
    }

    /**
     * Increment violation counter (called by middleware)
     */
    public function recordViolation(): void
    {
        $cache = $this->getCache();
        $key = 'waf_violations_minute';
        $count = (int) $cache->get($key);
        $cache->set($key, $count + 1, 60);
    }

    // ========================================================================
    // Privileged IP Cache
    // ========================================================================

    /**
     * Invalidate the cached merged privileged IP list
     *
     * Called by PrivilegedIp::onAfterWrite() and onAfterDelete()
     * to ensure changes take effect immediately.
     */
    public function invalidatePrivilegedIpCache(): void
    {
        $this->getCache()->delete('privileged_ips_merged');
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    /**
     * Clean up expired bans (for scheduled maintenance)
     */
    public function cleanupExpiredBans(): int
    {
        $mode = $this->getStorageMode();
        $removed = 0;

        if ($mode === 'file') {
            $bans = $this->loadBansFromFile();
            $originalCount = count($bans);
            $bans = array_filter($bans, fn($ban) => ($ban['expires'] ?? 0) > time());
            $removed = $originalCount - count($bans);
            if ($removed > 0) {
                $this->saveBansToFile($bans);
            }
        } elseif ($mode === 'database') {
            $banClass = 'Restruct\\SilverStripe\\Waf\\Models\\BannedIp';
            if (class_exists($banClass)) {
                try {
                    $expired = $banClass::get()->filter([
                        'IsPermanent' => false,
                        'ExpiresAt:LessThan' => date('Y-m-d H:i:s'),
                    ]);
                    $removed = $expired->count();
                    foreach ($expired as $ban) {
                        $ban->delete();
                    }
                } catch (\Exception $e) {
                    // Ignore DB errors
                }
            }
        }

        return $removed;
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    protected function getStorageMode(): string
    {
        // Environment override
        $envMode = Environment::getEnv('WAF_STORAGE_MODE');
        if ($envMode) {
            return $envMode;
        }

        return $this->config()->get('storage_mode');
    }

    protected function getCache(): CacheInterface
    {
        return Injector::inst()->get(CacheInterface::class . '.Waf');
    }
}
