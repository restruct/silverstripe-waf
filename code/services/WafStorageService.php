<?php

/**
 * Hybrid storage service for WAF data
 *
 * Operates in three modes:
 * - 'cache': Pure cache, no DB, no file writes (fastest, data volatile)
 * - 'file': Cache + JSON file backup (admin can view, survives cache clear)
 * - 'database': Cache + DB persistence (full CMS admin, highest overhead)
 *
 * Under high load (attack), automatically falls back to cache-only.
 *
 * SS3 backport: uses SS_Cache (Zend_Cache) instead of PSR SimpleCache.
 */
class WafStorageService extends SS_Object
{
    // Storage mode: 'cache', 'file', or 'database'
    private static $storage_mode = 'file';

    // File storage filenames (stored in TEMP_FOLDER, same as framework cache)
    private static $blocked_log_file = 'waf_blocked.jsonl';
    private static $bans_file = 'waf_bans.json';

    // Max entries to keep in log file
    private static $max_log_entries = 1000;

    // High load threshold - if violations per minute exceed this, skip persistence
    private static $high_load_threshold = 100;

    // ========================================================================
    // Ban Management
    // ========================================================================

    /**
     * Check if an IP is banned
     *
     * @param string $ip
     * @return bool
     */
    public function isBanned($ip)
    {
        $cache = $this->getCache();
        $cacheKey = 'banned_' . md5($ip);

        // Cache is always checked first (fast)
        $cached = $cache->load($cacheKey);
        if ($cached !== false) {
            return (bool) $cached;
        }

        // In file mode, check bans file
        if ($this->getStorageMode() === 'file') {
            $bans = $this->loadBansFromFile();
            if (isset($bans[$ip]) && $bans[$ip]['expires'] > time()) {
                // Warm the cache
                $cache->save('1', $cacheKey, array(), $bans[$ip]['expires'] - time());
                return true;
            }
        }

        // In database mode, check DB
        if ($this->getStorageMode() === 'database') {
            return $this->checkBanInDatabase($ip, $cache, $cacheKey);
        }

        // Cache the negative result briefly to avoid repeated lookups
        $cache->save('0', $cacheKey, array(), 60);
        return false;
    }

    /**
     * Ban an IP address
     *
     * @param string $ip
     * @param int $duration Seconds
     * @param string $reason
     */
    public function banIp($ip, $duration, $reason)
    {
        $cache = $this->getCache();
        $cacheKey = 'banned_' . md5($ip);
        $expiresAt = time() + $duration;

        // Always cache (primary storage)
        $cache->save('1', $cacheKey, array(), $duration);

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
     *
     * @param string $ip
     */
    public function unbanIp($ip)
    {
        $cache = $this->getCache();
        $cacheKey = 'banned_' . md5($ip);

        // Clear from cache
        $cache->remove($cacheKey);

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
     *
     * @return ArrayList
     */
    public function getActiveBans()
    {
        $list = ArrayList::create();
        $mode = $this->getStorageMode();

        if ($mode === 'file') {
            $bans = $this->loadBansFromFile();
            foreach ($bans as $ip => $data) {
                if ($data['expires'] > time()) {
                    $list->push(ArrayData::create(array(
                        'IpAddress' => $ip,
                        'Reason' => isset($data['reason']) ? $data['reason'] : 'Unknown',
                        'ExpiresAt' => date('Y-m-d H:i:s', $data['expires']),
                        'CreatedAt' => date('Y-m-d H:i:s', isset($data['created']) ? $data['created'] : $data['expires']),
                    )));
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
     *
     * @param string $ip
     * @param string $uri
     * @param string $userAgent
     * @param string $reason
     * @param string $detail
     */
    public function logBlockedRequest($ip, $uri, $userAgent, $reason, $detail)
    {
        // Skip under high load
        if ($this->isHighLoad()) {
            return;
        }

        $mode = $this->getStorageMode();

        if ($mode === 'file') {
            $this->appendToBlockedLog(array(
                'timestamp' => time(),
                'datetime' => date('Y-m-d H:i:s'),
                'ip' => $ip,
                'uri' => substr($uri, 0, 255),
                'user_agent' => substr($userAgent, 0, 255),
                'reason' => $reason,
                'detail' => substr($detail, 0, 255),
            ));
        } elseif ($mode === 'database') {
            $this->saveBlockedRequestToDatabase($ip, $uri, $userAgent, $reason, $detail);
        }
    }

    /**
     * Get blocked requests (for admin display)
     *
     * @param int $limit
     * @return ArrayList
     */
    public function getBlockedRequests($limit = 100)
    {
        $list = ArrayList::create();
        $mode = $this->getStorageMode();

        if ($mode === 'file') {
            $entries = $this->readBlockedLog($limit);
            foreach ($entries as $entry) {
                $list->push(ArrayData::create(array(
                    'Created' => isset($entry['datetime']) ? $entry['datetime'] : date('Y-m-d H:i:s', isset($entry['timestamp']) ? $entry['timestamp'] : 0),
                    'IpAddress' => isset($entry['ip']) ? $entry['ip'] : '',
                    'Uri' => isset($entry['uri']) ? $entry['uri'] : '',
                    'UserAgent' => isset($entry['user_agent']) ? $entry['user_agent'] : '',
                    'Reason' => isset($entry['reason']) ? $entry['reason'] : '',
                    'Detail' => isset($entry['detail']) ? $entry['detail'] : '',
                )));
            }
        } elseif ($mode === 'database') {
            return $this->getBlockedRequestsFromDatabase($limit);
        }

        return $list;
    }

    // ========================================================================
    // File Storage Implementation
    // ========================================================================

    /**
     * @return string
     */
    protected function getBansFilePath()
    {
        $filename = $this->config()->get('bans_file');
        if ($filename[0] === '/') {
            return $filename; # Absolute path
        }
        return TEMP_FOLDER . '/' . $filename;
    }

    /**
     * @return string
     */
    protected function getBlockedLogPath()
    {
        $filename = $this->config()->get('blocked_log_file');
        if ($filename[0] === '/') {
            return $filename; # Absolute path
        }
        return TEMP_FOLDER . '/' . $filename;
    }

    /**
     * @return array
     */
    protected function loadBansFromFile()
    {
        $path = $this->getBansFilePath();
        if (!file_exists($path)) {
            return array();
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            return array();
        }

        $data = json_decode($content, true);
        return is_array($data) ? $data : array();
    }

    /**
     * @param array $bans
     */
    protected function saveBansToFile($bans)
    {
        $path = $this->getBansFilePath();
        $dir = dirname($path);

        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        // Clean expired bans
        $bans = array_filter($bans, fn($ban) => (isset($ban['expires']) ? $ban['expires'] : 0) > time());

        @file_put_contents($path, json_encode($bans, JSON_PRETTY_PRINT), LOCK_EX);
    }

    /**
     * @param string $ip
     * @param string $reason
     * @param int $expiresAt
     */
    protected function saveBanToFile($ip, $reason, $expiresAt)
    {
        $bans = $this->loadBansFromFile();
        $bans[$ip] = array(
            'reason' => $reason,
            'expires' => $expiresAt,
            'created' => time(),
        );
        $this->saveBansToFile($bans);
    }

    /**
     * @param array $entry
     */
    protected function appendToBlockedLog($entry)
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

    /**
     * @param string $path
     */
    protected function rotateBlockedLogIfNeeded($path)
    {
        $maxEntries = $this->config()->get('max_log_entries');

        // Check file size as proxy for entry count (rough estimate)
        $size = @filesize($path);
        if ($size === false || $size < $maxEntries * 200) {
            return; # Assume ~200 bytes per entry
        }

        // Read all, keep last N entries
        $entries = $this->readBlockedLog($maxEntries);
        $content = implode("\n", array_map('json_encode', $entries)) . "\n";
        @file_put_contents($path, $content, LOCK_EX);
    }

    /**
     * @param int $limit
     * @return array
     */
    protected function readBlockedLog($limit = 100)
    {
        $path = $this->getBlockedLogPath();
        if (!file_exists($path)) {
            return array();
        }

        $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return array();
        }

        // Get last N entries (most recent first)
        $lines = array_slice($lines, -$limit);
        $lines = array_reverse($lines);

        $entries = array();
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

    /**
     * @param string $ip
     * @param Zend_Cache_Core $cache
     * @param string $cacheKey
     * @return bool
     */
    protected function checkBanInDatabase($ip, $cache, $cacheKey)
    {
        if (!class_exists('WafBannedIp')) {
            return false;
        }

        $ban = WafBannedIp::get()->filter(array(
            'IpAddress' => $ip,
            'ExpiresAt:GreaterThan' => date('Y-m-d H:i:s'),
        ))->first();

        if ($ban) {
            $ttl = strtotime($ban->ExpiresAt) - time();
            if ($ttl > 0) {
                $cache->save('1', $cacheKey, array(), $ttl);
            }
            return true;
        }

        return false;
    }

    /**
     * @param string $ip
     * @param string $reason
     * @param int $expiresAt
     */
    protected function saveBanToDatabase($ip, $reason, $expiresAt)
    {
        if (!class_exists('WafBannedIp')) {
            return;
        }

        try {
            $ban = WafBannedIp::create();
            $ban->IpAddress = $ip;
            $ban->Reason = $reason;
            $ban->ExpiresAt = date('Y-m-d H:i:s', $expiresAt);
            $ban->write();
        } catch (Exception $e) {
            // Ignore DB errors
        }
    }

    /**
     * @param string $ip
     */
    protected function removeBanFromDatabase($ip)
    {
        if (!class_exists('WafBannedIp')) {
            return;
        }

        try {
            $bans = WafBannedIp::get()->filter('IpAddress', $ip);
            foreach ($bans as $ban) {
                $ban->delete();
            }
        } catch (Exception $e) {
            // Ignore DB errors
        }
    }

    /**
     * @return ArrayList|DataList
     */
    protected function getBansFromDatabase()
    {
        if (!class_exists('WafBannedIp')) {
            return ArrayList::create();
        }

        return WafBannedIp::get()->filterAny(array(
            'IsPermanent' => true,
            'ExpiresAt:GreaterThan' => date('Y-m-d H:i:s'),
        ));
    }

    /**
     * @param string $ip
     * @param string $uri
     * @param string $userAgent
     * @param string $reason
     * @param string $detail
     */
    protected function saveBlockedRequestToDatabase($ip, $uri, $userAgent, $reason, $detail)
    {
        if (!class_exists('WafBlockedRequest')) {
            return;
        }

        try {
            $log = WafBlockedRequest::create();
            $log->IpAddress = $ip;
            $log->Uri = substr($uri, 0, 255);
            $log->UserAgent = substr($userAgent, 0, 255);
            $log->Reason = $reason;
            $log->Detail = substr($detail, 0, 255);
            $log->write();
        } catch (Exception $e) {
            // Ignore DB errors
        }
    }

    /**
     * @param int $limit
     * @return ArrayList|DataList
     */
    protected function getBlockedRequestsFromDatabase($limit)
    {
        if (!class_exists('WafBlockedRequest')) {
            return ArrayList::create();
        }

        return WafBlockedRequest::get()->sort('Created', 'DESC')->limit($limit);
    }

    // ========================================================================
    // High Load Detection
    // ========================================================================

    /**
     * Check if we're under high load (likely attack)
     *
     * When true, skip all persistence to maintain performance
     *
     * @return bool
     */
    protected function isHighLoad()
    {
        $threshold = $this->config()->get('high_load_threshold');
        if ($threshold <= 0) {
            return false; # Disabled
        }

        $cache = $this->getCache();
        $count = $cache->load('waf_violations_minute');

        return $count !== false && (int) $count >= $threshold;
    }

    /**
     * Increment violation counter (called by request filter)
     */
    public function recordViolation()
    {
        $cache = $this->getCache();
        $key = 'waf_violations_minute';
        $count = $cache->load($key);
        $count = ($count !== false) ? (int) $count : 0;
        $cache->save((string) ($count + 1), $key, array(), 60);
    }

    // ========================================================================
    // Privileged IP Cache
    // ========================================================================

    /**
     * Invalidate the cached merged privileged IP list
     *
     * Called by WafPrivilegedIp::onAfterWrite() and onAfterDelete()
     * to ensure changes take effect immediately.
     */
    public function invalidatePrivilegedIpCache()
    {
        $this->getCache()->remove('privileged_ips_merged');
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    /**
     * Clean up expired bans (for scheduled maintenance)
     *
     * @return int Number of removed bans
     */
    public function cleanupExpiredBans()
    {
        $mode = $this->getStorageMode();
        $removed = 0;

        if ($mode === 'file') {
            $bans = $this->loadBansFromFile();
            $originalCount = count($bans);
            $bans = array_filter($bans, fn($ban) => (isset($ban['expires']) ? $ban['expires'] : 0) > time());
            $removed = $originalCount - count($bans);
            if ($removed > 0) {
                $this->saveBansToFile($bans);
            }
        } elseif ($mode === 'database') {
            if (class_exists('WafBannedIp')) {
                try {
                    $expired = WafBannedIp::get()->filter(array(
                        'IsPermanent' => false,
                        'ExpiresAt:LessThan' => date('Y-m-d H:i:s'),
                    ));
                    $removed = $expired->count();
                    foreach ($expired as $ban) {
                        $ban->delete();
                    }
                } catch (Exception $e) {
                    // Ignore DB errors
                }
            }
        }

        return $removed;
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    /**
     * @return string
     */
    protected function getStorageMode()
    {
        // Environment override
        $envMode = getenv('WAF_STORAGE_MODE');
        if ($envMode) {
            return $envMode;
        }

        return $this->config()->get('storage_mode');
    }

    /**
     * Get SS3 cache backend (Zend_Cache_Core)
     *
     * @return Zend_Cache_Core
     */
    protected function getCache()
    {
        return SS_Cache::factory('waf');
    }
}
