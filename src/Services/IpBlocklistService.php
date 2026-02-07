<?php

namespace Restruct\SilverStripe\Waf\Services;

use Psr\SimpleCache\CacheInterface;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;

/**
 * Service for checking IPs against threat intelligence blocklists
 *
 * Supports multiple blocklist sources:
 * - FireHOL IP lists
 * - Binary Defense ban list
 * - Spamhaus DROP
 * - Local custom blocklist
 *
 * Performance optimizations:
 * - Direct IP lookup via hash table: O(1)
 * - CIDR ranges converted to sorted IP ranges for binary search: O(log n)
 * - Per-IP result caching to skip repeated lookups for same visitor
 */
class IpBlocklistService
{
    use Configurable;
    use Injectable;

    private static bool $sync_enabled = true;
    private static int $cache_duration = 3600;
    private static array $blocklist_sources = [];
    private static ?string $local_blocklist_file = null;

    /**
     * How long to cache per-IP "is blocked" results (seconds)
     * Reduces repeated CIDR lookups for the same visitor
     */
    private static int $ip_result_cache_duration = 60;

    protected ?array $loadedBlocklist = null;

    /**
     * Check if an IP is on any blocklist
     *
     * Uses multi-tier caching:
     * 1. Per-IP result cache (fastest - skips all lookups)
     * 2. Direct IP hash lookup (fast)
     * 3. Binary search through sorted IP ranges (O(log n) vs O(n))
     */
    public function isBlocked(string $ip): bool
    {
        if (!$this->config()->get('sync_enabled')) {
            return false;
        }

        // Optimization 1: Check per-IP result cache first
        $cache = $this->getCache();
        $resultKey = 'ip_blocked_' . md5($ip);
        $cachedResult = $cache->get($resultKey);

        if ($cachedResult !== null) {
            return $cachedResult === 'yes';
        }

        // Perform the actual lookup
        $isBlocked = $this->performBlocklistCheck($ip);

        // Cache the result for this IP
        $cache->set(
            $resultKey,
            $isBlocked ? 'yes' : 'no',
            $this->config()->get('ip_result_cache_duration')
        );

        return $isBlocked;
    }

    /**
     * Perform the actual blocklist check (without result caching)
     */
    protected function performBlocklistCheck(string $ip): bool
    {
        $blocklist = $this->getBlocklist();

        if (empty($blocklist)) {
            return false;
        }

        // Check direct IP match first (O(1) hash lookup)
        if (isset($blocklist['ips'][$ip])) {
            return true;
        }

        // Check IP ranges using binary search (O(log n))
        if (!empty($blocklist['ranges'])) {
            return $this->ipInRanges($ip, $blocklist['ranges']);
        }

        // Fallback: linear CIDR check (for backwards compatibility)
        foreach ($blocklist['cidrs'] ?? [] as $cidr) {
            if ($this->ipInCidr($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Binary search through sorted IP ranges
     *
     * Ranges are stored as [start_long, end_long] pairs, sorted by start.
     * This reduces O(n) linear scan to O(log n) binary search.
     */
    protected function ipInRanges(string $ip, array $ranges): bool
    {
        // Only IPv4 supported for range search (IPv6 would need different handling)
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return false;
        }

        // Convert to unsigned for proper comparison
        $ipLong = sprintf('%u', $ipLong);

        // Binary search: find the last range where start <= ip
        // Cast to int for proper numeric comparison (64-bit PHP handles IPv4 range easily)
        $ipInt = (int) $ipLong;
        $left = 0;
        $right = count($ranges) - 1;

        while ($left <= $right) {
            $mid = (int) (($left + $right) / 2);
            $rangeStart = (int) $ranges[$mid][0];
            $rangeEnd = (int) $ranges[$mid][1];

            if ($ipInt >= $rangeStart && $ipInt <= $rangeEnd) {
                return true; // IP is within this range
            }

            if ($ipInt < $rangeStart) {
                $right = $mid - 1;
            } else {
                $left = $mid + 1;
            }
        }

        return false;
    }

    /**
     * Get the combined blocklist (from cache or sync)
     *
     * Uses chunked storage to handle large blocklists within Memcached limits.
     * Metadata is stored in one key, CIDR chunks in separate keys.
     */
    public function getBlocklist(): array
    {
        if ($this->loadedBlocklist !== null) {
            return $this->loadedBlocklist;
        }

        $cache = $this->getCache();

        // Load metadata
        $meta = $cache->get('blocklist_meta');
        if ($meta === null) {
            // Need to sync
            $blocklist = $this->syncBlocklists();
            $this->loadedBlocklist = $blocklist;
            return $blocklist;
        }

        // Load IPs (stored as associative array for fast lookup)
        $ips = $cache->get('blocklist_ips') ?: [];

        // Load IP ranges (optimized binary-searchable format)
        $ranges = $cache->get('blocklist_ranges') ?: [];

        // Load CIDR chunks (fallback for IPv6 or if ranges failed)
        $cidrs = [];
        $chunkCount = $meta['cidr_chunks'] ?? 0;
        for ($i = 0; $i < $chunkCount; $i++) {
            $chunk = $cache->get("blocklist_cidrs_{$i}");
            if ($chunk) {
                $cidrs = array_merge($cidrs, $chunk);
            }
        }

        $this->loadedBlocklist = [
            'ips' => $ips,
            'cidrs' => $cidrs,
            'ranges' => $ranges,
            'synced_at' => $meta['synced_at'] ?? null,
            'sources' => $meta['sources'] ?? [],
        ];

        return $this->loadedBlocklist;
    }

    /**
     * Force sync all blocklists
     *
     * Stores data in chunks to work within Memcached size limits:
     * - blocklist_meta: Metadata and stats
     * - blocklist_ips: IP lookup table (usually small enough for one key)
     * - blocklist_ranges: Sorted IP ranges for binary search
     * - blocklist_cidrs_N: CIDR ranges in chunks of 500 (fallback)
     */
    public function syncBlocklists(): array
    {
        $combined = [
            'ips' => [],
            'cidrs' => [],
            'ranges' => [],
            'synced_at' => time(),
            'sources' => [],
        ];

        $sources = $this->config()->get('blocklist_sources') ?: [];

        foreach ($sources as $name => $config) {
            if (!($config['enabled'] ?? false)) {
                continue;
            }

            try {
                $result = $this->fetchBlocklist($config['url'], $config['format'] ?? 'ip');

                $combined['ips'] = array_merge($combined['ips'], $result['ips']);
                $combined['cidrs'] = array_merge($combined['cidrs'], $result['cidrs']);
                $combined['sources'][$name] = [
                    'url' => $config['url'],
                    'count' => count($result['ips']) + count($result['cidrs']),
                    'synced_at' => time(),
                ];
            } catch (\Exception $e) {
                $combined['sources'][$name] = [
                    'url' => $config['url'],
                    'error' => $e->getMessage(),
                    'synced_at' => time(),
                ];
            }
        }

        // Load local blocklist if configured
        $localFile = $this->config()->get('local_blocklist_file');
        if ($localFile && file_exists($localFile)) {
            $result = $this->parseBlocklistFile(file_get_contents($localFile), 'cidr');
            $combined['ips'] = array_merge($combined['ips'], $result['ips']);
            $combined['cidrs'] = array_merge($combined['cidrs'], $result['cidrs']);
            $combined['sources']['local'] = [
                'file' => $localFile,
                'count' => count($result['ips']) + count($result['cidrs']),
            ];
        }

        // Convert IPs array to associative for fast lookup
        $combined['ips'] = array_fill_keys($combined['ips'], true);

        // Remove duplicate CIDRs
        $combined['cidrs'] = array_unique(array_values($combined['cidrs']));

        // Optimization 2: Convert CIDRs to sorted IP ranges for binary search
        $combined['ranges'] = $this->cidrsToSortedRanges($combined['cidrs']);

        // Store in cache with chunking for large data
        $this->storeBlocklistInCache($combined);

        return $combined;
    }

    /**
     * Convert CIDR list to sorted IP ranges for O(log n) binary search
     *
     * Only processes IPv4 CIDRs. IPv6 falls back to linear CIDR matching.
     *
     * @param array $cidrs List of CIDR strings (e.g., "192.168.1.0/24")
     * @return array Sorted array of [start_long, end_long] pairs
     */
    protected function cidrsToSortedRanges(array $cidrs): array
    {
        $ranges = [];

        foreach ($cidrs as $cidr) {
            if (!str_contains($cidr, '/')) {
                continue;
            }

            [$subnet, $bits] = explode('/', $cidr);
            $bits = (int) $bits;

            // Only handle IPv4 for range optimization
            if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                continue;
            }

            $subnetLong = ip2long($subnet);
            if ($subnetLong === false) {
                continue;
            }

            // Calculate range: apply mask to get start, invert mask for end
            $mask = $bits === 0 ? 0 : (~0 << (32 - $bits));
            $start = $subnetLong & $mask;
            $end = $subnetLong | (~$mask & 0xFFFFFFFF);

            // Store as unsigned strings for proper comparison
            $ranges[] = [
                sprintf('%u', $start),
                sprintf('%u', $end),
            ];
        }

        // Sort by range start for binary search (numeric comparison required)
        usort($ranges, fn($a, $b) => (int) $a[0] <=> (int) $b[0]);

        // Merge overlapping ranges to reduce list size
        return $this->mergeOverlappingRanges($ranges);
    }

    /**
     * Merge overlapping or adjacent IP ranges
     *
     * Reduces the number of ranges to search through.
     */
    protected function mergeOverlappingRanges(array $ranges): array
    {
        if (empty($ranges)) {
            return [];
        }

        $merged = [$ranges[0]];

        for ($i = 1; $i < count($ranges); $i++) {
            $last = &$merged[count($merged) - 1];
            $current = $ranges[$i];

            // If current range overlaps or is adjacent to last, merge them
            // Use int comparison (64-bit PHP handles IPv4 range easily, no bcmath needed)
            if ((int) $current[0] <= (int) $last[1] + 1) {
                // Keep the larger end value
                if ((int) $current[1] > (int) $last[1]) {
                    $last[1] = $current[1];
                }
            } else {
                $merged[] = $current;
            }
        }

        return $merged;
    }

    /**
     * Store blocklist in cache with chunking for Memcached compatibility
     */
    protected function storeBlocklistInCache(array $blocklist): void
    {
        $cache = $this->getCache();
        $ttl = $this->config()->get('cache_duration');

        // Store IPs (usually fits in one key, but could be chunked if needed)
        $cache->set('blocklist_ips', $blocklist['ips'], $ttl);

        // Store optimized IP ranges for binary search
        $cache->set('blocklist_ranges', $blocklist['ranges'], $ttl);

        // Chunk CIDRs (500 per chunk ~= 20-50KB, well under 1MB limit)
        // Keep CIDRs as fallback for IPv6
        $cidrChunks = array_chunk($blocklist['cidrs'], 500);
        foreach ($cidrChunks as $i => $chunk) {
            $cache->set("blocklist_cidrs_{$i}", $chunk, $ttl);
        }

        // Store metadata
        $meta = [
            'synced_at' => $blocklist['synced_at'],
            'sources' => $blocklist['sources'],
            'total_ips' => count($blocklist['ips']),
            'total_cidrs' => count($blocklist['cidrs']),
            'total_ranges' => count($blocklist['ranges']),
            'cidr_chunks' => count($cidrChunks),
        ];
        $cache->set('blocklist_meta', $meta, $ttl);
    }

    /**
     * Fetch and parse a remote blocklist
     */
    protected function fetchBlocklist(string $url, string $format): array
    {
        $content = $this->fetchUrl($url);

        if ($content === false) {
            throw new \RuntimeException("Failed to fetch blocklist from: {$url}");
        }

        return $this->parseBlocklistFile($content, $format);
    }

    /**
     * Fetch URL content using cURL (preferred) or file_get_contents (fallback)
     */
    protected function fetchUrl(string $url): string|false
    {
        // Prefer cURL - more universally available than allow_url_fopen
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_USERAGENT => 'Silverstripe-WAF/1.0',
                CURLOPT_SSL_VERIFYPEER => true,
            ]);

            $content = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            curl_close($ch);

            if ($content !== false && $httpCode >= 200 && $httpCode < 300) {
                return $content;
            }

            // Log cURL failure, try fallback
            error_log("[WAF] cURL fetch failed for {$url}: HTTP {$httpCode} - {$error}");
        }

        // Fallback to file_get_contents (requires allow_url_fopen=On)
        if (ini_get('allow_url_fopen')) {
            $context = stream_context_create([
                'http' => [
                    'timeout' => 30,
                    'user_agent' => 'Silverstripe-WAF/1.0',
                ],
            ]);

            return @file_get_contents($url, false, $context);
        }

        return false;
    }

    /**
     * Parse blocklist content based on format
     */
    protected function parseBlocklistFile(string $content, string $format): array
    {
        $ips = [];
        $cidrs = [];

        $lines = explode("\n", $content);

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip comments and empty lines
            if (empty($line) || $line[0] === '#') {
                continue;
            }

            // Handle different formats
            switch ($format) {
                case 'cidr':
                    // One CIDR or IP per line
                    if (str_contains($line, '/')) {
                        $cidrs[] = $line;
                    } elseif (filter_var($line, FILTER_VALIDATE_IP)) {
                        $ips[] = $line;
                    }
                    break;

                case 'ip':
                    // One IP per line
                    if (filter_var($line, FILTER_VALIDATE_IP)) {
                        $ips[] = $line;
                    }
                    break;

                case 'cidr_semicolon':
                    // CIDR ; comment (Spamhaus format)
                    $parts = explode(';', $line);
                    $entry = trim($parts[0]);
                    if (str_contains($entry, '/')) {
                        $cidrs[] = $entry;
                    } elseif (filter_var($entry, FILTER_VALIDATE_IP)) {
                        $ips[] = $entry;
                    }
                    break;
            }
        }

        return [
            'ips' => $ips,
            'cidrs' => $cidrs,
        ];
    }

    /**
     * Check if an IP is within a CIDR range (linear fallback for IPv6)
     */
    protected function ipInCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr);
        $bits = (int) $bits;

        // Handle IPv4
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return false;
            }

            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $mask = -1 << (32 - $bits);

            return ($ipLong & $mask) === ($subnetLong & $mask);
        }

        // Handle IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return false;
            }

            $ipBin = inet_pton($ip);
            $subnetBin = inet_pton($subnet);

            if ($ipBin === false || $subnetBin === false) {
                return false;
            }

            // Build the mask
            $mask = str_repeat('f', (int) ($bits / 4));
            $remainder = $bits % 4;
            if ($remainder) {
                $mask .= dechex(0xf << (4 - $remainder));
            }
            $mask = str_pad($mask, 32, '0');
            $maskBin = pack('H*', $mask);

            return ($ipBin & $maskBin) === ($subnetBin & $maskBin);
        }

        return false;
    }

    /**
     * Get blocklist statistics
     */
    public function getStats(): array
    {
        $cache = $this->getCache();

        // Try to get stats from metadata (fast, no full load)
        $meta = $cache->get('blocklist_meta');
        if ($meta) {
            return [
                'total_ips' => $meta['total_ips'] ?? 0,
                'total_cidrs' => $meta['total_cidrs'] ?? 0,
                'total_ranges' => $meta['total_ranges'] ?? 0,
                'synced_at' => $meta['synced_at'] ?? null,
                'sources' => $meta['sources'] ?? [],
            ];
        }

        // Fallback to full load
        $blocklist = $this->getBlocklist();

        return [
            'total_ips' => count($blocklist['ips'] ?? []),
            'total_cidrs' => count($blocklist['cidrs'] ?? []),
            'total_ranges' => count($blocklist['ranges'] ?? []),
            'synced_at' => $blocklist['synced_at'] ?? null,
            'sources' => $blocklist['sources'] ?? [],
        ];
    }

    /**
     * Clear the cached blocklist
     */
    public function clearCache(): void
    {
        $cache = $this->getCache();

        // Clear metadata
        $meta = $cache->get('blocklist_meta');
        $cache->delete('blocklist_meta');
        $cache->delete('blocklist_ips');
        $cache->delete('blocklist_ranges');

        // Clear all CIDR chunks
        if ($meta && isset($meta['cidr_chunks'])) {
            for ($i = 0; $i < $meta['cidr_chunks']; $i++) {
                $cache->delete("blocklist_cidrs_{$i}");
            }
        }

        $this->loadedBlocklist = null;
    }

    protected function getCache(): CacheInterface
    {
        return Injector::inst()->get(CacheInterface::class . '.Waf');
    }
}
