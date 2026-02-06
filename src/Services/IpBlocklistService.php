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
 * Uses CIDR matching for efficient IP range checking.
 */
class IpBlocklistService
{
    use Configurable;
    use Injectable;

    private static bool $sync_enabled = true;
    private static int $cache_duration = 3600;
    private static array $blocklist_sources = [];
    private static ?string $local_blocklist_file = null;

    protected ?array $loadedBlocklist = null;

    /**
     * Check if an IP is on any blocklist
     */
    public function isBlocked(string $ip): bool
    {
        if (!$this->config()->get('sync_enabled')) {
            return false;
        }

        $blocklist = $this->getBlocklist();

        if (empty($blocklist)) {
            return false;
        }

        // Check direct IP match first (fast)
        if (isset($blocklist['ips'][$ip])) {
            return true;
        }

        // Check CIDR ranges
        foreach ($blocklist['cidrs'] ?? [] as $cidr) {
            if ($this->ipInCidr($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the combined blocklist (from cache or sync)
     */
    public function getBlocklist(): array
    {
        if ($this->loadedBlocklist !== null) {
            return $this->loadedBlocklist;
        }

        $cache = $this->getCache();
        $cacheKey = 'blocklist_combined';

        // Try cache first
        $cached = $cache->get($cacheKey);
        if ($cached !== null) {
            $this->loadedBlocklist = $cached;
            return $cached;
        }

        // Sync and cache
        $blocklist = $this->syncBlocklists();
        $cache->set($cacheKey, $blocklist, $this->config()->get('cache_duration'));

        $this->loadedBlocklist = $blocklist;
        return $blocklist;
    }

    /**
     * Force sync all blocklists
     */
    public function syncBlocklists(): array
    {
        $combined = [
            'ips' => [],
            'cidrs' => [],
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
        $combined['cidrs'] = array_unique($combined['cidrs']);

        return $combined;
    }

    /**
     * Fetch and parse a remote blocklist
     */
    protected function fetchBlocklist(string $url, string $format): array
    {
        $context = stream_context_create([
            'http' => [
                'timeout' => 30,
                'user_agent' => 'Silverstripe-WAF/1.0',
            ],
        ]);

        $content = @file_get_contents($url, false, $context);

        if ($content === false) {
            throw new \RuntimeException("Failed to fetch blocklist from: {$url}");
        }

        return $this->parseBlocklistFile($content, $format);
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
     * Check if an IP is within a CIDR range
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
        $blocklist = $this->getBlocklist();

        return [
            'total_ips' => count($blocklist['ips'] ?? []),
            'total_cidrs' => count($blocklist['cidrs'] ?? []),
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
        $cache->delete('blocklist_combined');
        $this->loadedBlocklist = null;
    }

    protected function getCache(): CacheInterface
    {
        return Injector::inst()->get(CacheInterface::class . '.Waf');
    }
}
