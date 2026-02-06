<?php

namespace Restruct\SilverStripe\Waf\Middleware;

use Psr\SimpleCache\CacheInterface;
use Restruct\SilverStripe\Waf\Models\BannedIp;
use Restruct\SilverStripe\Waf\Models\BlockedRequest;
use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;

/**
 * WAF Middleware - runs within Silverstripe framework
 *
 * Features:
 * - Rate limiting per IP
 * - IP blocklist checking (threat intelligence feeds)
 * - User-agent filtering
 * - Auto-banning after violations
 * - Database logging of blocked requests
 */
class WafMiddleware implements HTTPMiddleware
{
    use Configurable;
    use Injectable;

    // ========================================================================
    // Configuration (set via YAML)
    // ========================================================================

    private static bool $enabled = true;

    // Rate limiting
    private static bool $rate_limit_enabled = true;
    private static int $rate_limit_requests = 100;
    private static int $rate_limit_window = 60;

    // Soft rate limiting (progressive delays before hard block)
    private static bool $soft_rate_limit_enabled = true;
    private static int $soft_rate_limit_threshold = 50;  // Start delaying at this % of hard limit
    private static int $soft_rate_limit_max_delay = 3000; // Max delay in milliseconds

    // Auto-ban
    private static bool $auto_ban_enabled = true;
    private static int $ban_threshold = 10;
    private static int $ban_duration = 3600;

    // Logging
    private static bool $log_blocked_requests = true;
    private static bool $log_to_database = true;

    // Whitelists
    private static array $whitelisted_ips = [];
    private static array $whitelisted_user_agents = [];

    // Blocklists
    private static array $blocked_user_agents = [];

    // ========================================================================
    // Middleware Entry Point
    // ========================================================================

    public function process(HTTPRequest $request, callable $delegate): HTTPResponse
    {
        // Skip if disabled
        if (!$this->config()->get('enabled')) {
            return $delegate($request);
        }

        $ip = $request->getIP();
        $userAgent = $request->getHeader('User-Agent') ?? '';
        $uri = $request->getURL(true);

        // Skip whitelisted IPs
        if ($this->isWhitelistedIp($ip)) {
            return $delegate($request);
        }

        // Check if IP is banned (cache or database)
        if ($this->isBanned($ip)) {
            return $this->blocked($request, 'banned', 'IP is banned');
        }

        // Check IP against threat intelligence blocklists
        if ($this->isBlocklistedIp($ip)) {
            $this->recordViolation($ip, 'blocklist');
            return $this->blocked($request, 'blocklist', 'IP on threat blocklist');
        }

        // Check user-agent against whitelist first
        if (!$this->isWhitelistedUserAgent($userAgent)) {
            // Check user-agent against blocklist
            if ($this->isBlockedUserAgent($userAgent)) {
                $this->recordViolation($ip, 'bad_useragent');
                return $this->blocked($request, 'bad_useragent', 'Blocked user-agent');
            }
        }

        // Rate limiting
        if ($this->config()->get('rate_limit_enabled')) {
            $requestCount = $this->getRequestCount($ip);
            $hardLimit = $this->config()->get('rate_limit_requests');

            // Hard rate limit
            if ($requestCount >= $hardLimit) {
                $this->recordViolation($ip, 'rate_limit');
                return $this->tooManyRequests($request);
            }

            // Soft rate limiting (progressive delay)
            if ($this->config()->get('soft_rate_limit_enabled')) {
                $this->applySoftRateLimit($requestCount, $hardLimit);
            }

            $this->recordRequest($ip);
        }

        // Request passed all checks
        return $delegate($request);
    }

    // ========================================================================
    // IP Checking
    // ========================================================================

    protected function isWhitelistedIp(string $ip): bool
    {
        $whitelist = $this->config()->get('whitelisted_ips') ?: [];

        // Also check environment variable
        $envWhitelist = Environment::getEnv('WAF_WHITELIST_IPS');
        if ($envWhitelist) {
            $whitelist = array_merge($whitelist, array_map('trim', explode(',', $envWhitelist)));
        }

        return in_array($ip, $whitelist, true);
    }

    protected function isBanned(string $ip): bool
    {
        $cache = $this->getCache();
        $cacheKey = 'banned_' . md5($ip);

        // Check cache first (fast)
        if ($cache->has($cacheKey)) {
            return true;
        }

        // Check database for persistent bans
        $ban = BannedIp::get()->filter([
            'IpAddress' => $ip,
            'ExpiresAt:GreaterThan' => date('Y-m-d H:i:s'),
        ])->first();

        if ($ban) {
            // Cache the result for faster subsequent checks
            $ttl = strtotime($ban->ExpiresAt) - time();
            if ($ttl > 0) {
                $cache->set($cacheKey, true, $ttl);
            }
            return true;
        }

        return false;
    }

    protected function isBlocklistedIp(string $ip): bool
    {
        try {
            /** @var IpBlocklistService $service */
            $service = Injector::inst()->get(IpBlocklistService::class);
            return $service->isBlocked($ip);
        } catch (\Exception $e) {
            // Don't block on service failure
            return false;
        }
    }

    // ========================================================================
    // User-Agent Checking
    // ========================================================================

    protected function isWhitelistedUserAgent(string $userAgent): bool
    {
        if (empty($userAgent)) {
            return false;
        }

        foreach ($this->config()->get('whitelisted_user_agents') ?: [] as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    protected function isBlockedUserAgent(string $userAgent): bool
    {
        foreach ($this->config()->get('blocked_user_agents') ?: [] as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // Rate Limiting
    // ========================================================================

    protected function getRequestCount(string $ip): int
    {
        $cache = $this->getCache();
        $key = 'rate_' . md5($ip);
        return (int) $cache->get($key);
    }

    protected function isRateLimited(string $ip): bool
    {
        return $this->getRequestCount($ip) >= $this->config()->get('rate_limit_requests');
    }

    protected function recordRequest(string $ip): void
    {
        $cache = $this->getCache();
        $key = 'rate_' . md5($ip);
        $count = (int) $cache->get($key);

        $cache->set($key, $count + 1, $this->config()->get('rate_limit_window'));
    }

    /**
     * Apply soft rate limiting - progressive delay as request count increases
     *
     * Delays are applied when request count exceeds the soft threshold,
     * scaling up to max_delay as it approaches the hard limit.
     *
     * Example with defaults (threshold 50%, max_delay 3000ms, hard_limit 100):
     * - 50 requests: 0ms delay
     * - 60 requests: 600ms delay
     * - 75 requests: 1500ms delay
     * - 90 requests: 2400ms delay
     * - 99 requests: 2940ms delay
     */
    protected function applySoftRateLimit(int $requestCount, int $hardLimit): void
    {
        $thresholdPercent = $this->config()->get('soft_rate_limit_threshold');
        $maxDelay = $this->config()->get('soft_rate_limit_max_delay');

        $softThreshold = (int) ($hardLimit * $thresholdPercent / 100);

        // No delay if under threshold
        if ($requestCount <= $softThreshold) {
            return;
        }

        // Calculate progressive delay
        // Scale from 0 at threshold to max_delay at hard limit
        $range = $hardLimit - $softThreshold;
        $excess = $requestCount - $softThreshold;
        $ratio = min(1.0, $excess / $range);

        $delayMs = (int) ($ratio * $maxDelay);

        if ($delayMs > 0) {
            // Log soft limiting (at debug level to avoid log spam)
            if ($delayMs >= 1000) {
                error_log(sprintf(
                    '[WAF] SOFT_LIMIT ip=%s requests=%d delay=%dms',
                    $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    $requestCount,
                    $delayMs
                ));
            }

            // Apply delay (usleep takes microseconds)
            usleep($delayMs * 1000);
        }
    }

    // ========================================================================
    // Violation & Banning
    // ========================================================================

    protected function recordViolation(string $ip, string $reason): void
    {
        if (!$this->config()->get('auto_ban_enabled')) {
            return;
        }

        $cache = $this->getCache();
        $violationKey = 'violations_' . md5($ip);
        $violations = (int) $cache->get($violationKey);
        $violations++;

        // Log for fail2ban
        error_log(sprintf(
            '[WAF] VIOLATION reason=%s ip=%s count=%d',
            $reason,
            $ip,
            $violations
        ));

        // Auto-ban if threshold exceeded
        $threshold = $this->config()->get('ban_threshold');
        $banDuration = $this->config()->get('ban_duration');

        if ($violations >= $threshold) {
            $this->banIp($ip, $banDuration, "Auto-banned after {$violations} violations");
        } else {
            // Store violation count (expires after 1 hour)
            $cache->set($violationKey, $violations, 3600);
        }
    }

    protected function banIp(string $ip, int $duration, string $reason): void
    {
        // Cache ban
        $cache = $this->getCache();
        $cacheKey = 'banned_' . md5($ip);
        $cache->set($cacheKey, true, $duration);

        // Store in database for persistence
        $ban = BannedIp::create();
        $ban->IpAddress = $ip;
        $ban->Reason = $reason;
        $ban->ExpiresAt = date('Y-m-d H:i:s', time() + $duration);
        $ban->write();

        // Log
        error_log(sprintf(
            '[WAF] BANNED ip=%s duration=%d reason="%s"',
            $ip,
            $duration,
            $reason
        ));
    }

    // ========================================================================
    // Response Helpers
    // ========================================================================

    protected function blocked(HTTPRequest $request, string $reason, string $detail): HTTPResponse
    {
        $this->logBlockedRequest($request, $reason, $detail);

        return HTTPResponse::create()
            ->setStatusCode(403)
            ->addHeader('Content-Type', 'text/plain')
            ->addHeader('Cache-Control', 'no-store')
            ->setBody('Forbidden');
    }

    protected function tooManyRequests(HTTPRequest $request): HTTPResponse
    {
        $this->logBlockedRequest($request, 'rate_limit', 'Rate limit exceeded');

        return HTTPResponse::create()
            ->setStatusCode(429)
            ->addHeader('Content-Type', 'text/plain')
            ->addHeader('Retry-After', (string) $this->config()->get('rate_limit_window'))
            ->addHeader('Cache-Control', 'no-store')
            ->setBody('Too Many Requests');
    }

    protected function logBlockedRequest(HTTPRequest $request, string $reason, string $detail): void
    {
        $ip = $request->getIP();
        $uri = $request->getURL(true);
        $userAgent = $request->getHeader('User-Agent') ?? '';

        // Log to error log (fail2ban compatible)
        if ($this->config()->get('log_blocked_requests')) {
            error_log(sprintf(
                '[WAF] BLOCKED reason=%s detail="%s" ip=%s uri="%s"',
                $reason,
                substr($detail, 0, 100),
                $ip,
                substr($uri, 0, 200)
            ));
        }

        // Log to database
        if ($this->config()->get('log_to_database')) {
            try {
                $log = BlockedRequest::create();
                $log->IpAddress = $ip;
                $log->Uri = substr($uri, 0, 255);
                $log->UserAgent = substr($userAgent, 0, 255);
                $log->Reason = $reason;
                $log->Detail = substr($detail, 0, 255);
                $log->write();
            } catch (\Exception $e) {
                // Don't fail request on logging error
            }
        }
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    protected function getCache(): CacheInterface
    {
        return Injector::inst()->get(CacheInterface::class . '.Waf');
    }
}
