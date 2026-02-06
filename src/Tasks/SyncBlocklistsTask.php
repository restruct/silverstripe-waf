<?php

namespace Restruct\SilverStripe\Waf\Tasks;

use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\BuildTask;

/**
 * Sync IP blocklists from threat intelligence feeds
 *
 * Run manually:
 *   vendor/bin/sake dev/tasks/waf-sync-blocklists
 *
 * Schedule via cron (recommended every 6 hours):
 *   0 */6 * * * cd /path/to/site && vendor/bin/sake dev/tasks/waf-sync-blocklists
 *
 * Or use the SyncBlocklistsJob for QueuedJobs module integration.
 */
class SyncBlocklistsTask extends BuildTask
{
    private static string $segment = 'waf-sync-blocklists';

    protected $title = 'WAF: Sync IP Blocklists';

    protected $description = 'Download and cache IP blocklists from threat intelligence feeds (FireHOL, Binary Defense, etc.)';

    public function run($request): void
    {
        $this->output("Starting blocklist sync...\n");

        /** @var IpBlocklistService $service */
        $service = Injector::inst()->get(IpBlocklistService::class);

        // Clear cache to force fresh sync
        $service->clearCache();

        // Sync blocklists
        $startTime = microtime(true);
        $result = $service->syncBlocklists();
        $duration = round(microtime(true) - $startTime, 2);

        // Output results
        $this->output("\nSync completed in {$duration}s\n");
        $this->output("=====================================\n");
        $this->output("Total IPs: " . count($result['ips']) . "\n");
        $this->output("Total CIDRs: " . count($result['cidrs']) . "\n");
        $this->output("Optimized ranges: " . count($result['ranges']) . " (merged for binary search)\n");
        $this->output("\nSources:\n");

        foreach ($result['sources'] as $name => $source) {
            if (isset($source['error'])) {
                $this->output("  - {$name}: ERROR - {$source['error']}\n");
            } else {
                $count = $source['count'] ?? 0;
                $this->output("  - {$name}: {$count} entries\n");
            }
        }

        // Clean up expired bans
        $this->output("\nCleaning up expired bans...\n");
        /** @var WafStorageService $storage */
        $storage = Injector::inst()->get(WafStorageService::class);
        $storage->cleanupExpiredBans();
        $this->output("Done.\n");
    }

    protected function output(string $message): void
    {
        if (php_sapi_name() === 'cli') {
            echo $message;
        } else {
            echo nl2br(htmlspecialchars($message));
        }
    }
}
