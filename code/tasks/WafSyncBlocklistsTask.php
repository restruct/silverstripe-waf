<?php

/**
 * Sync IP blocklists from threat intelligence feeds
 *
 * Run manually:
 *   php framework/cli-script.php dev/tasks/WafSyncBlocklistsTask
 *
 * Schedule via cron (recommended every 6 hours):
 *   0 0,6,12,18 * * * cd /path/to/site && php framework/cli-script.php dev/tasks/WafSyncBlocklistsTask
 *
 * Or use the WafSyncBlocklistsJob for QueuedJobs module integration.
 */
class WafSyncBlocklistsTask extends BuildTask
{
    protected $title = 'WAF: Sync IP Blocklists';

    protected $description = 'Download and cache IP blocklists from threat intelligence feeds (FireHOL, Binary Defense, etc.)';

    /**
     * @param SS_HTTPRequest $request
     */
    public function run($request)
    {
        $this->output("Starting blocklist sync...\n");

        /** @var WafIpBlocklistService $service */
        $service = Injector::inst()->get('WafIpBlocklistService');

        // Clear cache to force fresh sync
        $service->clearBlocklistCache();

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
                $count = isset($source['count']) ? $source['count'] : 0;
                $this->output("  - {$name}: {$count} entries\n");
            }
        }

        // Clean up expired bans
        $this->output("\nCleaning up expired bans...\n");
        /** @var WafStorageService $storage */
        $storage = Injector::inst()->get('WafStorageService');
        $storage->cleanupExpiredBans();
        $this->output("Done.\n");
    }

    /**
     * @param string $message
     */
    protected function output($message)
    {
        if (php_sapi_name() === 'cli') {
            echo $message;
        } else {
            echo nl2br(htmlspecialchars($message));
        }
    }
}
