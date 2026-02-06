<?php

namespace Restruct\SilverStripe\Waf\Tasks;

use Restruct\SilverStripe\Waf\Models\BannedIp;
use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\BuildTask;

/**
 * Task to sync IP blocklists from threat intelligence feeds
 *
 * Run via:
 *   vendor/bin/sake dev/tasks/waf-sync-blocklists
 *
 * Schedule via cron (recommended: every 6 hours):
 *   0 */6 * * * cd /path/to/site && vendor/bin/sake dev/tasks/waf-sync-blocklists
 */
class SyncBlocklistsTask extends BuildTask
{
    private static string $segment = 'waf-sync-blocklists';

    protected $title = 'WAF: Sync IP Blocklists';
    protected $description = 'Sync IP blocklists from threat intelligence feeds (FireHOL, Binary Defense, etc.)';

    public function run($request): void
    {
        $this->output("Starting blocklist sync...\n");

        /** @var IpBlocklistService $service */
        $service = Injector::inst()->get(IpBlocklistService::class);

        // Clear cache to force fresh sync
        $service->clearCache();

        // Sync blocklists
        $startTime = microtime(true);
        $blocklist = $service->syncBlocklists();
        $duration = round(microtime(true) - $startTime, 2);

        // Output results
        $this->output("\nSync completed in {$duration}s\n");
        $this->output("=====================================\n");

        $totalIps = count($blocklist['ips'] ?? []);
        $totalCidrs = count($blocklist['cidrs'] ?? []);
        $this->output("Total IPs: {$totalIps}\n");
        $this->output("Total CIDRs: {$totalCidrs}\n");
        $this->output("\nSources:\n");

        foreach ($blocklist['sources'] ?? [] as $name => $source) {
            if (isset($source['error'])) {
                $this->output("  - {$name}: ERROR - {$source['error']}\n");
            } else {
                $count = $source['count'] ?? 0;
                $this->output("  - {$name}: {$count} entries\n");
            }
        }

        // Also clean up expired bans
        $this->output("\nCleaning up expired bans...\n");
        $expiredCount = BannedIp::cleanupExpired();
        $this->output("Removed {$expiredCount} expired bans\n");

        $this->output("\nDone.\n");
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
