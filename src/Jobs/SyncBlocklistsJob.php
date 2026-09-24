<?php

namespace Restruct\SilverStripe\Waf\Jobs;

use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use Symbiote\QueuedJobs\Services\QueuedJob;
use Symbiote\QueuedJobs\Services\QueuedJobService;

# symbiote/silverstripe-queuedjobs is OPTIONAL (composer "suggest", and the YAML fragment that
# schedules this job is gated by `Only: moduleexists`). Without it, declaring a subclass of
# AbstractQueuedJob fatals the whole application on the next flush: the config layer's
# PrivateStaticTransformer calls class_exists() on every class in the manifest, which autoloads
# this file and hits the missing parent. The YAML `Only:` guard does not prevent that - it gates a
# config fragment, not this file. A file-scope return leaves the class undeclared instead (waf#6).
# The guard sits BELOW the `use` block on purpose: above it, AbstractQueuedJob::class would resolve
# into this file's own namespace and the check would always be false.
if (!class_exists(AbstractQueuedJob::class)) {
    return;
}

/**
 * Queued job to sync IP blocklists from threat intelligence feeds
 *
 * Self-scheduling: runs every 6 hours automatically.
 *
 * To initialize, either:
 * - Run via CLI: vendor/bin/sake dev/tasks/ProcessJobQueueTask
 * - Or configure in YAML (see README)
 */
class SyncBlocklistsJob extends AbstractQueuedJob implements QueuedJob
{
    use Configurable;
    /**
     * How often to run (6 hours in seconds)
     */
    private static int $reschedule_interval = 21600;

    public function getTitle(): string
    {
        return 'WAF: Sync IP Blocklists';
    }

    public function getJobType(): int
    {
        return QueuedJob::QUEUED;
    }

    public function process(): void
    {
        /** @var IpBlocklistService $service */
        $service = Injector::inst()->get(IpBlocklistService::class);

        // Clear and sync
        $service->clearCache();
        $result = $service->syncBlocklists();

        // Log results
        $totalIps = count($result['ips']);
        $totalCidrs = count($result['cidrs']);
        $totalRanges = count($result['ranges']);

        $this->addMessage("Synced blocklists: {$totalIps} IPs, {$totalCidrs} CIDRs, {$totalRanges} ranges");

        // Report source status
        foreach ($result['sources'] as $name => $source) {
            if (isset($source['error'])) {
                $this->addMessage("Source {$name}: ERROR - {$source['error']}");
            } else {
                $count = $source['count'] ?? 0;
                $this->addMessage("Source {$name}: {$count} entries");
            }
        }

        // Clean up expired bans
        /** @var WafStorageService $storage */
        $storage = Injector::inst()->get(WafStorageService::class);
        $removed = $storage->cleanupExpiredBans();
        if ($removed > 0) {
            $this->addMessage("Cleaned up {$removed} expired bans");
        }

        // Schedule next run
        $this->scheduleNextRun();

        $this->isComplete = true;
    }

    /**
     * Schedule the next run of this job
     */
    protected function scheduleNextRun(): void
    {
        $interval = $this->config()->get('reschedule_interval');
        $nextRun = date('Y-m-d H:i:s', time() + $interval);

        $job = new self();

        /** @var QueuedJobService $jobService */
        $jobService = Injector::inst()->get(QueuedJobService::class);
        $jobService->queueJob($job, $nextRun);

        $this->addMessage("Next sync scheduled for: {$nextRun}");
    }
}
