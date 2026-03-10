<?php

# Guard: only define if QueuedJobs module is installed
if (!class_exists('AbstractQueuedJob')) {
    return;
}

/**
 * Queued job to sync IP blocklists from threat intelligence feeds
 *
 * Self-scheduling: runs every 6 hours automatically.
 *
 * To initialize, either:
 * - Run via CLI: php framework/cli-script.php dev/tasks/ProcessJobQueueTask
 * - Or configure in YAML (see README)
 */
class WafSyncBlocklistsJob extends AbstractQueuedJob implements QueuedJob
{
    /**
     * How often to run (6 hours in seconds)
     */
    private static $reschedule_interval = 21600;

    /**
     * @return string
     */
    public function getTitle()
    {
        return 'WAF: Sync IP Blocklists';
    }

    /**
     * @return int
     */
    public function getJobType()
    {
        return QueuedJob::QUEUED;
    }

    public function process()
    {
        /** @var WafIpBlocklistService $service */
        $service = Injector::inst()->get('WafIpBlocklistService');

        // Clear and sync
        $service->clearBlocklistCache();
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
                $count = isset($source['count']) ? $source['count'] : 0;
                $this->addMessage("Source {$name}: {$count} entries");
            }
        }

        // Clean up expired bans
        /** @var WafStorageService $storage */
        $storage = Injector::inst()->get('WafStorageService');
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
    protected function scheduleNextRun()
    {
        $interval = $this->config()->get('reschedule_interval');
        $nextRun = date('Y-m-d H:i:s', time() + $interval);

        $job = new WafSyncBlocklistsJob();

        /** @var QueuedJobService $jobService */
        $jobService = Injector::inst()->get('QueuedJobService');
        $jobService->queueJob($job, $nextRun);

        $this->addMessage("Next sync scheduled for: {$nextRun}");
    }
}
