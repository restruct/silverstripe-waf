<?php

namespace Restruct\SilverStripe\Waf\Tasks;

use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\BuildTask;
use SilverStripe\PolyExecution\PolyOutput;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;

/**
 * Sync IP blocklists from threat intelligence feeds
 *
 * Run manually:
 *   Silverstripe 5: vendor/bin/sake dev/tasks/waf-sync-blocklists
 *   Silverstripe 6: vendor/bin/sake tasks:waf-sync-blocklists
 *
 * Schedule via cron (recommended every 6 hours):
 *   0 0,6,12,18 * * * cd /path/to/site && vendor/bin/sake dev/tasks/waf-sync-blocklists
 *   (Silverstripe 6: `vendor/bin/sake tasks:waf-sync-blocklists`)
 *
 * Or use the SyncBlocklistsJob for QueuedJobs module integration.
 *
 * ONE class for BOTH Silverstripe majors. BuildTask's API changed completely in Silverstripe 6
 * (run($request) became execute(InputInterface, PolyOutput): int, $title became a typed property,
 * $description became static, the URL segment became $commandName). Two classes, one per major,
 * cannot work: TaskRunner discovers tasks from the class MANIFEST, which lists a class even when a
 * file-level guard leaves it undeclared, and then fatals reflecting on it. So this class declares
 * only what is compatible with both, and branches at runtime:
 * - no $title / $description property declarations (their types differ between majors): the title
 *   comes from getTitle(), the description from the constructor (SS5) or the lang file (SS6);
 * - run() is declared with untyped parameters, which satisfies both SS5's abstract run($request)
 *   and SS6's run(InputInterface, PolyOutput): int; on SS6 it hands straight back to the parent,
 *   which calls execute().
 */
class SyncBlocklistsTask extends BuildTask
{
    public const TITLE = 'WAF: Sync IP Blocklists';

    # Silverstripe 6 reads the description through _t('<class>.description'), so the same text also
    # lives in lang/en.yml. SyncBlocklistsTaskTest asserts both majors report this exact string.
    public const DESCRIPTION = 'Download and cache IP blocklists from threat intelligence feeds (FireHOL, Binary Defense, etc.)';

    # Silverstripe 5: URL segment, dev/tasks/waf-sync-blocklists
    private static string $segment = 'waf-sync-blocklists';

    # Silverstripe 6: command name, `sake tasks:waf-sync-blocklists` and dev/tasks/waf-sync-blocklists.
    # Declared with the parent's exact type so it is compatible there; on SS5 nothing reads it.
    protected static string $commandName = 'waf-sync-blocklists';

    // Pre-1.6.0 declarations, incompatible with Silverstripe 6's typed/static BuildTask properties:
    // protected $title = 'WAF: Sync IP Blocklists';
    // protected $description = 'Download and cache IP blocklists from threat intelligence feeds (FireHOL, Binary Defense, etc.)';

    public function __construct()
    {
        parent::__construct();

        # Silverstripe 5 keeps the description in an instance property that getDescription() returns.
        # On Silverstripe 6 that property is static and shared by every task, so it must not be written.
        if (!static::isPolyCommandApi()) {
            $this->description = _t(self::class . '.description', self::DESCRIPTION);
        }
    }

    public function getTitle(): string
    {
        return self::TITLE;
    }

    /**
     * Silverstripe 5 entry point ($input is the HTTPRequest, $output is not passed), and the
     * Silverstripe 6 entry point (InputInterface + PolyOutput), which defers to BuildTask::run().
     */
    public function run($input, $output = null): int
    {
        if (static::isPolyCommandApi()) {
            return parent::run($input, $output);
        }

        $this->sync(function (string $line): void {
            $this->output($line . "\n");
        });

        return 0;
    }

    /**
     * Silverstripe 6 only; BuildTask::run() calls it. Never called on Silverstripe 5.
     */
    protected function execute(InputInterface $input, PolyOutput $output): int
    {
        $this->sync(function (string $line) use ($output): void {
            # Feed error messages are free text; escape them so the console formatter does not
            # read a `<...>` in them as a style tag.
            $output->writeln(OutputFormatter::escape($line));
        });

        return 0;
    }

    /**
     * Silverstripe 5 output: plain text on the CLI, escaped HTML in the browser.
     */
    protected function output(string $message): void
    {
        if (php_sapi_name() === 'cli') {
            echo $message;
        } else {
            echo nl2br(htmlspecialchars($message));
        }
    }

    /**
     * The sake command that runs this task on the running major, for display (WafAdmin status panels).
     * Silverstripe 5 addresses a task by its URL segment, Silverstripe 6 by its command name.
     */
    public static function getSakeCommand(): string
    {
        return static::isPolyCommandApi()
            ? 'vendor/bin/sake tasks:' . static::$commandName
            : 'vendor/bin/sake dev/tasks/' . static::config()->get('segment');
    }

    /**
     * Whether the running framework has the Silverstripe 6 BuildTask API.
     */
    protected static function isPolyCommandApi(): bool
    {
        return class_exists(PolyOutput::class);
    }

    /**
     * The task body, shared by both majors. $writeLine receives one line at a time, without a newline.
     */
    protected function sync(callable $writeLine): void
    {
        $writeLine("Starting blocklist sync...");

        /** @var IpBlocklistService $service */
        $service = Injector::inst()->get(IpBlocklistService::class);

        // Clear cache to force fresh sync
        $service->clearCache();

        // Sync blocklists
        $startTime = microtime(true);
        $result = $service->syncBlocklists();
        $duration = round(microtime(true) - $startTime, 2);

        // Output results
        $writeLine('');
        $writeLine("Sync completed in {$duration}s");
        $writeLine("=====================================");
        $writeLine("Total IPs: " . count($result['ips']));
        $writeLine("Total CIDRs: " . count($result['cidrs']));
        $writeLine("Optimized ranges: " . count($result['ranges']) . " (merged for binary search)");
        $writeLine('');
        $writeLine("Sources:");

        foreach ($result['sources'] as $name => $source) {
            if (isset($source['error'])) {
                $writeLine("  - {$name}: ERROR - {$source['error']}");
            } else {
                $count = $source['count'] ?? 0;
                $writeLine("  - {$name}: {$count} entries");
            }
        }

        // Clean up expired bans
        $writeLine('');
        $writeLine("Cleaning up expired bans...");
        /** @var WafStorageService $storage */
        $storage = Injector::inst()->get(WafStorageService::class);
        $storage->cleanupExpiredBans();
        $writeLine("Done.");
    }
}
