<?php

namespace Restruct\SilverStripe\Waf\Tests\Tasks;

use Psr\SimpleCache\CacheInterface;
use Restruct\SilverStripe\Waf\Jobs\SyncBlocklistsJob;
use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use Restruct\SilverStripe\Waf\Tasks\SyncBlocklistsTask;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\ClassInfo;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\BuildTask;
use SilverStripe\Dev\SapphireTest;

/**
 * SyncBlocklistsTask runs through each major's own BuildTask API, and the optional queued job
 * does not break the application when queuedjobs is absent.
 */
class SyncBlocklistsTaskTest extends SapphireTest
{
    protected $usesDatabase = false;

    private string $localFile;

    protected function setUp(): void
    {
        parent::setUp();
        # No network: every remote feed off, one local file with 2 IPs and 1 CIDR.
        Config::modify()->set(IpBlocklistService::class, 'blocklist_sources', []);
        $this->localFile = tempnam(sys_get_temp_dir(), 'waftest');
        file_put_contents($this->localFile, "# comment\n198.51.100.1\n198.51.100.2\n203.0.113.0/24\n");
        Config::modify()->set(IpBlocklistService::class, 'local_blocklist_file', $this->localFile);
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
    }

    protected function tearDown(): void
    {
        @unlink($this->localFile);
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        parent::tearDown();
    }

    public function testTaskIsDiscoverableAndEnabled(): void
    {
        $this->assertContains(SyncBlocklistsTask::class, ClassInfo::subclassesFor(BuildTask::class, false));
        $this->assertTrue(SyncBlocklistsTask::singleton()->isEnabled());
    }

    public function testTitleAndDescription(): void
    {
        $task = SyncBlocklistsTask::create();
        $this->assertSame('WAF: Sync IP Blocklists', $task->getTitle());
        # SS5: instance getDescription(); SS6: static getDescription() reading the lang file.
        # Both must report the same text, which also pins lang/en.yml to the class constant.
        $description = $this->isSs6() ? SyncBlocklistsTask::getDescription() : $task->getDescription();
        $this->assertSame(SyncBlocklistsTask::DESCRIPTION, $description);
    }

    public function testTaskAddressIsWafSyncBlocklists(): void
    {
        if ($this->isSs6()) {
            $this->assertSame('tasks:waf-sync-blocklists', SyncBlocklistsTask::getName());
        } else {
            $this->assertSame('waf-sync-blocklists', SyncBlocklistsTask::config()->get('segment'));
        }
    }

    public function testRunSyncsTheLocalBlocklist(): void
    {
        $output = $this->runTask();

        $this->assertStringContainsString('Total IPs: 2', $output);
        $this->assertStringContainsString('Total CIDRs: 1', $output);
        $this->assertStringContainsString('local: 3 entries', $output);
        $this->assertStringContainsString('Done.', $output);

        # The sync must actually have populated the blocklist the middleware consults.
        $service = Injector::inst()->get(IpBlocklistService::class);
        $this->assertTrue($service->isBlocked('198.51.100.2'));
        $this->assertTrue($service->isBlocked('203.0.113.77'));
        $this->assertFalse($service->isBlocked('192.0.2.1'));
    }

    /**
     * waf#6: SyncBlocklistsJob must exist exactly when its optional parent does. Without the
     * file-level guard, loading the class with queuedjobs absent is a fatal error.
     */
    public function testQueuedJobIsDeclaredOnlyWithQueuedJobs(): void
    {
        $parentExists = class_exists('Symbiote\\QueuedJobs\\Services\\AbstractQueuedJob');
        $this->assertSame($parentExists, class_exists(SyncBlocklistsJob::class));
    }

    private function runTask(): string
    {
        $task = SyncBlocklistsTask::create();
        if ($this->isSs6()) {
            $buffer = new \Symfony\Component\Console\Output\BufferedOutput();
            $output = new \SilverStripe\PolyExecution\PolyOutput(
                \SilverStripe\PolyExecution\PolyOutput::FORMAT_ANSI,
                wrappedOutput: $buffer
            );
            $exit = $task->run(new \Symfony\Component\Console\Input\ArrayInput([]), $output);
            $this->assertSame(0, $exit);
            return $buffer->fetch();
        }
        ob_start();
        try {
            $task->run(new HTTPRequest('GET', '/dev/tasks/waf-sync-blocklists'));
        } finally {
            $text = ob_get_clean();
        }
        return $text;
    }

    private function isSs6(): bool
    {
        return class_exists('SilverStripe\\PolyExecution\\PolyOutput');
    }
}
