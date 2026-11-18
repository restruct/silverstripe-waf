<?php

namespace Restruct\SilverStripe\Waf\Tests\Jobs;

use Restruct\SilverStripe\Waf\Jobs\SyncBlocklistsJob;
use SilverStripe\Dev\SapphireTest;
use Symbiote\QueuedJobs\DataObjects\QueuedJobDescriptor;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use Symbiote\QueuedJobs\Services\QueuedJob;

/**
 * waf#19: getJobType() must return the queue constant as queuedjobs defines it, a string ('2').
 * Declared `: int`, PHP coerced '2' to 2, and on Silverstripe 6 the descriptor's JobType field
 * refuses an int on write, so every reschedule failed and the job ended Broken.
 */
class SyncBlocklistsJobTest extends SapphireTest
{
    protected $usesDatabase = true;

    protected function setUp(): void
    {
        # parent::setUp() first: skipping before it leaves the kernel state unset and
        # tearDownAfterClass() then errors.
        parent::setUp();
        # queuedjobs is optional (composer "suggest"); without it the job class is not declared.
        if (!class_exists(AbstractQueuedJob::class)) {
            $this->markTestSkipped('symbiote/silverstripe-queuedjobs is not installed');
        }
    }

    public function testJobTypeIsTheQueueConstantUnchanged(): void
    {
        $this->assertSame(QueuedJob::QUEUED, (new SyncBlocklistsJob())->getJobType());
    }

    public function testDescriptorWithTheJobTypeCanBeWritten(): void
    {
        # The write is what failed on SS6 (DBField validation); on SS5 this passes either way.
        $descriptor = QueuedJobDescriptor::create([
            'JobTitle' => 'waf#19',
            'Implementation' => SyncBlocklistsJob::class,
            'JobType' => (new SyncBlocklistsJob())->getJobType(),
        ]);
        $this->assertGreaterThan(0, $descriptor->write());
    }
}
