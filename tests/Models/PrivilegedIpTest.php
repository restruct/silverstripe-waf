<?php

namespace Restruct\SilverStripe\Waf\Tests\Models;

use Restruct\SilverStripe\Waf\Extensions\PrivilegedIpValidationExtension;
use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use Restruct\SilverStripe\Waf\Models\BannedIp;
use Restruct\SilverStripe\Waf\Models\BlockedRequest;
use Restruct\SilverStripe\Waf\Models\PrivilegedIp;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\DB;

/**
 * PrivilegedIp validation and the module's database schema, on Silverstripe 5 and 6.
 *
 * Validation runs through DataObject::validate()'s extension hook, whose name differs per major
 * (validate / updateValidate). A hook with the wrong name fails silently - every record would
 * validate - so these tests assert that invalid records are REJECTED, not just that valid ones pass.
 */
class PrivilegedIpTest extends SapphireTest
{
    protected $usesDatabase = true;

    public function testValidationExtensionIsApplied(): void
    {
        $this->assertTrue(PrivilegedIp::singleton()->hasExtension(PrivilegedIpValidationExtension::class));
    }

    public function testValidSingleIpsAndCidrsPass(): void
    {
        foreach (['203.0.113.7', '10.0.0.0/8', '2001:db8::1', '2001:db8::/64'] as $ip) {
            $record = PrivilegedIp::create(['IpAddress' => $ip, 'Factor' => 2.0]);
            $this->assertTrue($record->validate()->isValid(), "$ip should validate");
        }
    }

    public function testInvalidIpIsRejected(): void
    {
        $result = PrivilegedIp::create(['IpAddress' => 'not-an-ip', 'Factor' => 2.0])->validate();
        $this->assertFalse($result->isValid());
        $this->assertSame(['IpAddress'], $this->fieldsWithErrors($result));
    }

    public function testInvalidCidrIsRejected(): void
    {
        foreach (['10.0.0.0/abc', '10.0.0.0/129', 'nonsense/8'] as $cidr) {
            $result = PrivilegedIp::create(['IpAddress' => $cidr, 'Factor' => 2.0])->validate();
            $this->assertFalse($result->isValid(), "$cidr should be rejected");
            $this->assertStringContainsString('CIDR', $this->messagesText($result), $cidr);
        }
    }

    public function testNonPositiveFactorIsRejected(): void
    {
        foreach ([0, -1.5] as $factor) {
            $result = PrivilegedIp::create(['IpAddress' => '203.0.113.7', 'Factor' => $factor])->validate();
            $this->assertFalse($result->isValid(), "factor $factor should be rejected");
            $this->assertSame(['Factor'], $this->fieldsWithErrors($result));
        }
    }

    public function testWriteRefusesAnInvalidRecord(): void
    {
        $record = PrivilegedIp::create(['IpAddress' => 'not-an-ip', 'Factor' => 2.0]);
        try {
            $record->write();
            $this->fail('write() should refuse an invalid PrivilegedIp');
        } catch (\Exception $e) {
            # ValidationException moved namespace in Silverstripe 6; match on the short name.
            $this->assertSame('ValidationException', substr(strrchr(get_class($e), '\\'), 1));
        }
        $this->assertSame(0, PrivilegedIp::get()->count());
    }

    public function testTierFactorIsCopiedOnWrite(): void
    {
        Config::modify()->set(WafMiddleware::class, 'privileged_tiers', [
            'office' => ['factor' => 3.5, 'ips' => []],
        ]);
        $record = PrivilegedIp::create(['IpAddress' => '203.0.113.7', 'Factor' => 1.0, 'Tier' => 'office']);
        $record->write();
        $this->assertSame(3.5, (float) PrivilegedIp::get()->byID($record->ID)->Factor);
    }

    public function testSchemaIsBuilt(): void
    {
        $expected = [
            BannedIp::class => ['Waf_BannedIp', ['IpAddress', 'Reason', 'ExpiresAt', 'IsPermanent']],
            BlockedRequest::class => ['Waf_BlockedRequest', ['IpAddress', 'Uri', 'UserAgent', 'Reason', 'Detail']],
            PrivilegedIp::class => ['Waf_PrivilegedIp', ['IpAddress', 'Factor', 'Tier', 'IsActive']],
        ];
        $schema = DB::get_schema();
        foreach ($expected as $class => [$table, $fields]) {
            $this->assertSame($table, $class::singleton()->baseTable());
            $this->assertTrue($schema->hasTable($table), "table $table");
            $columns = array_keys($schema->fieldList($table));
            foreach ($fields as $field) {
                $this->assertContains($field, $columns, "$table.$field");
            }
        }
    }

    /**
     * @return string[] field names that carry an error
     */
    private function fieldsWithErrors($result): array
    {
        $fields = array_values(array_filter(array_map(fn($m) => $m['fieldName'] ?? null, $result->getMessages())));
        sort($fields);
        return array_values(array_unique($fields));
    }

    private function messagesText($result): string
    {
        return implode(' | ', array_map(fn($m) => $m['message'] ?? '', $result->getMessages()));
    }
}
