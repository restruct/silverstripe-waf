<?php

namespace Restruct\WafBrowser;

use Restruct\SilverStripe\Waf\Models\PrivilegedIp;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataObject;

/**
 * BROWSER-TEST FIXTURE ONLY - seeds the WAF admin screen (/admin/waf) on every dev/build.
 *
 * A DataObject only so that dev/build calls requireDefaultRecords(); it has no rows. Never loaded
 * by a real install: it lives under tests/browser/, which carries a _manifest_exclude marker, and
 * the browser-test runner copies it into a scratch host's app/ before dev/build.
 *
 * - logs one blocked request, so the Blocked Requests list has a known entry;
 * - removes the privileged-IP entries the specs add;
 * - lifts any ban the specs place (all in documentation ranges, RFC 5737 / RFC 3849), so a run
 *   starts without them whatever an earlier run left behind. Storage is the module default
 *   ('file'), kept under the host's TEMP_PATH.
 */
class WafBSeed extends DataObject
{
    private static $table_name = 'WafBSeed';

    /**
     * The addresses the specs ban: the IPv6 one in the canonical form the module stores, and in the
     * spelling the spec types, which a broken build (a must-fail control) stores as typed.
     */
    public const SPEC_IPS = ['203.0.113.7', '203.0.113.8', '198.51.100.9', '2001:db8::99', '2001:0DB8:0:0:0:0:0:99'];

    /** The privileged entries the specs add. */
    public const SPEC_PRIVILEGED = ['198.51.100.0/24', 'not-an-ip'];

    public function requireDefaultRecords()
    {
        parent::requireDefaultRecords();

        /** @var WafStorageService $storage */
        $storage = Injector::inst()->get(WafStorageService::class);
        foreach (self::SPEC_IPS as $ip) {
            $storage->unbanIp($ip);
        }
        foreach (PrivilegedIp::get()->filter('IpAddress', self::SPEC_PRIVILEGED) as $old) {
            $old->delete();
        }
        $storage->logBlockedRequest(
            '192.0.2.44',
            '/wp-login.php?browser-fixture=1',
            'sqlmap/1.7 (browser fixture)',
            'bad_user_agent',
            'browser-fixture'
        );
    }
}
