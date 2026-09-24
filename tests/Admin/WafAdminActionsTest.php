<?php

namespace Restruct\SilverStripe\Waf\Tests\Admin;

use Psr\SimpleCache\CacheInterface;
use Restruct\SilverStripe\Waf\Admin\GridFieldManualBan;
use Restruct\SilverStripe\Waf\Middleware\WafMiddleware;
use Restruct\SilverStripe\Waf\Services\IpBlocklistService;
use Restruct\SilverStripe\Waf\Services\WafStorageService;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\Security\SecurityToken;

/**
 * The WAF admin's state-changing requests (ban, unban) through HTTP, with CSRF protection ON:
 * the URL actions and the GridField actions the screen uses, plus output escaping of the panels.
 */
class WafAdminActionsTest extends FunctionalTest
{
    protected $usesDatabase = true;

    private string $bansFile;
    private string $logFile;

    protected function setUp(): void
    {
        parent::setUp();
        # FunctionalTest disables the token for every test; these tests are about the token
        SecurityToken::enable();

        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        # File mode lists bans (cache mode cannot); private files keep the shared temp files untouched
        $this->bansFile = sys_get_temp_dir() . '/waf-admin-test-bans-' . getmypid() . '.json';
        $this->logFile = sys_get_temp_dir() . '/waf-admin-test-log-' . getmypid() . '.jsonl';
        Config::modify()->set(WafStorageService::class, 'storage_mode', 'file');
        Config::modify()->set(WafStorageService::class, 'bans_file', $this->bansFile);
        Config::modify()->set(WafStorageService::class, 'blocked_log_file', $this->logFile);
        Config::modify()->set(IpBlocklistService::class, 'blocklist_sources', []);
        # The test session has no client IP; keep the WAF itself out of these admin requests
        Config::modify()->set(WafMiddleware::class, 'enabled', false);

        $this->logInWithPermission('WAF_ADMIN');
    }

    protected function tearDown(): void
    {
        Injector::inst()->get(CacheInterface::class . '.Waf')->clear();
        @unlink($this->bansFile);
        @unlink($this->logFile);
        parent::tearDown();
    }

    private function storage(): WafStorageService
    {
        return Injector::inst()->get(WafStorageService::class);
    }

    /**
     * Whether $ip is in the persisted ban list. The list is read from the bans file, not from the
     * cache, so it reflects what the request actually stored or removed.
     */
    private function isListedAsBanned(string $ip): bool
    {
        foreach (WafStorageService::create()->getActiveBans() as $ban) {
            if ($ban->IpAddress === $ip) {
                return true;
            }
        }
        return false;
    }

    /**
     * Load the admin screen and return its security token (the edit form's SecurityID).
     */
    private function loadAdminToken(): string
    {
        $response = $this->get('admin/waf');
        $this->assertSame(200, $response->getStatusCode(), 'the admin screen loads');
        $inputs = $this->cssParser()->getByXpath('//form[@id="Form_EditForm"]//input[@name="SecurityID"]');
        $this->assertNotEmpty($inputs, 'the edit form carries a SecurityID');
        return (string) $inputs[0]['value'];
    }

    // ------------------------------------------------------------------
    // URL actions: admin/waf/unban and admin/waf/ban
    // ------------------------------------------------------------------

    public function testUnbanWithoutSecurityTokenIsRejected(): void
    {
        $this->storage()->banIp('192.0.2.10', 3600, 'test');
        $this->loadAdminToken();

        $response = $this->post('admin/waf/unban', ['ip' => '192.0.2.10']);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertTrue($this->isListedAsBanned('192.0.2.10'), 'still banned');
    }

    public function testUnbanWithWrongSecurityTokenIsRejected(): void
    {
        $this->storage()->banIp('192.0.2.11', 3600, 'test');
        $this->loadAdminToken();

        $response = $this->post('admin/waf/unban', ['ip' => '192.0.2.11', 'SecurityID' => 'not-the-token']);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertTrue($this->isListedAsBanned('192.0.2.11'), 'still banned');
    }

    /**
     * A GET must not unban, even with a valid token in the query string (1.5.x unbanned on a GET link).
     */
    public function testUnbanOverGetIsRejected(): void
    {
        $this->storage()->banIp('192.0.2.12', 3600, 'test');
        $token = $this->loadAdminToken();

        $response = $this->get('admin/waf/unban?ip=192.0.2.12&SecurityID=' . urlencode($token));

        $this->assertSame(405, $response->getStatusCode());
        $this->assertTrue($this->isListedAsBanned('192.0.2.12'), 'still banned');
    }

    /**
     * Positive control for the three refusals above: the same request as a POST with the token works.
     */
    public function testUnbanOverPostWithTokenUnbans(): void
    {
        $this->storage()->banIp('192.0.2.13', 3600, 'test');
        $token = $this->loadAdminToken();

        $this->autoFollowRedirection = false;
        $response = $this->post('admin/waf/unban', ['ip' => '192.0.2.13', 'SecurityID' => $token]);

        $this->assertSame(302, $response->getStatusCode());
        $this->assertFalse($this->isListedAsBanned('192.0.2.13'), 'unbanned');
    }

    public function testBanWithoutSecurityTokenIsRejected(): void
    {
        $this->loadAdminToken();

        $response = $this->post('admin/waf/ban', ['ip' => '192.0.2.20', 'hours' => 1, 'reason' => 'x']);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertFalse($this->isListedAsBanned('192.0.2.20'), 'not banned');
    }

    public function testBanOverGetIsRejected(): void
    {
        $token = $this->loadAdminToken();

        $response = $this->get('admin/waf/ban?ip=192.0.2.21&SecurityID=' . urlencode($token));

        $this->assertSame(405, $response->getStatusCode());
        $this->assertFalse($this->isListedAsBanned('192.0.2.21'), 'not banned');
    }

    /**
     * The IP is validated on the server: markup, ranges and non-addresses are refused (400) and
     * nothing is stored. The valid address at the end is the positive control.
     */
    public function testBanWithInvalidIpIsRejected(): void
    {
        $token = $this->loadAdminToken();
        $this->autoFollowRedirection = false;

        foreach (['not-an-ip', '192.0.2.300', '10.0.0.0/8', '192.0.2.22<script>', '', ' '] as $bad) {
            $response = $this->post('admin/waf/ban', ['ip' => $bad, 'hours' => 1, 'SecurityID' => $token]);
            $this->assertSame(400, $response->getStatusCode(), "refused: '$bad'");
        }
        $this->assertCount(0, WafStorageService::create()->getActiveBans(), 'nothing was banned');

        foreach (['192.0.2.22', '2001:db8::22'] as $good) {
            $response = $this->post('admin/waf/ban', ['ip' => $good, 'hours' => 1, 'SecurityID' => $token]);
            $this->assertSame(302, $response->getStatusCode(), "accepted: '$good'");
            $this->assertTrue($this->isListedAsBanned($good), "banned: '$good'");
        }
    }

    // ------------------------------------------------------------------
    // GridField actions: what the admin screen actually uses
    // ------------------------------------------------------------------

    /**
     * XPath for the one button carrying CSS class $class (exact class token, not a substring).
     */
    private function buttonXpath(string $class): string
    {
        return sprintf('//button[contains(concat(" ", normalize-space(@class), " "), " %s ")]', $class);
    }

    /**
     * Post a GridField action the way GridField's JavaScript does: the button's name, the inputs,
     * and (optionally) the form's token, to the grid's own URL.
     */
    private function postGridAction(string $buttonClass, array $data, ?string $token): HTTPResponse
    {
        $xpath = $this->buttonXpath($buttonClass);
        $buttons = $this->cssParser()->getByXpath($xpath);
        $this->assertCount(1, $buttons, "one button with class $buttonClass");
        $button = $buttons[0];

        $data[(string) $button['name']] = (string) $button['value'] ?: '1';
        # The default StateStore keeps an action's state in the session; AttributeStore puts it here
        if (isset($button['data-action-state'])) {
            $data['ActionState'] = (string) $button['data-action-state'];
        }
        if ($token !== null) {
            $data['SecurityID'] = $token;
        }

        return $this->post((string) $button['data-url'], $data, ['X-Pjax' => 'CurrentField']);
    }

    public function testActiveBansHaveNoGetUnbanLink(): void
    {
        $this->storage()->banIp('192.0.2.30', 3600, 'test');
        $this->get('admin/waf');

        $this->assertStringNotContainsString('admin/waf/unban', $this->content(), 'no link to the unban URL');
        $this->assertCount(1, $this->cssParser()->getByXpath($this->buttonXpath('waf-unban')), 'an unban button instead');
    }

    public function testGridUnbanWithoutSecurityTokenIsRejected(): void
    {
        $this->storage()->banIp('192.0.2.31', 3600, 'test');
        $this->loadAdminToken();

        $response = $this->postGridAction('waf-unban', [], null);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertTrue($this->isListedAsBanned('192.0.2.31'), 'still banned');
    }

    public function testGridUnbanWithTokenUnbans(): void
    {
        $this->storage()->banIp('192.0.2.32', 3600, 'test');
        $token = $this->loadAdminToken();

        $response = $this->postGridAction('waf-unban', [], $token);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertFalse($this->isListedAsBanned('192.0.2.32'), 'unbanned');
        $this->assertStringNotContainsString('192.0.2.32', $response->getBody(), 'the re-rendered grid no longer lists it');
    }

    public function testGridBanWithoutSecurityTokenIsRejected(): void
    {
        $this->loadAdminToken();

        $response = $this->postGridAction('waf-ban', [GridFieldManualBan::FIELD_IP => '192.0.2.33'], null);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertFalse($this->isListedAsBanned('192.0.2.33'), 'not banned');
    }

    public function testGridBanValidatesTheIp(): void
    {
        $token = $this->loadAdminToken();

        $response = $this->postGridAction('waf-ban', [
            GridFieldManualBan::FIELD_IP => '192.0.2.34<b>x</b>',
            GridFieldManualBan::FIELD_HOURS => '2',
        ], $token);
        $this->assertSame(200, $response->getStatusCode());
        $this->assertCount(0, WafStorageService::create()->getActiveBans(), 'nothing was banned');
        $this->assertStringContainsString('is not a valid IPv4 or IPv6 address', $response->getBody());
        $this->assertStringNotContainsString('<b>x</b>', $response->getBody(), 'the message is escaped');

        # Positive control: a valid address is banned, and the re-rendered grid lists it
        $this->get('admin/waf');
        $response = $this->postGridAction('waf-ban', [
            GridFieldManualBan::FIELD_IP => ' 192.0.2.34 ',
            GridFieldManualBan::FIELD_HOURS => '2',
            GridFieldManualBan::FIELD_REASON => 'grid test',
        ], $token);
        $this->assertSame(200, $response->getStatusCode());
        $this->assertTrue($this->isListedAsBanned('192.0.2.34'), 'banned');
        $this->assertStringContainsString('192.0.2.34', $response->getBody());
    }

    // ------------------------------------------------------------------
    // Escaping
    // ------------------------------------------------------------------

    /**
     * Values that reach the admin panels from storage, config or a remote fetch are escaped. The
     * banned "IP" is stored directly, as a tampered or legacy entry would be (the ban form refuses it).
     */
    public function testValuesWithMarkupAreEscaped(): void
    {
        $this->storage()->banIp('"><img src=x onerror=alert(1)>', 3600, 'test');
        Config::modify()->set(WafMiddleware::class, 'privileged_tiers', [
            '<i>tier</i>' => ['factor' => '<u>2</u>', 'ips' => ['<s>203.0.113.9</s>']],
        ]);
        # Blocklist stats from a stub service, not the cache: with silverstripe/versioned installed the
        # cache is namespaced per reading mode, so a value set here would not be seen by the admin request.
        Injector::inst()->registerService(new class extends IpBlocklistService {
            public function getStats(): array
            {
                return [
                    'total_ips' => 1,
                    'total_cidrs' => 0,
                    'total_ranges' => 0,
                    'synced_at' => time(),
                    'sources' => [
                        '<em>feed</em>' => ['count' => 1, 'url' => 'https://example.com/<q>list</q>'],
                        'broken' => ['error' => '<script>alert(2)</script>'],
                    ],
                ];
            }
        }, IpBlocklistService::class);

        $this->get('admin/waf');
        $html = $this->content();

        foreach ([
            '<img src=x onerror=alert(1)>',
            '<i>tier</i>', '<u>2</u>', '<s>203.0.113.9</s>',
            '<em>feed</em>', '<q>list</q>', '<script>alert(2)</script>',
        ] as $raw) {
            $this->assertStringNotContainsString($raw, $html, "printed raw: $raw");
        }
        # And they are shown, escaped (so the assertions above are not passing on absence)
        foreach ([
            '&lt;img src=x onerror=alert(1)&gt;',
            '&lt;i&gt;tier&lt;/i&gt;', '&lt;u&gt;2&lt;/u&gt;', '&lt;s&gt;203.0.113.9&lt;/s&gt;',
            '&lt;em&gt;feed&lt;/em&gt;', '&lt;q&gt;list&lt;/q&gt;', '&lt;script&gt;alert(2)&lt;/script&gt;',
        ] as $escaped) {
            $this->assertStringContainsString($escaped, $html, "shown escaped: $escaped");
        }
    }
}
