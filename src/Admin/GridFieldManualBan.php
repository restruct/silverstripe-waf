<?php

namespace Restruct\SilverStripe\Waf\Admin;

use SilverStripe\Core\Convert;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridField_ActionProvider;
use SilverStripe\Forms\GridField\GridField_FormAction;
use SilverStripe\Forms\GridField\GridField_HTMLProvider;
use Restruct\SilverStripe\Waf\Services\WafStorageService;

/**
 * The "Manual Ban" inputs under the WAF admin's Active Bans grid.
 *
 * The inputs are plain named inputs inside the edit form, and "Ban IP" is a GridField action:
 * GridField posts it with every input of the form (these three included) and the form's security
 * token, and checks the token before handleAction() runs. The IP is then validated server-side by
 * WafAdmin::applyManualBan(); an invalid one bans nothing and shows a message on the grid.
 *
 * This replaces the 1.5.x LiteralField, a <form> nested inside the edit form: browsers drop a nested
 * form, it carried no security token, and the IP was checked only by a pattern attribute.
 */
class GridFieldManualBan implements GridField_HTMLProvider, GridField_ActionProvider
{
    public const ACTION = 'wafban';

    # Input names, unique within the edit form (GridField posts the whole form)
    public const FIELD_IP = 'WafBanIp';
    public const FIELD_HOURS = 'WafBanHours';
    public const FIELD_REASON = 'WafBanReason';

    public function getHTMLFragments($gridField)
    {
        $button = GridField_FormAction::create($gridField, 'WafManualBan', 'Ban IP', self::ACTION, [])
            ->addExtraClass('btn btn-warning waf-ban');

        $ip = Convert::raw2att(self::FIELD_IP);
        $hours = Convert::raw2att(self::FIELD_HOURS);
        $reason = Convert::raw2att(self::FIELD_REASON);
        $buttonHtml = $button->Field();

        # no-change-track: typing here should not mark the whole edit form as having unsaved changes.
        # The pattern/min/max attributes are a convenience only; the server validates the values.
        $html = <<<HTML
<div class="waf-manual-ban" style="background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 4px; border: 1px solid #ffc107;">
    <h4 style="margin-top: 0;">Manual Ban</h4>
    <div style="display: flex; gap: 10px; align-items: end;">
        <div>
            <label for="{$ip}">IP Address</label><br>
            <input type="text" id="{$ip}" name="{$ip}" class="no-change-track" pattern="[0-9a-fA-F.:]+" placeholder="1.2.3.4" style="padding: 5px;">
        </div>
        <div>
            <label for="{$hours}">Duration (hours)</label><br>
            <input type="number" id="{$hours}" name="{$hours}" class="no-change-track" value="24" min="1" max="8760" style="padding: 5px; width: 80px;">
        </div>
        <div>
            <label for="{$reason}">Reason</label><br>
            <input type="text" id="{$reason}" name="{$reason}" class="no-change-track" value="Manual ban" style="padding: 5px; width: 200px;">
        </div>
        {$buttonHtml}
    </div>
</div>
HTML;

        return ['after' => $html];
    }

    public function getActions($gridField)
    {
        return [self::ACTION];
    }

    public function handleAction(GridField $gridField, $actionName, $arguments, $data)
    {
        if ($actionName !== self::ACTION) {
            return;
        }

        $admin = WafAdmin::fromGridField($gridField);
        $ip = trim((string) ($data[self::FIELD_IP] ?? ''));
        $applied = $admin->applyManualBan(
            $ip,
            (int) ($data[self::FIELD_HOURS] ?? 0),
            (string) ($data[self::FIELD_REASON] ?? '')
        );

        if (!$applied) {
            # Shown under the grid in the response; FormField messages are escaped when rendered
            $gridField->setMessage("Not banned: '{$ip}' is not a valid IPv4 or IPv6 address.", 'error');
            return;
        }

        # The grid's list was read before this action ran; re-read it so the response shows the ban
        $gridField->setList(Injector::inst()->get(WafStorageService::class)->getActiveBans());
    }
}
