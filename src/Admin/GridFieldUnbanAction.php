<?php

namespace Restruct\SilverStripe\Waf\Admin;

use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridField_ActionProvider;
use SilverStripe\Forms\GridField\GridField_ColumnProvider;
use SilverStripe\Forms\GridField\GridField_FormAction;
use Restruct\SilverStripe\Waf\Services\WafStorageService;

/**
 * An "Unban" button on each row of the WAF admin's Active Bans grid.
 *
 * The button is a GridField action, so it is a POST that GridField sends with the edit form's
 * security token and checks before handleAction() runs (GridField::gridFieldAlterAction()). It
 * replaces the GET link of 1.5.x, which any page could make a WAF admin's browser follow (CSRF).
 *
 * Works on any list of records with an IpAddress field: the ArrayList of file/cache storage mode
 * and the BannedIp DataList of database mode alike.
 */
class GridFieldUnbanAction implements GridField_ColumnProvider, GridField_ActionProvider
{
    public const ACTION = 'wafunban';

    public function augmentColumns($gridField, &$columns)
    {
        if (!in_array('WafActions', $columns)) {
            $columns[] = 'WafActions';
        }
    }

    public function getColumnsHandled($gridField)
    {
        return ['WafActions'];
    }

    public function getColumnMetadata($gridField, $columnName)
    {
        return ['title' => ''];
    }

    public function getColumnAttributes($gridField, $record, $columnName)
    {
        return ['class' => 'grid-field__col-compact'];
    }

    public function getColumnContent($gridField, $record, $columnName)
    {
        $ip = (string) $record->IpAddress;

        # The IP travels in the action's stored state, never in markup that is parsed again.
        # FormField attributes (the title here) are escaped by getAttributesHTML().
        $button = GridField_FormAction::create(
            $gridField,
            'WafUnban' . md5($ip),
            'Unban',
            self::ACTION,
            ['ip' => $ip]
        )
            ->addExtraClass('btn btn-sm btn-outline-danger waf-unban')
            ->setAttribute('title', 'Unban ' . $ip);

        return $button->Field();
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
        $ip = (string) ($arguments['ip'] ?? '');
        if ($ip !== '') {
            $admin->applyUnban($ip);
        }

        # The grid's list was read before this action ran; re-read it so the response shows the change
        $gridField->setList(Injector::inst()->get(WafStorageService::class)->getActiveBans());
    }
}
