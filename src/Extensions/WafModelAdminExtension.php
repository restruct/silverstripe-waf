<?php

namespace Restruct\SilverStripe\Waf\Extensions;

use SilverStripe\Admin\ModelAdmin;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Extension;

/**
 * Prevents ModelAdmin from triggering errors on invalid ModelClass requests
 *
 * Scanners probe admin URLs with garbage paths like /admin/my-admin//sito/wp-includes/...
 * which ModelAdmin tries to resolve as model class names, causing PHP errors.
 *
 * This extension intercepts invalid ModelClass requests before init() and returns
 * a 404 response, optionally with a JS fork bomb to waste the scanner's resources.
 *
 * @extends Extension<ModelAdmin>
 */
class WafModelAdminExtension extends Extension
{
    use Configurable;

    # Return a JS fork bomb in the 404 response body (wastes scanner resources)
    private static bool $forkbomb = true;

    public function onBeforeInit(): void
    {
        /** @var ModelAdmin $owner */
        $owner = $this->getOwner();
        $request = $owner->getRequest();
        $modelClass = $request->param('ModelClass');

        # No ModelClass parameter — let ModelAdmin handle it (shows default model)
        if (!$modelClass) {
            return;
        }

        # Unsanitise: ModelAdmin uses hyphens in URLs for namespace backslashes
        $unsanitised = str_replace('-', '\\', $modelClass);
        $managedModels = $owner->getManagedModels();

        if (array_key_exists($unsanitised, $managedModels)) {
            return; # Valid model — proceed normally
        }

        # Invalid ModelClass — log and block
        error_log(sprintf(
            '[WAF] BLOCKED reason=invalid_modelclass ip=%s uri="%s"',
            $request->getIP(),
            substr($request->getURL(true), 0, 200)
        ));

        # 500 instead of 404 — looks like a normal error, doesn't reveal the trap
        $response = HTTPResponse::create()->setStatusCode(500);

        if (static::config()->get('forkbomb')) {
            # JS fork bomb: creates infinite intervals, eats scanner resources
            $forkBomb = '(_ = () => setInterval(_, 0))()';
            $response->addHeader('Content-Type', 'text/html; charset=utf-8');
            $response->setBody("<script>{$forkBomb}</script><noscript>This page requires JavaScript to be enabled.</noscript>");
        } else {
            $response->addHeader('Content-Type', 'text/plain');
            $response->setBody('Not Found');
        }

        throw new HTTPResponse_Exception($response);
    }
}
