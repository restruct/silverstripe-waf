<?php

namespace Restruct\SilverStripe\Waf\Extensions;

use Restruct\SilverStripe\Waf\Models\PrivilegedIp;
use SilverStripe\Core\Extension;

/**
 * Runs PrivilegedIp's own validation from DataObject::validate()'s extension hook.
 *
 * Applied by PrivilegedIp itself (its $extensions static); projects do not need to configure it.
 *
 * Why an extension and not a validate() override: see PrivilegedIp::validateIpAndFactor().
 *
 * The hook was RENAMED between majors, and a hook with the wrong name fails silently - the method
 * is simply never called and every record validates. So both names are implemented; on each major
 * exactly one of them fires:
 * - Silverstripe 5: DataObject::validate() calls `$this->extend('validate', $result)`
 * - Silverstripe 6: DataObject::validate() calls `$this->extend('updateValidate', $result)`
 *
 * @extends Extension<PrivilegedIp>
 */
class PrivilegedIpValidationExtension extends Extension
{
    /**
     * Silverstripe 6 hook name.
     *
     * @param \SilverStripe\Core\Validation\ValidationResult $result
     */
    public function updateValidate($result): void
    {
        $this->getOwner()->validateIpAndFactor($result);
    }

    /**
     * Silverstripe 5 hook name. Never called on Silverstripe 6 (nothing fires 'validate' there).
     *
     * @param \SilverStripe\ORM\ValidationResult $result
     */
    public function validate($result): void
    {
        $this->getOwner()->validateIpAndFactor($result);
    }
}
