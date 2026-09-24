# Upgrading

## 1.5.x to 1.6.0

1.6.0 keeps one line for Silverstripe 5 and 6 (`composer.json` is the source of truth: framework
`^5.4 || ^6`, PHP `^8.1`). Most sites need to do nothing beyond updating.

**Silverstripe 5.0 to 5.3 are no longer allowed.** The framework floor is now 5.4, the only Silverstripe 5
minor this release is tested on (the admin screen uses list filter syntax whose first 5.x minor is not
known). A site on 5.0-5.3 stays on 1.5.x until it upgrades the framework.

Note on constraints: a project requiring `~1.5.1` or `~1.5.2` means `>=1.5.x <1.6`, so it will **not**
receive 1.6.0 until the constraint is widened (for example to `^1.5`).

### If you are on Silverstripe 6

This is the first release that runs there. Run the blocklist sync task with the Silverstripe 6 syntax:

    vendor/bin/sake tasks:waf-sync-blocklists

`/dev/tasks/waf-sync-blocklists` in the browser is unchanged. Update any cron line that used
`sake dev/tasks/waf-sync-blocklists`.

### If you do not have symbiote/silverstripe-queuedjobs

Nothing to do. Before 1.6.0 such a site fataled on the next flush (deploy, `dev/build`, `?flush=1`);
from 1.6.0 the queued job simply does not exist without queuedjobs. Schedule the sync from cron instead
(see [docs/configuration.md](docs/configuration.md#syncing-blocklists)).

### If you subclass or call module classes

You are affected only if your project extends or calls these directly:

- **`PrivilegedIp::validate()` is no longer overridden.** The checks moved to
  `PrivilegedIp::validateIpAndFactor($result)`, run from `PrivilegedIpValidationExtension` through
  `DataObject::validate()`'s extension hook. A subclass that overrode `validate()` and called
  `parent::validate()` still gets the checks (they now run inside the parent call). Validation results
  are unchanged.
- **`WafStorageService::getActiveBans()` / `getBlockedRequests()`** now declare an `SS_List` return type
  (a union of `SilverStripe\ORM\SS_List` and `SilverStripe\Model\List\SS_List`) instead of `ArrayList`.
  In file and cache mode they still return an ArrayList; in database mode they return a DataList, which
  used to be a TypeError. A subclass overriding them with `: ArrayList` must use a type compatible with
  the new declaration. Code that called `->push()` on the result only works in file/cache mode, as before.
- **`SyncBlocklistsTask`** no longer declares `$title` / `$description` properties (their types differ
  between Silverstripe 5 and 6). Override `getTitle()` in a subclass instead; the description lives in the
  `SyncBlocklistsTask::DESCRIPTION` constant and `lang/en.yml`. The task body moved from `run()` into
  `sync(callable $writeLine)`.

### Dependencies

`silverstripe/admin` is now a declared requirement. Every install already had it (the admin screen
extends `LeftAndMain`), so Composer should resolve without changes.
