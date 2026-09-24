# Changelog

## 1.6.0

Silverstripe 6 support that actually runs, on the same line as Silverstripe 5. `composer.json` already
declared `silverstripe/framework: ^5.0 || ^6.0` since 1.0, but on Silverstripe 6 the module fataled on
the first flush. It is now tested on both majors: 165 tests, same count on Silverstripe 5.4 and 6.2.
See [UPGRADING.md](UPGRADING.md).

### Fixed

- **Security: the WAF admin's ban and unban are protected against cross-site request forgery (CSRF).**
  In 1.5.x unban was a GET link and the manual ban a hand-written POST, neither with a security token,
  and only the `WAF_ADMIN` permission was checked: any page a WAF admin opened could make their browser
  unban or ban an address. The admin screen now does both as GridField actions, which post with the
  form's security token and are refused without it. The `admin/waf/ban` and `admin/waf/unban` URL
  actions accept only a POST with a valid `SecurityID` (405 for a GET, 400 for a missing or wrong token,
  403 without permission). Found by reading the code, not by an observed attack.
- **Security: the manual-ban IP is validated on the server.** It must be a single IPv4 or IPv6 address
  (`FILTER_VALIDATE_IP`); anything else is refused and nothing is stored. Before, only the form's
  `pattern` attribute checked it. Ranges such as `10.0.0.0/8` are refused too: bans are stored per
  exact address, so a range ban never matched a request.
- **Security: values printed in the WAF admin panels are escaped.** A banned IP went unescaped into the
  unban link's inline `onclick` handler, where even an HTML-escaped value is decoded again before the
  JavaScript runs, so a stored value with quotes could run script. Blocklist source names, URLs and
  fetch errors, privileged-tier names, factors and IPs, and the counters are now escaped as well.
- **The manual ban no longer sits in a nested form.** Its `<form>` was nested inside the admin's edit
  form; browsers drop a nested form, so by reading the markup the button could not have posted to the
  ban action. The GridField version is tested over HTTP on both majors, not yet clicked through in a
  browser.
- **`SyncBlocklistsJob` no longer fatals the application when `symbiote/silverstripe-queuedjobs` is not
  installed** (waf#6). Declaring a subclass of a missing parent fataled every flush (deploy, `dev/build`,
  `?flush=1`, cold cache) on both majors, because the config layer autoloads every class in the manifest.
  The YAML `Only: moduleexists` guard does not prevent that; a file-level guard now does.
- **Silverstripe 6: the module loads and runs.** `PrivilegedIp` (a `validate()` return type from the SS5
  namespace) and `SyncBlocklistsTask` (the old BuildTask API) fataled at class load, i.e. on every flush;
  `WafStorageService` failed on first use of its lists (ArrayList/ArrayData moved to `SilverStripe\Model`).
- **Silverstripe 6: `sake db:build` no longer aborts on a site with `silverstripe/errorpage`.** The
  middleware passed a null client IP (an in-process request, as ErrorPage makes when writing its static
  pages) to string-typed checks, a TypeError. On Silverstripe 5 the same TypeError is reachable by any
  request that reaches the middleware without an IP (the Silverstripe 5 database build did not trigger
  it). Requests without a client IP are now passed through, skipping every check, and each one is
  logged at debug level (`[WAF] no client IP, all checks skipped`) so the branch is never silent.
- **Database storage mode: the CMS admin and `getActiveBans()` / `getBlockedRequests()` no longer throw
  a TypeError** (both majors). They returned a DataList from methods typed `: ArrayList`.
- **Silverstripe 6: a manual ban with a reason over 255 characters is no longer silently lost** in
  database mode (field-length validation threw and the exception was swallowed). The reason is truncated.
- **Silverstripe 6: a blocked request with a reason over 50 characters is no longer silently dropped from
  the database log**, for the same reason. The reason is truncated to 50 characters (multibyte-safe).
- **Database storage mode: long multibyte values are truncated in characters, not bytes.** A manual-ban
  reason and a blocked request's URI, user agent and detail over 255 characters were cut at 255 bytes,
  splitting the last multibyte character: MySQL stored it as `?` and kept only part of the value. All
  four now use `mb_substr`, like the blocked-request reason.
- **File storage mode: a blocked request with a long multibyte URI, user agent or detail is no longer
  lost from the JSONL log.** The same byte cut at 255 split the last character, `json_encode()` failed on
  the invalid UTF-8 and a blank line was written in place of the entry. The three fields now use
  `mb_substr`, as in database mode.
- **The WAF admin status panels show the sake command of the running major.** They printed the
  Silverstripe 5 form (`dev/tasks/waf-sync-blocklists`) on Silverstripe 6 too.
- **The early-filter data-provider tests now run on PHPUnit 10+.** They were refused by PHPUnit 11, so
  72 test cases silently never ran on Silverstripe 6.

### Changed

- **The framework floor is `^5.4 || ^6`** (was `^5.0 || ^6.0`). Silverstripe 5.4 is the only 5.x minor this
  release is tested on; a site on 5.0-5.3 stays on 1.5.x. See [UPGRADING.md](UPGRADING.md).
- **The `Restruct\SilverStripe\Waf\EarlyFilter:` block in `_config/config.yml` is commented out**, and
  `docs/extending.md` no longer tells sites to add patterns there. Nothing ever read it (there is no such
  class, and the early filter runs before the framework), so a pattern added there never blocked
  anything. The blocked-path inventory is code-level, in `_waf_matching.php`. CI now runs the config
  audit on both majors and fails on any config key of this module that no class declares.
- `silverstripe/admin` is now declared in `require` (`^2 || ^3`); `WafAdmin` extends `LeftAndMain`, so it
  was always needed and only ever arrived through a recipe. `symbiote/silverstripe-queuedjobs` and
  `silverstripe/errorpage` are listed in `suggest`.
- `SyncBlocklistsTask` serves both BuildTask APIs from one class. On Silverstripe 6 run it as
  `vendor/bin/sake tasks:waf-sync-blocklists`; on Silverstripe 5 `dev/tasks/waf-sync-blocklists` is unchanged.
- `PrivilegedIp` validates through `PrivilegedIpValidationExtension` (applied by the model itself) calling
  the new `PrivilegedIp::validateIpAndFactor()`, instead of overriding `validate()`.
- `WafStorageService::getActiveBans()` and `getBlockedRequests()` declare an `SS_List` return type (a
  union of both majors' SS_List) instead of `ArrayList`.
- `require-dev` is `silverstripe/recipe-testing ^3 || ^4` instead of a bare `phpunit/phpunit ^9.5`.
- `psr/simple-cache` is required as `^3.0` instead of `^1.0 || ^2.0 || ^3.0`; 1 and 2 were never
  installable, since `silverstripe/config` requires `^3.0` on both majors.
- `composer.json` carries a `funding` entry.

### Added

- Behavioural tests on a booted app (validation, schema, task on each major's API, storage lists in every
  mode, middleware request handling, admin form rendering), a CI workflow testing Silverstripe 5 and 6
  with and without queuedjobs, and `.gitattributes` keeping tests out of dist installs.

## 1.5.3

### Fixed / Changed

- **Removed the worker-holding soft-rate-limit delay (attack vector).** The soft rate limit
  `usleep()`'d inside the PHP-FPM worker (up to 3s, scaling from the threshold to the hard limit),
  so a "soft-limited" request HELD a scarce worker slot, amplifying the pool exhaustion it appeared
  to defend against. A fast human on an AJAX-per-keystroke UI could trip it, and an attacker could
  use it to pin workers. **Worse: it shipped ON by default**: `_config/config.yml` set
  `soft_rate_limit_enabled: true`, overriding the code static (`false`), so the delay was live on
  every install that didn't explicitly disable it (the 1.5.0 "default off" only changed the static).
- **Soft rate limiting is now NON-BLOCKING.** When enabled and a client is over
  `soft_rate_limit_threshold` % of its hard limit, the served response carries standard
  `X-RateLimit-Limit` / `X-RateLimit-Remaining` headers so well-behaved clients self-throttle before
  the hard 429: no delay, no held worker. `soft_rate_limit_max_delay` is removed (inert if set).
  Default is off (both static and config.yml aligned); enabling is now safe.
- The default-guard test now checks the **shipped config.yml**, not just the PHP static, the layer
  the previous test missed.

## 1.5.2

### Added

- **Microsoft autodiscover / `FPURL.xml` probes added to the inventory** (waf#1). Exchange/Outlook
  autodiscover probes have no legitimate answer on a Silverstripe site and were the one probe class
  with hard evidence of consuming FPM workers during a real outage. `export: false`: the nginx
  parasite blocklist already owns these as exact-match locations, and a duplicate `location =` would
  be an nginx `[emerg]`; so this closes the gap for **standalone (no-webserver-config) sites** without
  affecting the exported nginx block. 132 tests.

## 1.5.1

### Fixed

- **`resources/blocklist.json` export: `suffix` entries are now emitted as `"match":
  "suffix"`, not `"extension"`.** The 1.5.0 exporter flattened basename-suffix patterns
  (e.g. `/shell.php`) into the same `extension` type as true file-extensions (e.g.
  `.bak`), losing the fact that the leading `/` is significant. A consumer rendering
  `/shell.php` as an extension would emit `~* shell\.php$`, which also matches
  `/notshell.php`, the waf#3 false-positive class, reintroduced at the webserver layer.
  Reported by the forge-helper consumer. Export match set is now
  `{exact, prefix, suffix, contains}`; `extension` no longer appears. A consumer maps
  `suffix` → `location ~* <escaped-pattern>$` with the pattern's leading char preserved.
  A new test pins the export shape so this can't silently drift again.

## 1.5.0

Path-matching engine rewrite and default hardening. **Read the "behaviour changes"
below before upgrading**: a few shipped defaults changed on purpose.

### Fixed

- **Early-filter path matching no longer uses unanchored substring matching against the
  full `REQUEST_URI`** (waf#3). The old filter matched every pattern with `stripos()`
  over the whole URI *including the query string*, so `/vacatures/healthcare-manager`
  was blocked by the `/health` pattern (403 + a tracked violation → auto-ban after 10),
  and a site-search for `wp-admin` blocked itself. Matching is now **typed and anchored**
  (`exact` / `prefix` / `segment` / `suffix` / `contains` / `traversal`) against the
  **decoded URL path only**; the query string is never in the match target. Inventory
  and matcher live in the new shared `_waf_matching.php`, so the tests exercise the
  **real** shipped list (the pre-1.5.0 tests kept a *duplicate* list, which is how the
  false positives went unnoticed).

### Behaviour changes (may need action on upgrade)

- **`soft_rate_limit_enabled` now defaults to `false`** (waf#4). The soft limit delayed
  busy clients with a `usleep()` of up to 3s **inside the PHP-FPM worker**. On a
  worker-constrained host that amplifies the pool-exhaustion failure it appears to
  prevent, and fast human users on AJAX-per-keystroke UIs trigger it. The hard limit
  (429) is unaffected. Re-enable per site if your environment can afford held workers.
- **The empty-User-Agent block (`/^$/i`) is no longer in the shipped default
  `blocked_user_agents`** (waf#5). Legitimate empty-UA senders exist (payment/webhook
  callbacks, naive monitoring, un-flagged `curl` in cron) and a 403 to a webhook is a
  silent integration breaker. Commented in `config.yml`; re-enable per site.
- **Content-vocabulary patterns dropped or re-typed** (waf#5). Removed from defaults as
  "words a site might legitimately publish, not attacker infrastructure": bare `/health`,
  `/metrics`, `/console`, `/debug`, `/api/debug`, `/api/test`, `/sql`, `/db`, `/database`,
  bare `~`, and the archive/db **file extensions** (`.zip .tar .tar.gz .tgz .gz .rar .7z
  .sql .backup .old .save .tmp`): downloads are a feature, and on Silverstripe protected
  assets stream through `index.php` so the filter would see them. Kept but re-anchored:
  `/plesk`, `/artisan`, `/phpmyadmin`, webshell basenames, etc.

### Added

- **Verified-crawler rate-limit exemption** (`rate_limit_exempt_verified_bots`, default
  on). Search engines verified by **forward-confirmed reverse DNS** (never UA string
  alone, which is trivially spoofed) bypass rate limiting only; every other check still applies.
  A Googlebot crawl burst no longer gets soft-delayed/429'd on a site whose content
  exists to be indexed. Verification is lazy (only IPs past the soft threshold) and
  cached 24h. Configure via `verified_bot_signatures` (UA-claim regex → rDNS parents).
- **`resources/blocklist.json`**: the typed inventory as a versioned, schema-stamped
  JSON export (`bin/export-blocklist.php <version>`), for webserver-config generators
  that want one source of truth and emit their own **anchored** forms (nginx `location`,
  Apache). Entries the webserver should not emit (path traversal, since the server's URI
  normalisation already rejects it; dotfiles, since the stock vhost deny covers them) are
  excluded from the export.

### Known / not yet addressed

- The fixed-window rate counter still allows ~2× the limit across a window boundary
  (tracked in waf#4). Sliding window / token bucket is a future change.
