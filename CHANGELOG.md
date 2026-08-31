# Changelog

## 1.5.3

### Fixed / Changed

- **Removed the worker-holding soft-rate-limit delay (attack vector).** The soft rate limit
  `usleep()`'d inside the PHP-FPM worker (up to 3s, scaling from the threshold to the hard limit),
  so a "soft-limited" request HELD a scarce worker slot — amplifying the pool exhaustion it appeared
  to defend against. A fast human on an AJAX-per-keystroke UI could trip it, and an attacker could
  use it to pin workers. **Worse: it shipped ON by default** — `_config/config.yml` set
  `soft_rate_limit_enabled: true`, overriding the code static (`false`), so the delay was live on
  every install that didn't explicitly disable it (the 1.5.0 "default off" only changed the static).
- **Soft rate limiting is now NON-BLOCKING.** When enabled and a client is over
  `soft_rate_limit_threshold` % of its hard limit, the served response carries standard
  `X-RateLimit-Limit` / `X-RateLimit-Remaining` headers so well-behaved clients self-throttle before
  the hard 429 — no delay, no held worker. `soft_rate_limit_max_delay` is removed (inert if set).
  Default is off (both static and config.yml aligned); enabling is now safe.
- The default-guard test now checks the **shipped config.yml**, not just the PHP static — the layer
  the previous test missed.

## 1.5.2

### Added

- **Microsoft autodiscover / `FPURL.xml` probes added to the inventory** (waf#1). Exchange/Outlook
  autodiscover probes have no legitimate answer on a Silverstripe site and were the one probe class
  with hard evidence of consuming FPM workers during a real outage. `export: false` — the nginx
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
  `/notshell.php` — the waf#3 false-positive class, reintroduced at the webserver layer.
  Reported by the forge-helper consumer. Export match set is now
  `{exact, prefix, suffix, contains}` — `extension` no longer appears. A consumer maps
  `suffix` → `location ~* <escaped-pattern>$` with the pattern's leading char preserved.
  A new test pins the export shape so this can't silently drift again.

## 1.5.0

Path-matching engine rewrite and default hardening. **Read the "behaviour changes"
below before upgrading** — a few shipped defaults changed on purpose.

### Fixed

- **Early-filter path matching no longer uses unanchored substring matching against the
  full `REQUEST_URI`** (waf#3). The old filter matched every pattern with `stripos()`
  over the whole URI *including the query string*, so `/vacatures/healthcare-manager`
  was blocked by the `/health` pattern (403 + a tracked violation → auto-ban after 10),
  and a site-search for `wp-admin` blocked itself. Matching is now **typed and anchored**
  (`exact` / `prefix` / `segment` / `suffix` / `contains` / `traversal`) against the
  **decoded URL path only** — the query string is never in the match target. Inventory
  and matcher live in the new shared `_waf_matching.php`, so the tests exercise the
  **real** shipped list (the pre-1.5.0 tests kept a *duplicate* list, which is how the
  false positives went unnoticed).

### Behaviour changes (may need action on upgrade)

- **`soft_rate_limit_enabled` now defaults to `false`** (waf#4). The soft limit delayed
  busy clients with a `usleep()` of up to 3s **inside the PHP-FPM worker** — on a
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
  .sql .backup .old .save .tmp`) — downloads are a feature, and on Silverstripe protected
  assets stream through `index.php` so the filter would see them. Kept but re-anchored:
  `/plesk`, `/artisan`, `/phpmyadmin`, webshell basenames, etc.

### Added

- **Verified-crawler rate-limit exemption** (`rate_limit_exempt_verified_bots`, default
  on). Search engines verified by **forward-confirmed reverse DNS** (never UA string
  alone — trivially spoofed) bypass rate limiting only; every other check still applies.
  A Googlebot crawl burst no longer gets soft-delayed/429'd on a site whose content
  exists to be indexed. Verification is lazy (only IPs past the soft threshold) and
  cached 24h. Configure via `verified_bot_signatures` (UA-claim regex → rDNS parents).
- **`resources/blocklist.json`** — the typed inventory as a versioned, schema-stamped
  JSON export (`bin/export-blocklist.php <version>`), for webserver-config generators
  that want one source of truth and emit their own **anchored** forms (nginx `location`,
  Apache). Entries the webserver should not emit (path traversal — the server's URI
  normalisation already rejects it; dotfiles — the stock vhost deny covers them) are
  excluded from the export.

### Known / not yet addressed

- The fixed-window rate counter still allows ~2× the limit across a window boundary
  (tracked in waf#4). Sliding window / token bucket is a future change.
