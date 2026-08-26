# Changelog

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
