# Early Filter

The early filter is a standalone PHP file that runs before Silverstripe loads. It blocks known-bad URL patterns with minimal overhead (~0.1ms), preventing scanners from consuming framework resources.

## Setup

Add to your `public/index.php` **at the very top**, before `use` statements:

```php
<?php

// WAF Early Filter - runs before framework loads
$wafFilter = dirname(__DIR__) . '/vendor/restruct/silverstripe-waf/_waf_early_filter.php';
if (file_exists($wafFilter)) {
    require_once $wafFilter;
}

use SilverStripe\Control\HTTPApplication;
// ... rest of index.php
```

Disable via environment variable:
```bash
WAF_EARLY_FILTER_DISABLED=true
```

## Blocked Patterns

The early filter blocks URL paths like these by default. Since 1.5.0 matching is typed and anchored
against the decoded URL path (not a substring match over the whole URI), and the inventory is
code-level, not YAML config: the authoritative list is `wafBlockedPathEntries()` in `_waf_matching.php`,
which this summary may lag. See [Extending](extending.md#custom-blocked-patterns).

**WordPress probes:**
`/wp-admin`, `/wp-login`, `/wp-content`, `/wp-includes`, `/xmlrpc.php`, `/wp-config`

**PHP backdoors and webshells:**
`/eval-stdin.php`, `/alfacgiapi`, `/alfa-rex`, `/shell.php`, `/c99.php`, `/r57.php`, `/wso.php`

**Config and sensitive files:**
`/.env`, `/.git`, `/.svn`, `/.htpasswd`, `/.htaccess`, `/config.php`, `/configuration.php`, `/LocalSettings.php`, `/web.config`

**Environment config variants** (not caught by the `/.env` entry):
`config.env`, `stripe.env`, `/env.js`, `/env.backup`, `/__env.js`

**Build tool / framework dev probes:**
`/@vite/`, `/.vite/`, `/node_modules/`, `/asset-manifest.json`

**Other CMS admin paths:**
`/administrator/index.php`, `/phpmyadmin`, `/pma/`, `/myadmin/`, `/adminer`

**Path traversal:**
`../`, `..%2f`, `..%252f`

**Random PHP file probes:**
Short PHP filenames matching `/^\/[a-z0-9_]{2,8}\.php$/i` (e.g., `/abc123.php`, `/xyz.php`) are blocked as likely webshell probes. Legitimate files like `/index.php` are whitelisted.

## Early Filter Banning

When enabled (default), the early filter tracks violations per IP using lightweight files. After a configurable threshold (default: 10 violations), the IP is banned for **all URLs** — not just pattern matches. This stops scanners that fire bursts of probes in seconds, without needing fail2ban or any background job.

### How It Works

1. Scanner hits `/wp-admin` — 403 + violation count incremented
2. Scanner hits `/wp-login`, `/.env`, etc. — more violations
3. After 10 violations — IP banned at the PHP level
4. All subsequent requests from that IP — instant 403 (before pattern matching)
5. Ban expires after configured duration (default: 1 hour)

### Performance Impact

| Scenario | Cost |
|----------|------|
| Feature disabled | 0ms |
| Normal traffic (not banned) | ~0.01ms (one `file_exists` check) |
| Banned IP | ~0.02ms (read 20-byte file) |
| Tracking violation (bad traffic only) | ~0.1ms (read+write per-IP file) |

### Configuration

Uses the same `ban_threshold` and `ban_duration` values as the middleware auto-ban (set via YAML config). The middleware writes these to a shared config file that the early filter reads.

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  early_ban_enabled: true   # Toggle early filter banning
  ban_threshold: 10         # Shared: violations before ban
  ban_duration: 3600        # Shared: ban duration in seconds
```

Disable via environment variable (useful for debugging):
```bash
WAF_EARLY_BAN=false
```

### How Config Sharing Works

The early filter runs before the Silverstripe framework, so it can't read YAML config directly. Instead:

1. The middleware writes `ban_threshold`, `ban_duration`, and `early_ban_enabled` to a shared JSON config file (once per hour)
2. The early filter reads this JSON file to get the current config values
3. If the config file doesn't exist yet (first request), the early filter uses sensible defaults (threshold: 10, duration: 3600)

Both components work out the data directory the same way (from the module's installation path and the
real process environment), so they always agree on where to find the files.

### Where the early filter keeps its files

The ban files, violation counters and `config.json` live in a directory that only the PHP process user
can use:

- `WAF_DATA_DIR`, when set: an absolute path, for example a directory inside the project. It must be a
  **real environment variable** (web server or PHP-FPM pool config, e.g. `env[WAF_DATA_DIR] = ...`), not
  a line in `.env`: the early filter runs before Silverstripe loads `.env`. A value only in `.env` is
  ignored by both layers, and the middleware logs a warning saying so.
- Otherwise `<system temp dir>/waf-<uid>-<hash>`, one per process user and module install.

The directory is created with mode `0700` and its files with `0600`, written atomically. It is only used
while it is a real directory (not a symlink) owned by the process user that nobody else can write to:
one of ours that others can only read is tightened to `0700`; anything else is refused. A refused
directory means no early bans and the built-in defaults for the early filter (pattern blocking still
works), and the middleware logs `[WAF] no private data dir for the early filter ...` at most once an hour.

Up to 1.7.0 the files were in `<system temp dir>/waf_<hash>`, readable by everyone and trusted as found,
so on a host with a shared temp directory other users could read them or plant their own (waf#9). That
directory is no longer read; the middleware removes it when it belongs to the process user. Early bans
and violation counts in it do not carry over, so on upgrade they start from zero (bans last
`ban_duration`, one hour by default).

On a shared host, setting `WAF_DATA_DIR` to a directory inside your own account is the stronger choice:
the default name is predictable, so another user can pre-create it. They cannot read or change what
the WAF keeps there, but the refused directory switches the early ban off until you set `WAF_DATA_DIR`.

## Pattern Philosophy

### Why Path Blocking, Not Payload Inspection?

This module intentionally focuses on **path-based blocking** rather than SQLi/XSS payload inspection:

| Approach | False Positive Risk | Value for Silverstripe |
|----------|---------------------|------------------------|
| Path blocking | **Near zero** — paths like `/wp-admin` should never exist | High — stops scanners before framework loads |
| SQLi/XSS filtering | **Higher** — legitimate content may contain patterns | Low — framework already handles this |

**Silverstripe's built-in protection:**
- **SQLi**: ORM uses parameterized queries; `->filter()` escapes automatically
- **XSS**: Templates auto-escape by default; `$casting` system enforces output encoding

**Early filter is best for:**
- Blocking paths that should never be requested (zero false positives)
- Reducing scanner noise and saving resources
- Defense in depth at the perimeter

**For payload inspection**, use ModSecurity at the web server level where it's optimized for this purpose.
