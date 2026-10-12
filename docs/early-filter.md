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
`/@vite/`, `/.vite/`, `/node_modules/`, `/asset-manifest.json`, `/__webpack_hmr`

**Exploit endpoints of other apps:**
`/langflow/`, `/flowise/`, `/functionRouter`, `/api/fs/exec`, `/php-cgi/php-cgi.exe`

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

The ban files, violation counters and `config.json` live in a directory named `waf-<uid>-<hash>` (one
per process user and module install) that only the PHP process user can use. Since 1.9.0 its parent is
picked in the order Silverstripe picks its own temp folder (`TEMP_PATH`), so the WAF's files sit where the
site's other caches do. The first that applies wins:

1. **`WAF_DATA_DIR`**, when set: an absolute path, for example a directory inside the project. The WAF
   makes its own `waf-<uid>-<hash>` directory inside it and never changes or cleans `WAF_DATA_DIR` itself,
   so it can be a directory that also holds other things; a dedicated one is still the tidier choice.
2. **`SS_TEMP_PATH`**, the framework's own setting for its temp folder. A relative value is taken under
   the project root, as the framework does. The WAF's directory goes inside it, next to the framework's
   caches.
3. **`<project>/silverstripe-cache`**, when it exists, the framework's first choice when `SS_TEMP_PATH`
   is not set. Its mode does not matter (the framework makes it `0777` itself); the WAF only also needs
   to be able to write to it, and goes on to step 4 when it cannot (for example a directory made by a
   deploy user that the web server user cannot write to), where the framework would fail instead.
4. Otherwise the **system temp directory**, as in 1.8.0.

Both settings must be **real environment variables** (web server or PHP-FPM pool config, e.g.
`env[WAF_DATA_DIR] = ...`), not lines in `.env`: the early filter runs before Silverstripe loads `.env`.
`SS_TEMP_PATH` counts from the process environment and from server variables (a `fastcgi_param`), the
places the framework reads besides `.env`; `WAF_DATA_DIR` from the process environment. A value only in
`.env` is ignored by both layers so that they agree on the directory, and the middleware logs a warning
saying so. For `SS_TEMP_PATH` that means the framework's caches move and the WAF's files do not.

The project root is worked out from where the module is installed (`<project>/vendor/restruct/silverstripe-waf`),
because the early filter runs before Composer's autoloader. A module that is not under a `vendor`
directory, such as a path repository symlinked in for local development, has no project root to go on:
a relative `SS_TEMP_PATH` and `silverstripe-cache` are then skipped.

The directory is created with mode `0700` and its files with `0600`, written atomically. It is only used
while it is a real directory (not a symlink) owned by the process user that nobody else can write to,
checked on one `lstat()`; one of ours that others can only read is tightened to `0700`. Anything else is
refused. The parent directory is not checked: it may be writable by others, as the framework's own
`0777` `silverstripe-cache` and a `0775` deploy-group directory are. (1.8.0 refused such a parent,
because another local user could swap the WAF's directory in it right after the check. If other local
users are attacking your site you have bigger problems than a WAF can solve, so 1.9.0 drops that
requirement.) Only step 3 falls through to the next step; a `WAF_DATA_DIR` or `SS_TEMP_PATH` you set is
never silently replaced by another location.

A refused directory means no early bans and the built-in defaults for the
early filter (pattern blocking still works), and the middleware logs
`[WAF] no private data dir for the early filter ...` at most once an hour.

Inside it, a file is only believed when it is a regular file of the process user: a symlink, or a file
someone else left there while the directory was open, counts as absent. The middleware rewrites a
`config.json` that fails that check or has a modification time in the future. The occasional cleanup
only deletes the WAF's own names (`ban_<md5>`, `viol_<md5>`, and `.tmp-<hex>` left by an interrupted
write).

Up to 1.7.0 the files were in `<system temp dir>/waf_<hash>`, readable by everyone and trusted as found,
so on a host with a shared temp directory other users could read them or plant their own (waf#9). That
directory is no longer read. The middleware removes it when it is a real directory owned by the process
user, deleting only the files 1.7.0 wrote there (`config.json`, `ban_*`, `viol_*`); with anything else
in it, the directory stays. Telling the owner needs PHP's `posix` extension: without it the old
directory is left in place, unused, for you to delete. Early bans and violation counts in it do not
carry over, so on upgrade they start from zero (bans last `ban_duration`, one hour by default).

On a shared host, setting `WAF_DATA_DIR` to a directory inside your own account is the stronger choice:
the default name is predictable, so another user can pre-create it. They cannot read or change what
the WAF keeps there, but the refused directory switches the early ban off until you set `WAF_DATA_DIR`.

**Deploys and lost bans.** Early bans and violation counters are short-lived (`ban_duration`, one hour by
default), and losing them only means a repeat offender has to be caught again. They are lost whenever the
directory changes or is emptied:

- The `<hash>` in the name comes from the module's installation path, so on a zero-downtime deploy (each
  release in its own directory, as Laravel Forge does it) every release starts with an empty data
  directory, wherever its parent is: bans reset on every deploy anyway, so keeping the files in the
  release's `silverstripe-cache` loses nothing a shared location would keep. That was already so in 1.8.0.
- `silverstripe-cache` and a relative `SS_TEMP_PATH` live inside the release, so they are new with each
  release unless the deploy links them in from a shared location, and they go when old releases are
  pruned. Deploy scripts that empty `silverstripe-cache` empty the WAF's files with it. Neither breaks
  anything: the middleware writes `config.json` again on the next request.
- A flush (`?flush=1`, `dev/build flush=1`, `sake db:build --flush`) does not touch the WAF's directory:
  the framework clears its own cache folders and leaves other directories in its temp folder alone
  (checked with `SS_TEMP_PATH` on Silverstripe 5.4 and 6.2).

**Upgrading from 1.8.0.** Nothing moves unless `SS_TEMP_PATH` is set in the real environment or the
project has a `silverstripe-cache` directory; other sites keep using the system temp directory. Where it does
move, the early filter starts from an empty directory and the middleware writes a new `config.json` on the
first request it handles; bans and counters in the old directory are not carried over and expire on their
own. Until that first `config.json` exists the filter runs on its defaults, as after any deploy (see
"Running behind a proxy or CDN" in the README). The old 1.8.0 directory in the system temp directory is private (`0700`)
and no longer read; you can delete it.

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
