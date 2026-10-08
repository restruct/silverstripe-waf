# Silverstripe WAF

*Maintained by [Restruct](https://github.com/restruct). If this module saves you time, you can
[support ongoing maintenance](https://github.com/sponsors/restruct).*

PHP-level Web Application Firewall for Silverstripe CMS. Blocks vulnerability scanners, malicious bots, and bad IPs without requiring a separate WAF service.

## Features

- **Early PHP Filter** — Blocks requests before Silverstripe loads (minimal overhead)
- **Early Filter Banning** — Self-contained fail2ban alternative, bans repeat offenders at the PHP level
- **Pattern-based blocking** — WordPress probes, webshells, config file access, path traversal
- **IP Blocklists** — Auto-sync from threat intelligence feeds (FireHOL, Binary Defense)
- **Rate Limiting** — Hard limits (429), with optional non-blocking backoff headers before the limit
- **Privileged IPs** — Elevated rate limits for trusted IPs (still subject to all security checks)
- **Auto-banning** — Automatically ban IPs after repeated violations
- **ModelAdmin Guard** — Prevents PHP errors from scanner probes on admin URLs
- **Fail2ban Integration** — Log format compatible with fail2ban filters
- **CMS Admin** — View blocked requests, manage bans and privileged IPs
- **QueuedJobs Support** — Auto-schedules blocklist sync if module is installed

## Requirements

- PHP 8.1+ (Silverstripe 6 itself needs 8.3+)
- Silverstripe 5.4+ or 6, with `silverstripe/admin`
- Optional: `symbiote/silverstripe-queuedjobs` (scheduled blocklist sync), `silverstripe/errorpage`
  (styled 429 page)

| Branch | Module version | Silverstripe | PHP |
|--------|----------------|--------------|-----|
| `main` | `1.6.x` | `^5.4 \|\| ^6` | `^8.1` |
| (tags only) | `1.0` - `1.5.x` | `^5` (declared `^5 \|\| ^6`, but did not run on 6) | `^8.1` |
| `ss3` | `0.x` | `~3.1` | `>=7.4` |

`composer.json` is the source of truth; this table is a convenience copy. The Silverstripe 5 range is
maintained until Silverstripe 5 reaches end of life in April 2027. Upgrading from 1.5.x: see
[UPGRADING.md](UPGRADING.md).

## Installation

```bash
composer require restruct/silverstripe-waf
vendor/bin/sake dev/build flush=1        # Silverstripe 5
vendor/bin/sake db:build --flush         # Silverstripe 6
```

### Enable Early Filter (Recommended)

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

**Why before `use` statements?** The `use` statements are just namespace aliases (resolved at compile time), so the practical difference is minimal. However, placing the WAF filter first makes the security-first intent clear and ensures blocked requests parse the absolute minimum PHP before exiting.

## Running behind a proxy or CDN

Behind a reverse proxy, load balancer or CDN (Cloudflare, a Forge load balancer, Varnish), every request
arrives from the proxy's address, and the visitor's address is in the `X-Forwarded-For` (or `Client-IP`)
header. Tell Silverstripe which proxies to believe, in `.env`:

```
SS_TRUSTED_PROXY_IPS="10.0.0.0/8,172.16.0.0/12"
```

A comma-separated list of addresses and CIDR ranges (IPv4 and IPv6), or `*` for any sender. Only use `*`
when the web server cannot be reached except through the proxy: the header is set by whoever sends the
request, so trusting it from anyone lets anyone choose the address they are judged by.

Both layers of the WAF then judge the visitor, not the proxy:

- **The middleware** takes the client address from Silverstripe's `TrustedProxyMiddleware`, with the same
  headers and the same choice from a list of addresses.
- **The early filter** runs before the framework and before `.env` is loaded. It takes the list from a real
  environment variable when there is one (set in the web server or PHP-FPM config), otherwise from the
  config file the middleware writes for it (in the early filter's private data dir, refreshed at most
  hourly; see [Early Filter](docs/early-filter.md#where-the-early-filter-keeps-its-files)).
  Until the middleware has written that file, for example on the first request after a deploy, the early
  filter uses the connecting address and ignores the header. It never believes the header from a sender
  that is not on the list.

**The proxy must overwrite `X-Forwarded-For`, not append to it.** Like Silverstripe itself, the WAF picks
the left-most public address from that header. A proxy that appends to a header the client already sent
leaves the client's own (possibly fake) entry first, so the client chooses the address it is judged by.
Configure the proxy to replace the header with the connecting address (Cloudflare and most managed load
balancers do this; for nginx use `proxy_set_header X-Forwarded-For $remote_addr;` rather than
`$proxy_add_x_forwarded_for`), or restore the address in the web server as described below.

Without `SS_TRUSTED_PROXY_IPS`, both layers see only the proxy's address: bans and rate limits then hit
the proxy, and one attacker's violations can ban every visitor behind it. The alternative is to have the
web server restore the client address before PHP runs (nginx `real_ip`, Apache `mod_remoteip`), in which
case `SS_TRUSTED_PROXY_IPS` is not needed.

## Quick Configuration

All configuration is in `_config/config.yml` with extensive inline comments. The defaults work well for most sites. Common overrides:

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  rate_limit_requests: 150      # Max requests per IP per minute
  ban_threshold: 10             # Violations before auto-ban
  ban_duration: 3600            # Ban duration in seconds (1 hour)
  early_ban_enabled: true       # Self-contained fail2ban alternative

  whitelisted_ips:
    - '127.0.0.1'
    - '::1'
    # - '10.0.0.0/8'            # Office network
```

## CMS Admin

Access via the **WAF** menu item in the CMS:

- **Blocked Requests** — View blocked request log with reason, detail, URI, and user agent
- **Banned IPs** — Manage banned IPs (add/remove bans)
- **Privileged IPs** — Manage elevated rate limits for trusted IPs (protected from auto-ban)
- **Blocklist Status** — View sync status and source health

Works in all storage modes — no database required for `file` mode.

## Documentation

| Topic | Description |
|-------|-------------|
| [Configuration](docs/configuration.md) | Storage modes, rate limiting, whitelists, privileged IPs, user-agents |
| [Early Filter](docs/early-filter.md) | Blocked patterns, early banning, pattern philosophy |
| [ModelAdmin Guard](docs/modeladmin-guard.md) | Protect ModelAdmin from scanner probes |
| [Fail2ban](docs/fail2ban.md) | Fail2ban integration + Laravel Forge setup |
| [Performance](docs/performance.md) | TTFB benchmarks, memory footprint, optimizations |
| [Extending](docs/extending.md) | Custom patterns, blocklist sources, environment variables, testing |

## Running the tests

The suites need a booted Silverstripe app, so run them from a host project that installs this module
as a symlinked path repository (`/tests` is export-ignored, so a dist install contains no tests):

```bash
vendor/bin/phpunit vendor/restruct/silverstripe-waf/tests flush=1          # Silverstripe 5
SS_PHPUNIT_FLUSH=1 vendor/bin/phpunit vendor/restruct/silverstripe-waf/tests  # Silverstripe 6
```

`.github/workflows/ci.yml` builds exactly such a host for each supported major.

## Complementary Module

Pairs well with [restruct/silverstripe-security-baseline](https://github.com/restruct/silverstripe-security-baseline) which provides authentication security (password policy, brute-force, logging).

## License

MIT
