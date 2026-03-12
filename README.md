# Silverstripe WAF

PHP-level Web Application Firewall for Silverstripe CMS. Blocks vulnerability scanners, malicious bots, and bad IPs without requiring a separate WAF service.

## Features

- **Early PHP Filter** — Blocks requests before Silverstripe loads (minimal overhead)
- **Early Filter Banning** — Self-contained fail2ban alternative, bans repeat offenders at the PHP level
- **Pattern-based blocking** — WordPress probes, webshells, config file access, path traversal
- **IP Blocklists** — Auto-sync from threat intelligence feeds (FireHOL, Binary Defense)
- **Rate Limiting** — Hard limits with soft progressive delays
- **Privileged IPs** — Elevated rate limits for trusted IPs (still subject to all security checks)
- **Auto-banning** — Automatically ban IPs after repeated violations
- **ModelAdmin Guard** — Prevents PHP errors from scanner probes on admin URLs
- **Fail2ban Integration** — Log format compatible with fail2ban filters
- **CMS Admin** — View blocked requests, manage bans and privileged IPs
- **QueuedJobs Support** — Auto-schedules blocklist sync if module is installed

## Requirements

- PHP 8.1+
- Silverstripe Framework 5.0+ or 6.0+

## Installation

```bash
composer require restruct/silverstripe-waf
vendor/bin/sake dev/build flush=1
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

## Quick Configuration

All configuration is in `_config/config.yml` with extensive inline comments. The defaults work well for most sites. Common overrides:

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  rate_limit_requests: 100      # Max requests per IP per minute
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

## Complementary Module

Pairs well with [restruct/silverstripe-security-baseline](https://github.com/restruct/silverstripe-security-baseline) which provides authentication security (password policy, brute-force, logging).

## License

MIT
