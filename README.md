# Silverstripe WAF

PHP-level Web Application Firewall for Silverstripe CMS. Blocks vulnerability scanners, malicious bots, and bad IPs without requiring a separate WAF service.

## Features

- **Early PHP Filter** - Blocks requests before Silverstripe loads (minimal overhead)
- **Pattern-based blocking** - WordPress probes, webshells, config file access, path traversal
- **IP Blocklists** - Auto-sync from threat intelligence feeds (FireHOL, Binary Defense)
- **Rate Limiting** - Hard limits with soft progressive delays
- **Auto-banning** - Automatically ban IPs after repeated violations
- **Fail2ban Integration** - Log format compatible with fail2ban filters
- **CMS Admin** - View blocked requests and manage bans

## Requirements

- PHP 8.1+
- Silverstripe Framework 5.0+ or 6.0+

## Installation

```bash
composer require restruct/silverstripe-waf
```

### Enable Early Filter (Recommended)

Add to your `public/index.php` **before** the Silverstripe bootstrap:

```php
<?php

// WAF Early Filter - runs before framework loads
$wafFilter = dirname(__DIR__) . '/vendor/restruct/silverstripe-waf/public/_waf_early_filter.php';
if (file_exists($wafFilter)) {
    require_once $wafFilter;
}

// Silverstripe bootstrap
require dirname(__DIR__) . '/vendor/autoload.php';

// ... rest of index.php
```

### Build Database

```bash
vendor/bin/sake dev/build flush=1
```

## Configuration

### Basic Configuration (YAML)

```yaml
# app/_config/waf.yml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  # Enable/disable
  enabled: true

  # Storage mode: 'cache' (default) or 'database'
  # - cache: Uses PSR-16 cache only (fast, no DB queries)
  # - database: Also persists to DB (survives cache clear, enables CMS admin)
  storage_mode: 'cache'

  # Rate limiting (hard block)
  rate_limit_enabled: true
  rate_limit_requests: 100    # Max requests per minute
  rate_limit_window: 60       # Window in seconds

  # Soft rate limiting (progressive delays)
  soft_rate_limit_enabled: true
  soft_rate_limit_threshold: 50   # Start delaying at 50% of hard limit
  soft_rate_limit_max_delay: 3000 # Max 3 second delay

  # Auto-ban
  auto_ban_enabled: true
  ban_threshold: 10           # Violations before auto-ban
  ban_duration: 3600          # Ban duration (1 hour)

  # Whitelisted IPs
  whitelisted_ips:
    - '127.0.0.1'
    - '10.0.0.0/8'            # Internal network
```

### Storage Modes

The module supports three storage modes, configurable via `WafStorageService.storage_mode`:

| Mode | DB Queries | Persistence | CMS Admin | Use Case |
|------|------------|-------------|-----------|----------|
| `cache` | **None** | Until cache expires | Limited | Under attack, max performance |
| `file` (default) | **None** | JSON files | Full | Normal operation, no DB overhead |
| `database` | Some | Full DB | Full | Audit requirements, large teams |

```yaml
Restruct\SilverStripe\Waf\Services\WafStorageService:
  storage_mode: 'file'                    # 'cache', 'file', or 'database'
  blocked_log_file: 'silverstripe-cache/waf_blocked.jsonl'
  bans_file: 'silverstripe-cache/waf_bans.json'
  max_log_entries: 1000
  high_load_threshold: 100                # Auto-switch to cache under attack
```

**High-load auto-fallback:** When violations per minute exceed `high_load_threshold`, the module automatically skips file/DB persistence and operates in pure cache mode. This prevents disk I/O from becoming a bottleneck during attacks.

### IP Blocklist Chunking (Memcached Compatible)

The blocklist sync handles large IP lists (600K+ IPs) by chunking data:
- Metadata in one key
- CIDRs split into 500-entry chunks (~20KB each)
- Works within Memcached's 1MB item limit

For best performance, use `file` mode with Memcached/Redis:

### Environment Variables

```bash
# Disable early filter
WAF_EARLY_FILTER_DISABLED=true

# Whitelist IPs (comma-separated)
WAF_WHITELIST_IPS="1.2.3.4,5.6.7.8"
```

### IP Blocklist Sources

Configure threat intelligence feeds:

```yaml
Restruct\SilverStripe\Waf\Services\IpBlocklistService:
  sync_enabled: true
  cache_duration: 3600

  blocklist_sources:
    firehol_level1:
      url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset'
      enabled: true
      format: 'cidr'

    binarydefense:
      url: 'https://www.binarydefense.com/banlist.txt'
      enabled: true
      format: 'ip'

  # Custom local blocklist
  local_blocklist_file: '/path/to/custom-blocklist.txt'
```

## Sync Blocklists

Run manually:

```bash
vendor/bin/sake dev/tasks/waf-sync-blocklists
```

Schedule via cron (recommended every 6 hours):

```cron
0 */6 * * * cd /path/to/site && vendor/bin/sake dev/tasks/waf-sync-blocklists
```

## CMS Admin

Access via **WAF** menu item in the CMS:

- View blocked request log
- Manage banned IPs (add/remove permanent bans)
- View blocklist sync status

## Rate Limiting Behavior

### Hard Limit
Requests exceeding the hard limit receive `429 Too Many Requests`.

### Soft Limit (Progressive Delay)
As requests approach the hard limit, progressive delays are applied:

| Requests (of 100 limit) | Delay |
|-------------------------|-------|
| 50 (threshold) | 0ms |
| 60 | 600ms |
| 75 | 1500ms |
| 90 | 2400ms |
| 99 | 2940ms |
| 100+ | Blocked (429) |

This slows down aggressive bots while allowing legitimate users occasional bursts.

## Fail2ban Integration

The WAF logs in a fail2ban-compatible format:

```
[WAF] BLOCKED reason=blocked_pattern pattern="/wp-admin" ip=1.2.3.4 uri="/wp-admin/"
```

### Fail2ban Filter

Create `/etc/fail2ban/filter.d/silverstripe-waf.conf`:

```ini
[Definition]
failregex = \[WAF\] BLOCKED .* ip=<HOST>
ignoreregex =
```

### Fail2ban Jail

Create `/etc/fail2ban/jail.d/silverstripe-waf.conf`:

```ini
[silverstripe-waf]
enabled = true
port = http,https
filter = silverstripe-waf
logpath = /var/log/php-fpm/error.log
maxretry = 5
findtime = 300
bantime = 3600
```

## Blocked Patterns

The early filter blocks these patterns by default:

### WordPress Probes
- `/wp-admin`, `/wp-login`, `/wp-content`, `/xmlrpc.php`

### Webshells
- `/shell.php`, `/c99.php`, `/r57.php`, `/eval-stdin.php`
- Random PHP probes (e.g., `/bgymj.php`, `/ws38.php`)

### Config Files
- `/.env`, `/.git`, `/.htaccess`, `/config.php`

### Other CMS
- `/phpmyadmin`, `/adminer`, `/administrator/`

### Path Traversal
- `../`, `..%2f`, `..%252f`

## Extending

### Custom Blocked Patterns

Add to YAML config:

```yaml
Restruct\SilverStripe\Waf\EarlyFilter:
  blocked_patterns:
    - '/my-custom-block'
    - '/another-pattern'
```

### Custom Blocklist Source

```yaml
Restruct\SilverStripe\Waf\Services\IpBlocklistService:
  blocklist_sources:
    my_custom_list:
      url: 'https://example.com/blocklist.txt'
      enabled: true
      format: 'ip'  # or 'cidr' or 'cidr_semicolon'
```

## Complementary Module

This module pairs well with [restruct/silverstripe-security-baseline](https://github.com/restruct/silverstripe-security-baseline) which provides authentication security (OWASP guidelines):

| Module | Focus |
|--------|-------|
| **silverstripe-waf** | Perimeter security (request filtering, IP blocking) |
| **silverstripe-security-baseline** | Authentication security (password policy, brute-force, logging) |

## License

BSD-3-Clause
