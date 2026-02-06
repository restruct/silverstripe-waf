# Silverstripe WAF

PHP-level Web Application Firewall for Silverstripe CMS. Blocks vulnerability scanners, malicious bots, and bad IPs without requiring a separate WAF service.

## Features

- **Early PHP Filter** - Blocks requests before Silverstripe loads (minimal overhead)
- **Pattern-based blocking** - WordPress probes, webshells, config file access, path traversal
- **IP Blocklists** - Auto-sync from threat intelligence feeds (FireHOL, Binary Defense)
- **Rate Limiting** - Hard limits with soft progressive delays
- **Auto-banning** - Automatically ban IPs after repeated violations
- **Fail2ban Integration** - Log format compatible with fail2ban filters
- **CMS Admin** - View blocked requests and manage bans (no database required)
- **QueuedJobs Support** - Auto-schedules blocklist sync if module is installed

## Requirements

- PHP 8.1+
- Silverstripe Framework 5.0+ or 6.0+

## Installation

```bash
composer require restruct/silverstripe-waf
vendor/bin/sake dev/build flush=1
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

## Performance & Resource Footprint

This module is designed for minimal impact on legitimate traffic while effectively blocking malicious requests.

### TTFB Impact

| Check | Cost | Notes |
|-------|------|-------|
| Early filter | < 0.1ms | Pattern matching before framework loads |
| Whitelist check | ~0.01ms | O(1) array lookup |
| Ban check | ~0.5ms | Single cache get |
| Blocklist check | ~0.5ms | O(1) with per-IP caching* |
| User-agent check | ~0.1ms | Regex matching |
| Rate limit | ~1ms | Two cache operations |
| **Total overhead** | **2-3ms** | ~2-5% of typical page load |

*First lookup for a new IP uses O(log n) binary search through sorted IP ranges. Result is cached for 60s, so repeat requests from the same IP are O(1).

### Memory & Storage

| Resource | Size | Notes |
|----------|------|-------|
| Blocklist download | ~72 KB | FireHOL Level 1 + Binary Defense, every 6h |
| Cache: blocklist | ~500 KB | ~4,500 CIDRs stored as optimized ranges |
| Cache: rate data | ~60 bytes/IP | Rate counters + violation counts |
| Cache: total | ~1-2 MB | Under moderate load (10K unique IPs) |

The module uses chunked cache storage (500 entries per chunk) to work within Memcached's 1MB item limit.

### Performance Optimizations

1. **Per-IP result caching** - Blocklist lookup results are cached for 60s per IP, eliminating repeated lookups for the same visitor

2. **Binary search for IP ranges** - CIDRs are converted to sorted IP ranges at sync time. Lookups use O(log n) binary search instead of O(n) linear scan

3. **High-load auto-fallback** - When under attack (>100 violations/minute), automatically skips file/DB persistence and runs in pure cache mode

4. **Overlapping range merging** - Adjacent/overlapping CIDRs are merged during sync, reducing the number of ranges to search

### Comparison

| Approach | TTFB Impact | Notes |
|----------|-------------|-------|
| This WAF module | 2-3ms | PHP-level, no external service |
| Cloudflare WAF | ~50-100ms | DNS proxy, geographic latency |
| Apache mod_security | 5-20ms | Depends on ruleset complexity |
| No WAF | 0ms | But vulnerable to attacks |

## Configuration

All configuration is in `_config/config.yml` with extensive comments. Key options:

### Storage Modes

| Mode | DB Queries | Persistence | CMS Admin | Use Case |
|------|------------|-------------|-----------|----------|
| `cache` | **None** | Until cache expires | Limited | Under attack, max performance |
| `file` (default) | **None** | JSON files | Full | Normal operation, most sites |
| `database` | Some | Full DB | Full | Audit requirements, large teams |

```yaml
Restruct\SilverStripe\Waf\Services\WafStorageService:
  storage_mode: 'file'
  high_load_threshold: 100  # Auto-switch to cache under attack
```

### Rate Limiting

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  # Hard limit
  rate_limit_requests: 100    # Max requests per IP per window
  rate_limit_window: 60       # Window in seconds

  # Soft limit (progressive delays before hard block)
  soft_rate_limit_threshold: 50   # % of hard limit where delays start
  soft_rate_limit_max_delay: 3000 # Max delay in milliseconds
```

**Soft rate limiting behavior:**

| Requests (of 100 limit) | Delay |
|-------------------------|-------|
| 50 (threshold) | 0ms |
| 60 | 600ms |
| 75 | 1500ms |
| 90 | 2400ms |
| 99 | 2940ms |
| 100+ | Blocked (429) |

### IP Whitelist

Supports single IPs and CIDR notation:

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  whitelisted_ips:
    - '127.0.0.1'
    - '::1'
    - '10.0.0.0/8'      # Internal network
    - '192.168.1.0/24'  # Office network
```

Or via environment variable:
```bash
WAF_WHITELIST_IPS="1.2.3.4,5.6.7.8,10.0.0.0/8"
```

### Blocklist Sources

```yaml
Restruct\SilverStripe\Waf\Services\IpBlocklistService:
  blocklist_sources:
    firehol_level1:
      url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset'
      enabled: true
      format: 'cidr'

    binarydefense:
      url: 'https://www.binarydefense.com/banlist.txt'
      enabled: true
      format: 'ip'

  # Custom local blocklist (one IP/CIDR per line)
  local_blocklist_file: '/path/to/custom-blocklist.txt'
```

## Syncing Blocklists

### Manual

```bash
vendor/bin/sake dev/tasks/waf-sync-blocklists
```

### Cron (recommended every 6 hours)

```cron
0 */6 * * * cd /path/to/site && vendor/bin/sake dev/tasks/waf-sync-blocklists
```

### QueuedJobs (automatic)

If `symbiote/silverstripe-queuedjobs` is installed, the sync job auto-schedules every 6 hours. No manual cron setup required.

The job is automatically created on first `dev/build` or when running:
```bash
vendor/bin/sake dev/tasks/ProcessJobQueueTask
```

## CMS Admin

Access via **WAF** menu item in the CMS:

- View blocked request log (most recent first)
- Manage banned IPs (add/remove bans)
- View blocklist sync status and source health

Works in all storage modes - no database required for `file` mode.

## Fail2ban Integration

The WAF logs in a fail2ban-compatible format:

```
[WAF] BLOCKED reason=blocked_pattern ip=1.2.3.4 uri="/wp-admin/"
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

The early filter blocks these by default:

**WordPress probes:** `/wp-admin`, `/wp-login`, `/wp-content`, `/xmlrpc.php`

**Webshells:** `/shell.php`, `/c99.php`, `/r57.php`, `/eval-stdin.php`, random PHP probes (`/xyz123.php`)

**Config files:** `/.env`, `/.git`, `/.htaccess`, `/config.php`

**Other CMS:** `/phpmyadmin`, `/adminer`, `/administrator/`

**Path traversal:** `../`, `..%2f`, `..%252f`

## Extending

### Add Custom Blocked Patterns

```yaml
Restruct\SilverStripe\Waf\EarlyFilter:
  blocked_patterns:
    - '/my-custom-block'
    - '/another-pattern'
```

### Add Custom Blocklist Source

```yaml
Restruct\SilverStripe\Waf\Services\IpBlocklistService:
  blocklist_sources:
    my_custom_list:
      url: 'https://example.com/blocklist.txt'
      enabled: true
      format: 'ip'  # or 'cidr' or 'cidr_semicolon'
```

## Environment Variables

```bash
# Disable WAF completely
WAF_ENABLED=false

# Disable early filter only
WAF_EARLY_FILTER_DISABLED=true

# Whitelist IPs
WAF_WHITELIST_IPS="1.2.3.4,5.6.7.8"

# Override storage mode
WAF_STORAGE_MODE=cache
```

## Complementary Module

This module pairs well with [restruct/silverstripe-security-baseline](https://github.com/restruct/silverstripe-security-baseline) which provides authentication security:

| Module | Focus |
|--------|-------|
| **silverstripe-waf** | Perimeter security (request filtering, IP blocking) |
| **silverstripe-security-baseline** | Authentication security (password policy, brute-force, logging) |

## License

BSD-3-Clause
