# Silverstripe WAF

PHP-level Web Application Firewall for Silverstripe CMS. Blocks vulnerability scanners, malicious bots, and bad IPs without requiring a separate WAF service.

## Features

- **Early PHP Filter** - Blocks requests before Silverstripe loads (minimal overhead)
- **Early Filter Banning** - Self-contained fail2ban alternative, bans repeat offenders at the PHP level
- **Pattern-based blocking** - WordPress probes, webshells, config file access, path traversal
- **IP Blocklists** - Auto-sync from threat intelligence feeds (FireHOL, Binary Defense)
- **Rate Limiting** - Hard limits with soft progressive delays
- **Privileged IPs** - Elevated rate limits for trusted IPs (still subject to all security checks)
- **Auto-banning** - Automatically ban IPs after repeated violations
- **Fail2ban Integration** - Log format compatible with fail2ban filters
- **CMS Admin** - View blocked requests, manage bans and privileged IPs
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

Add to your `public/index.php` **at the very top**, before `use` statements:

```php
<?php

// WAF Early Filter - runs before framework loads
$wafFilter = dirname(__DIR__) . '/vendor/restruct/silverstripe-waf/_waf_early_filter.php';
if (file_exists($wafFilter)) {
    require_once $wafFilter;
}

use SilverStripe\Control\HTTPApplication;
use SilverStripe\Control\HTTPRequestBuilder;
use SilverStripe\Core\CoreKernel;

// ... rest of index.php
```

**Why before `use` statements?** The `use` statements are just namespace aliases (resolved at compile time), so the practical difference is minimal. However, placing the WAF filter first makes the security-first intent clear and ensures blocked requests parse the absolute minimum PHP before exiting.

### Early Filter Banning (Self-Contained Fail2ban Alternative)

When enabled (default), the early filter tracks violations per IP using lightweight files. After a configurable threshold (default: 10 violations), the IP is banned for **all URLs** — not just pattern matches. This stops scanners that fire bursts of probes in seconds, without needing fail2ban or any background job.

**How it works:**

1. Scanner hits `/wp-admin` → 403 + violation count incremented
2. Scanner hits `/wp-login`, `/.env`, etc. → more violations
3. After 10 violations → IP banned at the PHP level
4. All subsequent requests from that IP → instant 403 (before pattern matching)

**Performance impact:**

| Scenario | Cost |
|----------|------|
| Feature disabled | 0ms |
| Normal traffic (not banned) | ~0.01ms (one `file_exists` check) |
| Banned IP | ~0.02ms (read 20-byte file) |
| Tracking violation (bad traffic only) | ~0.1ms (read+write per-IP file) |

**Configuration** uses the same `ban_threshold` and `ban_duration` values as the middleware auto-ban (set via YAML config). The middleware writes these to a shared config file that the early filter reads.

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

### Real-World Benchmark

TTFB comparison on a Silverstripe 5 site (PHP 8.3, shared hosting) with WAF enabled vs disabled:

| Page | WITH WAF | WITHOUT WAF | WITH WAF (restored) |
|------|----------|-------------|---------------------|
| Homepage | 388-569ms (~501ms) | 468-532ms (~505ms) | 315-567ms (~488ms) |
| Content page 1 | 599-662ms (~618ms) | 557-615ms (~596ms) | 589-615ms (~603ms) |
| Content page 2 | 459-658ms (~525ms) | 441-600ms (~503ms) | 345-590ms (~503ms) |

**Conclusion:** No measurable TTFB impact. All results fall within normal variance (~50-100ms). The WAF overhead is negligible compared to framework and database processing time.

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

### 429 Error Page

When rate limits are exceeded, the module can show a styled error page (friendlier for legitimate users) instead of plain text. This requires the `silverstripe/errorpage` module and a published 429 error page.

**Create a 429 error page in the CMS:**
1. Go to **Settings > Error Pages** (or create an ErrorPage in the site tree)
2. Create a new error page with code **429**
3. Add a friendly message like "You're making too many requests. Please wait a moment and try again."
4. Publish the page

**Disable styled error pages** (return plain text instead):
```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  use_styled_error_pages: false
```

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

### Privileged IPs (Elevated Rate Limits)

Unlike whitelisted IPs (which skip ALL checks), privileged IPs still go through all security checks (bans, blocklist, user-agent) but receive an elevated rate limit via a configurable multiplier.

**Example:** With a base limit of 100 req/min and a factor of 3.0, a privileged IP gets 300 req/min.

**Via CMS Admin:** Manage privileged IPs in the WAF admin panel under the "Privileged IPs" tab. Supports single IPs, CIDR ranges, and tier grouping.

**Via YAML config:**

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  privileged_tiers:
    office:
      factor: 3.0
      ips:
        - '10.0.0.0/8'
        - '192.168.1.0/24'
    monitoring:
      factor: 5.0
      ips:
        - '203.0.113.50'

  # Cache duration for merged privileged IP list (seconds)
  privileged_ip_cache_duration: 300
```

DB entries (CMS admin) and YAML config tiers are merged at runtime. DB entries override config for the same IP.

**TTFB impact:** Zero for normal traffic. The privileged IP lookup is deferred until a request count reaches the base soft-rate-limit threshold (~99% of requests never trigger it).

### User-Agent Whitelist

Monitoring services and legitimate bots can be whitelisted by user-agent pattern (regex):

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  whitelisted_user_agents:
    - '/ohdear\.app/i'    # OhDear monitoring
    - '/googlebot/i'      # Google crawler
    - '/bingbot/i'        # Bing crawler
    - '/uptimerobot/i'    # UptimeRobot
    - '/pingdom/i'        # Pingdom
```

These skip the `blocked_user_agents` check (empty user-agent, security scanners, etc.).

**Important:** User-agent whitelisting only bypasses the blocked user-agent check. Whitelisted crawlers are still subject to rate limiting and auto-ban. To fully bypass WAF for trusted services, add their IP to `whitelisted_ips`.

### Crawlers & Monitoring Tools

The default rate limit is **100 requests/minute**. Crawlers exceeding this will:
1. Receive 429 (Too Many Requests) responses
2. After repeated violations (default: 10), get auto-banned for 1 hour (403 Forbidden)

**Recommended crawler settings:**
- Max 1 request/second (~60/minute) to stay safely under the limit
- Or whitelist the crawler's IP for full bypass

For example, OhDear's default "2 concurrent, 250ms" setting equals ~480 requests/minute - far exceeding the limit. Configure slower crawling or whitelist OhDear's IP addresses.

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
[WAF] EARLY_BAN ip=1.2.3.4 violations=10 duration=3600
```

> **Note:** The built-in [early filter banning](#early-filter-banning-self-contained-fail2ban-alternative) provides a self-contained PHP-level alternative to fail2ban. Use fail2ban when you want firewall-level blocking (more efficient for high-volume attacks, blocks before PHP even starts).

### Fail2ban Filter

Create `/etc/fail2ban/filter.d/silverstripe-waf.conf`:

```ini
[Definition]
failregex = \[WAF\] BLOCKED .* ip=<HOST>
            \[WAF\] VIOLATION .* ip=<HOST>
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

### Setting up Fail2ban on Laravel Forge

Forge servers don't include fail2ban by default. Here's how to set it up:

**1. Install fail2ban:**

```bash
sudo apt-get update && sudo apt-get install -y fail2ban
```

**2. Find your PHP error log path:**

```bash
# For Nginx + PHP-FPM (Forge default):
# Check your PHP-FPM pool config for the error_log setting
grep -r "error_log" /etc/php/*/fpm/pool.d/
# Common paths:
#   /var/log/php-fpm/error.log
#   /var/log/php8.3-fpm.log
#   /home/forge/.forge/php-errors.log (Forge custom)

# Or check where PHP actually writes errors:
php -i | grep error_log
```

**3. Create the filter and jail** (as shown above), using the correct `logpath`.

**4. Start and enable fail2ban:**

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

**5. Verify it's working:**

```bash
# Check jail status
sudo fail2ban-client status silverstripe-waf

# Watch bans in real-time
sudo tail -f /var/log/fail2ban.log
```

**6. Test with a probe** (from a different IP or be ready to unban yourself):

```bash
# Trigger a few blocks
for i in {1..6}; do curl -s -o /dev/null -w "%{http_code}\n" https://yoursite.com/wp-admin; done

# Check if the IP was picked up
sudo fail2ban-client status silverstripe-waf
```

> **Tip:** On Forge, if PHP errors go to the site-specific Nginx error log (`/var/log/nginx/yoursite.com-error.log`), use that as the `logpath`. The WAF uses `error_log()` which follows PHP's configured error log destination.

## Blocked Patterns

The early filter blocks these by default:

**WordPress probes:** `/wp-admin`, `/wp-login`, `/wp-content`, `/xmlrpc.php`

**Webshells:** `/shell.php`, `/c99.php`, `/r57.php`, `/eval-stdin.php`, random PHP probes (`/xyz123.php`)

**Config files:** `/.env`, `/.git`, `/.htaccess`, `/config.php`

**Other CMS:** `/phpmyadmin`, `/adminer`, `/administrator/`

**Path traversal:** `../`, `..%2f`, `..%252f`

### Why Path Blocking, Not Payload Inspection?

This module intentionally focuses on **path-based blocking** rather than SQLi/XSS payload inspection:

| Approach | False Positive Risk | Value for Silverstripe |
|----------|---------------------|------------------------|
| Path blocking | **Near zero** - paths like `/wp-admin` should never exist | High - stops scanners before framework loads |
| SQLi/XSS filtering | **Higher** - legitimate content may contain patterns | Low - framework already handles this |

**Silverstripe's built-in protection:**
- **SQLi**: ORM uses parameterized queries; `->filter()` escapes automatically
- **XSS**: Templates auto-escape by default; `$casting` system enforces output encoding

**Early filter is best for:**
- Blocking paths that should never be requested (zero false positives)
- Reducing scanner noise and saving resources
- Defense in depth at the perimeter

**For payload inspection**, use ModSecurity at the web server level where it's optimized for this purpose.

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

# Disable early filter banning (self-contained fail2ban alternative)
WAF_EARLY_BAN=false

# Whitelist IPs
WAF_WHITELIST_IPS="1.2.3.4,5.6.7.8"

# Override storage mode
WAF_STORAGE_MODE=cache
```

## Testing

The module includes comprehensive unit tests covering:

- **IP Range Handling** - CIDR to range conversion, numeric sorting, binary search, range merging
- **High-Load Detection** - Violation counting, threshold detection, automatic fallback
- **Rate Limiting** - Soft limit delay calculations, cap at maximum
- **Pattern Matching** - User-agent blocking, CIDR whitelist matching, path probe detection

### Running Tests

From your project root (with path repository setup):

```bash
# Ensure PHPUnit is installed
composer require --dev phpunit/phpunit

# Run tests
vendor/bin/phpunit --bootstrap vendor/autoload.php _dev/silverstripe-waf/tests/
```

Or if the module is installed standalone:

```bash
cd vendor/restruct/silverstripe-waf
composer install
vendor/bin/phpunit
```

### Test Coverage

| Component | Tests |
|-----------|-------|
| IpBlocklistService | 13 |
| WafStorageService | 9 |
| WafMiddleware | 6 |
| EarlyFilter | 8 |
| **Total** | **36** |

## Complementary Module

This module pairs well with [restruct/silverstripe-security-baseline](https://github.com/restruct/silverstripe-security-baseline) which provides authentication security:

| Module | Focus |
|--------|-------|
| **silverstripe-waf** | Perimeter security (request filtering, IP blocking) |
| **silverstripe-security-baseline** | Authentication security (password policy, brute-force, logging) |

## License

MIT
