# Configuration

All configuration lives in `_config/config.yml` with extensive inline comments. This page covers the key options.

## Storage Modes

Controls where bans and blocked request logs are persisted.

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

Can also be set via environment variable: `WAF_STORAGE_MODE=cache`

## Rate Limiting

### Hard Limit

Blocks requests completely when exceeded. Returns HTTP 429 Too Many Requests.

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  rate_limit_requests: 100    # Max requests per IP per window
  rate_limit_window: 60       # Window in seconds
```

The rate counter uses **fixed time windows** — each window period starts a fresh counter that expires independently. This means a crawler sending 2 requests/second will count ~120 requests per 60-second window, always resetting at the window boundary.

### Soft Limit (Progressive Delays)

Slows down requests as they approach the hard limit. Discourages bots while allowing legitimate burst traffic.

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  soft_rate_limit_threshold: 50   # % of hard limit where delays start
  soft_rate_limit_max_delay: 3000 # Max delay in milliseconds
```

**Behavior with default 100 req/min limit:**

| Requests | Delay |
|----------|-------|
| 50 (threshold) | 0ms |
| 60 | 600ms |
| 75 | 1500ms |
| 90 | 2400ms |
| 99 | 2940ms |
| 100+ | Blocked (429) |

### 429 Error Page

When rate limits are exceeded, the module can show a styled error page instead of plain text. Requires `silverstripe/errorpage` and a published 429 error page.

**Create a 429 error page in the CMS:**
1. Go to **Settings > Error Pages** (or create an ErrorPage in the site tree)
2. Create a new error page with code **429**
3. Add a friendly message like "You're making too many requests. Please wait a moment and try again."
4. Publish the page

**Disable styled error pages:**
```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  use_styled_error_pages: false
```

## IP Whitelist

Whitelisted IPs skip **all** WAF checks. Supports single IPs and CIDR notation.

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

## Privileged IPs (Elevated Rate Limits)

Unlike whitelisted IPs (which skip ALL checks), privileged IPs still go through all security checks (bans, blocklist, user-agent) but receive an elevated rate limit via a configurable multiplier.

**Example:** Base limit 100 req/min with factor 3.0 = 300 req/min effective limit.

### Via CMS Admin

Manage privileged IPs in the WAF admin panel under the **Privileged IPs** tab. Supports single IPs, CIDR ranges, and tier grouping.

### Via YAML Config

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

**TTFB impact:** Zero for normal traffic. The privileged IP lookup is deferred until request count reaches the base soft-rate-limit threshold (~99% of requests never trigger it).

## User-Agent Whitelist

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

These skip the `blocked_user_agents` check only. Whitelisted crawlers are still subject to rate limiting and auto-ban. To fully bypass WAF for trusted services, add their IP to `whitelisted_ips`.

## Crawlers & Monitoring Tools

The default rate limit is **100 requests/minute**. Crawlers exceeding this will:
1. Receive 429 (Too Many Requests) responses
2. After repeated violations (default: 10), get auto-banned for 1 hour (403 Forbidden)

**For known crawlers**, add their IP as a **privileged IP** with an appropriate factor (e.g. 3.0 = 300 req/min). Privileged IPs that exceed the elevated limit get 429 responses but are **never auto-banned** for rate limits.

**Recommended crawler settings:**
- Max 1 request/second (~60/minute) to stay safely under the limit
- Or add as privileged IP for elevated limits without ban risk
- Or whitelist the crawler's IP for full bypass (skips all checks)

For example, OhDear's default "2 concurrent, 250ms" setting equals ~480 requests/minute — far exceeding the limit. Configure slower crawling, add as privileged IP, or whitelist OhDear's IP addresses.

## Auto-Ban

Automatically bans IPs after repeated violations (blocklist hits, bad user-agents, rate limit exceeded).

```yaml
Restruct\SilverStripe\Waf\Middleware\WafMiddleware:
  auto_ban_enabled: true
  ban_threshold: 10       # Violations before auto-ban
  ban_duration: 3600      # Ban duration in seconds (1 hour)
```

### Privileged IP Protection

Privileged IPs are protected from auto-ban for rate limit violations. When a privileged IP exceeds the rate limit, it receives a 429 response but violations are **not counted** toward the ban threshold. This prevents known partners (SEO crawlers, monitoring tools) from being accidentally banned during traffic bursts.

Security violations (`blocklist`, `bad_useragent`) still count normally — privileged status only exempts rate limit bans.

Additionally, if a privileged IP is currently banned (e.g. it was banned before being marked privileged), the ban is automatically lifted on the next request.

## Blocklist Sources

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

### Syncing Blocklists

**Manual:**
```bash
vendor/bin/sake dev/tasks/waf-sync-blocklists
```

**Cron (recommended every 6 hours):**
```cron
0 */6 * * * cd /path/to/site && vendor/bin/sake dev/tasks/waf-sync-blocklists
```

**QueuedJobs (automatic):** If `symbiote/silverstripe-queuedjobs` is installed, the sync job auto-schedules every 6 hours. No manual cron setup required. The job is automatically created on first `dev/build`.
