# Extending

## Custom Blocked Patterns

The blocked-path inventory is **code-level and not configurable per site**. It lives in
`_waf_matching.php` (`wafBlockedPathEntries()`), where every entry is typed and anchored
(`exact`, `prefix`, `segment`, `suffix`, `contains`, `traversal`) and matched against the decoded
URL path, never the query string. The random-PHP-probe check and its allowed short files
(`/index.php`) are in `_waf_early_filter.php`.

Up to 1.5.x the module's `_config/config.yml` shipped a `Restruct\SilverStripe\Waf\EarlyFilter:`
block (`blocked_patterns`, `block_random_php_probes`, `php_probe_pattern`, `legitimate_php_files`)
and this page said to add patterns there. Nothing ever read that config: there is no such class, and
the early filter runs before the framework loads. A pattern added there never blocked anything. The
block is commented out from 1.6.0; if your project config sets these keys, remove them, they have no
effect.

To block an extra path on one site, do it where the site's own config lives:

- **Web server** (cheapest, the request never reaches PHP): an nginx `location` or an Apache rule.
  `resources/blocklist.json` exports the module's inventory for generators that write such config.
- **Project middleware**: a small `HTTPMiddleware` in your project that returns a 403 for your paths.

A pattern that every Silverstripe site should block belongs in the module's inventory: propose it
there (with a test in `tests/EarlyFilterTest.php`), keeping to the rule that an entry encodes attacker
infrastructure, never words a site might publish (see [Early Filter](early-filter.md)).

## Add Custom Blocklist Source

```yaml
Restruct\SilverStripe\Waf\Services\IpBlocklistService:
  blocklist_sources:
    my_custom_list:
      url: 'https://example.com/blocklist.txt'
      enabled: true
      format: 'ip'  # or 'cidr' or 'cidr_semicolon'
```

Supported formats:
- `ip` — One IP address per line
- `cidr` — One CIDR range per line (e.g., `10.0.0.0/8`)
- `cidr_semicolon` — CIDR followed by semicolon and comment (e.g., `10.0.0.0/8 ; Description`)

Lines starting with `#` are treated as comments in all formats.

### Local Blocklist File

For a static file-based blocklist (one IP/CIDR per line):

```yaml
Restruct\SilverStripe\Waf\Services\IpBlocklistService:
  local_blocklist_file: '/path/to/custom-blocklist.txt'
```

## Environment Variables

```bash
# Disable WAF completely
WAF_ENABLED=false

# Disable early filter only
WAF_EARLY_FILTER_DISABLED=true

# Disable early filter banning (self-contained fail2ban alternative)
WAF_EARLY_BAN=false

# Whitelist IPs (comma-separated, supports CIDR)
WAF_WHITELIST_IPS="1.2.3.4,5.6.7.8,10.0.0.0/8"

# Override storage mode
WAF_STORAGE_MODE=cache
```

## Testing

The module includes comprehensive unit tests.

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
| WafMiddleware | 22 |
| EarlyFilter | 10 |
| **Total** | **54** |

Covers: IP range handling, CIDR conversion, binary search, range merging, high-load detection, rate limiting, time-windowed counters, soft limit delays, privileged IP factor lookup, privileged IP auto-ban protection, user-agent blocking, CIDR whitelist matching, path probe detection.
