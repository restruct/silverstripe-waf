# Extending

## Add Custom Blocked Patterns

Add URL patterns to the early filter via YAML config:

```yaml
Restruct\SilverStripe\Waf\EarlyFilter:
  blocked_patterns:
    - '/my-custom-block'
    - '/another-pattern'
```

Patterns are matched as substrings (case-insensitive). A pattern like `/wp-admin` matches any URL containing that string.

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
| WafMiddleware | 6 |
| EarlyFilter | 8 |
| **Total** | **36** |

Covers: IP range handling, CIDR conversion, binary search, range merging, high-load detection, rate limiting, soft limit delays, user-agent blocking, CIDR whitelist matching, path probe detection.
