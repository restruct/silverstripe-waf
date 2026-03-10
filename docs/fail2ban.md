# Fail2ban Integration

The WAF logs in a fail2ban-compatible format, allowing fail2ban to ban offending IPs at the firewall level.

> **Note:** The built-in [early filter banning](early-filter.md#early-filter-banning) provides a self-contained PHP-level alternative to fail2ban. Use fail2ban when you want firewall-level blocking (more efficient for high-volume attacks, blocks before PHP even starts).

## Log Format

```
[WAF] BLOCKED reason=blocked_pattern ip=1.2.3.4 uri="/wp-admin/"
[WAF] BLOCKED reason=rate_limit ip=1.2.3.4 uri="/api/endpoint"
[WAF] BLOCKED reason=invalid_modelclass ip=1.2.3.4 uri="/admin/pages//wp-includes/..."
[WAF] EARLY_BAN ip=1.2.3.4 violations=10 duration=3600
```

## Fail2ban Filter

Create `/etc/fail2ban/filter.d/silverstripe-waf.conf`:

```ini
[Definition]
failregex = \[WAF\] BLOCKED .* ip=<HOST>
            \[WAF\] VIOLATION .* ip=<HOST>
ignoreregex =
```

## Fail2ban Jail

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

## Setting up Fail2ban on Laravel Forge

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
