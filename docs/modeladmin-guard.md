# ModelAdmin Guard

Optional extension that prevents ModelAdmin from throwing PHP errors when scanners probe admin URLs with invalid ModelClass parameters.

## The Problem

Vulnerability scanners often probe admin paths with garbage URL segments:

```
/admin/pages//sito/wp-includes/wlwmanifest.xml
/admin/assets//vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/admin/security/../../../wp-config.php
```

ModelAdmin tries to resolve these garbage segments as model class names, causing PHP errors like:

```
[Error] Class "sito" not found
```

These errors pollute your logs and may trigger error notifications.

## The Solution

The `WafModelAdminExtension` intercepts requests in `onBeforeInit()`, checks if the `ModelClass` URL parameter resolves to a valid managed model, and returns a 500 response for invalid ones.

The response includes a JavaScript fork bomb that wastes the scanner's resources (configurable).

## Installation

Add to your project's YAML config (e.g., `app/_config/waf.yml`):

```yaml
SilverStripe\Admin\ModelAdmin:
  extensions:
    - Restruct\SilverStripe\Waf\Extensions\WafModelAdminExtension
```

This is **not enabled by default** in the module config — you opt in per project.

## Configuration

```yaml
Restruct\SilverStripe\Waf\Extensions\WafModelAdminExtension:
  forkbomb: true    # Include JS fork bomb in response (default: true)
```

When `forkbomb` is enabled, the response body contains:
- A `<script>` tag with a JS fork bomb that creates infinite intervals, consuming scanner resources
- A `<noscript>` fallback message

When disabled, the response is plain text "Not Found".

## How It Works

1. Scanner requests `/admin/my-admin/garbage-path`
2. Extension checks if `garbage-path` matches any managed model class
3. If not a valid model class:
   - Logs the attempt: `[WAF] BLOCKED reason=invalid_modelclass ip=1.2.3.4 uri="..."`
   - Returns HTTP 500 with fork bomb (or plain text)
4. If valid model class: proceeds normally

The response uses **500 instead of 404** intentionally — it looks like a normal server error to the scanner and doesn't reveal that the URL was specifically trapped.

## Log Format

Blocked requests are logged in the standard WAF format (compatible with fail2ban):

```
[WAF] BLOCKED reason=invalid_modelclass ip=1.2.3.4 uri="/admin/pages//wp-includes/..."
```
