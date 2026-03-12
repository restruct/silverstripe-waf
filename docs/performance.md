# Performance

The module is designed for minimal impact on legitimate traffic while effectively blocking malicious requests.

## TTFB Impact

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

### Privileged IP Lookup

The privileged IP lookup is **deferred** until the request count reaches the base soft-rate-limit threshold. For 99%+ of requests (normal traffic under the threshold), there is zero additional overhead.

| Scenario | When it happens | TTFB impact |
|----------|----------------|-------------|
| Normal traffic (< base soft threshold) | ~99% of requests | **0ms** (no lookup) |
| Approaching limit + cache hit | Rare, cached 5 min | **~0.1ms** |
| Approaching limit + cache miss | Once per 5 min max | **~1-3ms** (DB query, then cached) |

## Memory & Storage

| Resource | Size | Notes |
|----------|------|-------|
| Blocklist download | ~72 KB | FireHOL Level 1 + Binary Defense, every 6h |
| Cache: blocklist | ~500 KB | ~4,500 CIDRs stored as optimized ranges |
| Cache: rate data | ~60 bytes/IP/window | Rate counters (time-windowed) + violation counts |
| Cache: total | ~1-2 MB | Under moderate load (10K unique IPs) |

The module uses chunked cache storage (500 entries per chunk) to work within Memcached's 1MB item limit.

## Performance Optimizations

1. **Per-IP result caching** — Blocklist lookup results are cached for 60s per IP, eliminating repeated lookups for the same visitor

2. **Binary search for IP ranges** — CIDRs are converted to sorted IP ranges at sync time. Lookups use O(log n) binary search instead of O(n) linear scan

3. **High-load auto-fallback** — When under attack (>100 violations/minute), automatically skips file/DB persistence and runs in pure cache mode

4. **Overlapping range merging** — Adjacent/overlapping CIDRs are merged during sync, reducing the number of ranges to search

5. **Lazy privileged IP evaluation** — Factor lookup only happens when request count approaches the rate limit threshold

## Comparison

| Approach | TTFB Impact | Notes |
|----------|-------------|-------|
| This WAF module | 2-3ms | PHP-level, no external service |
| Cloudflare WAF | ~50-100ms | DNS proxy, geographic latency |
| Apache mod_security | 5-20ms | Depends on ruleset complexity |
| No WAF | 0ms | But vulnerable to attacks |

## Real-World Benchmark

TTFB comparison on a Silverstripe 5 site (PHP 8.3, shared hosting) with WAF enabled vs disabled:

| Page | WITH WAF | WITHOUT WAF | WITH WAF (restored) |
|------|----------|-------------|---------------------|
| Homepage | 388-569ms (~501ms) | 468-532ms (~505ms) | 315-567ms (~488ms) |
| Content page 1 | 599-662ms (~618ms) | 557-615ms (~596ms) | 589-615ms (~603ms) |
| Content page 2 | 459-658ms (~525ms) | 441-600ms (~503ms) | 345-590ms (~503ms) |

**Conclusion:** No measurable TTFB impact. All results fall within normal variance (~50-100ms). The WAF overhead is negligible compared to framework and database processing time.
