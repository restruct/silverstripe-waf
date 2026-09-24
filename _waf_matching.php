<?php

/**
 * WAF blocked-path inventory + matcher (shared, dependency-free)
 *
 * Single source of truth consumed by:
 *   - _waf_early_filter.php  (runtime blocking, before the framework loads)
 *   - tests/EarlyFilterTest.php
 *   - bin/export-blocklist.php  (emits resources/blocklist.json for webserver-config
 *     generators, e.g. forge-helper's nginx flags — schema agreed 2026-08-26)
 *
 * MATCHING SEMANTICS (waf#3 — this replaces unanchored stripos over REQUEST_URI):
 * All types except `traversal` match against the DECODED, lowercased URL *path* —
 * the query string is never part of the match target (site-search terms and campaign
 * params used to be inside it; that is how "?q=admin.php" got visitors blocked).
 *
 *   exact      path === pattern
 *   prefix     path starts with pattern                  (stems like /wp-admin*)
 *   segment    path === pattern OR starts pattern + '/'  (directory-ish names; this is
 *              what stops /plesk matching /pleskens, or /health matching /healthcare)
 *   suffix     path ends with pattern                    (basename probes like
 *              /vendor/.../eval-stdin.php — leading slash keeps it basename-anchored:
 *              '/config.php' matches /app/config.php but NOT /xconfig.php)
 *   contains   substring of the path (last resort; currently unused by defaults)
 *   traversal  substring of the RAW path AND of the decoded path (encoded forms like
 *              ..%2f only exist pre-decode; plain ../ only reliably post-decode)
 *
 * INVENTORY PRINCIPLE (waf#5): a default entry may encode ATTACKER INFRASTRUCTURE —
 * paths no legitimate site serves — never CONTENT VOCABULARY a site might publish.
 * Dropped under that rule in 1.5.0 (see CHANGELOG; there is no per-site config to add them
 * back, the inventory is code-level: docs/extending.md): /health, /metrics, /console/, /debug/, /api/debug, /api/test,
 * /sql/, /db/, /database/, bare '~', and the archive/db extensions
 * (.zip .tar .tar.gz .tgz .gz .rar .7z .sql .backup .old .save .tmp) — on Silverstripe
 * protected assets stream through PHP, so blocking download extensions blocks features.
 *
 * EXPORT FLAGS: 'export' => false marks entries the webserver generator must skip —
 * traversal (nginx's own URI normalisation rejects those before location matching;
 * emitting them is dead config that looks protective) and dotfiles (the stock Forge
 * vhost's `location ~ /\.(?!well-known).*` deny already covers them).
 *
 * @package Restruct\SilverStripe\Waf
 */

/**
 * The typed inventory. Keys: pattern, match, class, [note], [export=false].
 * Keep sorted by class then pattern — the JSON exporter relies on stable order
 * so regenerated webserver config diffs stay byte-identical.
 */
function wafBlockedPathEntries(): array
{
    return [
        // --- wordpress ---
        ['pattern' => '/wp-admin',    'match' => 'prefix', 'class' => 'wordpress'],
        ['pattern' => '/wp-config',   'match' => 'prefix', 'class' => 'wordpress'],
        ['pattern' => '/wp-content',  'match' => 'prefix', 'class' => 'wordpress'],
        ['pattern' => '/wp-cron.php', 'match' => 'exact',  'class' => 'wordpress'],
        ['pattern' => '/wp-includes', 'match' => 'prefix', 'class' => 'wordpress'],
        ['pattern' => '/wp-json',     'match' => 'prefix', 'class' => 'wordpress'],
        ['pattern' => '/wp-load.php', 'match' => 'exact',  'class' => 'wordpress'],
        ['pattern' => '/wp-login',    'match' => 'prefix', 'class' => 'wordpress'],
        ['pattern' => '/wp-settings.php',  'match' => 'exact', 'class' => 'wordpress'],
        ['pattern' => '/wp-trackback.php', 'match' => 'exact', 'class' => 'wordpress'],
        ['pattern' => '/xmlrpc.php',  'match' => 'exact',  'class' => 'wordpress'],

        // --- joomla ---
        ['pattern' => '/administrator/index.php', 'match' => 'exact',  'class' => 'joomla'],
        ['pattern' => '/administrator/manifests', 'match' => 'prefix', 'class' => 'joomla'],
        ['pattern' => '/components/com_',         'match' => 'prefix', 'class' => 'joomla'],
        ['pattern' => '/htaccess.txt',            'match' => 'exact',  'class' => 'joomla'],
        ['pattern' => '/modules/mod_',            'match' => 'prefix', 'class' => 'joomla'],
        ['pattern' => '/plugins/system',          'match' => 'prefix', 'class' => 'joomla'],

        // --- drupal ---
        ['pattern' => '/core/install.php',    'match' => 'exact',  'class' => 'drupal'],
        ['pattern' => '/cron.php',            'match' => 'exact',  'class' => 'drupal'],
        ['pattern' => '/misc/drupal.js',      'match' => 'exact',  'class' => 'drupal'],
        ['pattern' => '/sites/all/modules',   'match' => 'prefix', 'class' => 'drupal'],
        ['pattern' => '/sites/default/files', 'match' => 'prefix', 'class' => 'drupal'],
        ['pattern' => '/update.php',          'match' => 'exact',  'class' => 'drupal'],

        // --- magento ---
        ['pattern' => '/app/etc/local.xml', 'match' => 'exact',   'class' => 'magento'],
        ['pattern' => '/downloader',        'match' => 'segment', 'class' => 'magento'],
        ['pattern' => '/js/mage/',          'match' => 'prefix',  'class' => 'magento'],
        ['pattern' => '/skin/adminhtml/',   'match' => 'prefix',  'class' => 'magento'],
        ['pattern' => '/var/export/',       'match' => 'prefix',  'class' => 'magento'],

        // --- laravel ---
        ['pattern' => '/artisan',            'match' => 'exact',  'class' => 'laravel',
         'note' => 'exact, not substring — /artisan-bakker is a plausible content slug'],
        ['pattern' => '/bootstrap/cache/',   'match' => 'prefix', 'class' => 'laravel'],
        ['pattern' => '/storage/framework/', 'match' => 'prefix', 'class' => 'laravel'],
        ['pattern' => '/storage/logs/',      'match' => 'prefix', 'class' => 'laravel'],

        // --- webshell (suffix = basename-anchored; probes scan deep paths like
        //     /vendor/phpunit/.../eval-stdin.php) ---
        ['pattern' => '/0x.php',         'match' => 'suffix',  'class' => 'webshell'],
        ['pattern' => '/adminer.php',    'match' => 'suffix',  'class' => 'webshell'],
        ['pattern' => '/alfa-rex',       'match' => 'segment', 'class' => 'webshell'],
        ['pattern' => '/alfacgiapi',     'match' => 'segment', 'class' => 'webshell'],
        ['pattern' => '/b374k',          'match' => 'segment', 'class' => 'webshell'],
        ['pattern' => '/c99.php',        'match' => 'suffix',  'class' => 'webshell'],
        ['pattern' => '/eval-stdin.php', 'match' => 'suffix',  'class' => 'webshell'],
        ['pattern' => '/filesman',       'match' => 'segment', 'class' => 'webshell'],
        ['pattern' => '/indoxploit',     'match' => 'segment', 'class' => 'webshell'],
        ['pattern' => '/leaf.php',       'match' => 'suffix',  'class' => 'webshell'],
        ['pattern' => '/mini.php',       'match' => 'suffix',  'class' => 'webshell'],
        ['pattern' => '/r57.php',        'match' => 'suffix',  'class' => 'webshell'],
        ['pattern' => '/shell.php',      'match' => 'suffix',  'class' => 'webshell'],
        ['pattern' => '/webadmin.php',   'match' => 'suffix',  'class' => 'webshell'],
        ['pattern' => '/wso.php',        'match' => 'suffix',  'class' => 'webshell',
         'note' => 'matching is case-insensitive; also covers WSO.php'],

        // --- config-leak (dotfiles carry export:false — the stock Forge vhost
        //     dotfile deny covers them at nginx already) ---
        ['pattern' => '/.aws/',          'match' => 'prefix', 'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.bash_history',  'match' => 'exact',  'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.dockerenv',     'match' => 'exact',  'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.ds_store',      'match' => 'suffix', 'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.env',           'match' => 'prefix', 'class' => 'config-leak', 'export' => false,
         'note' => 'prefix also catches /.env.local, /.env.backup, /.env.production'],
        ['pattern' => '/.git',           'match' => 'prefix', 'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.gitlab-ci.yml', 'match' => 'exact',  'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.hg',            'match' => 'prefix', 'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.htaccess',      'match' => 'suffix', 'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.htpasswd',      'match' => 'suffix', 'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.npmrc',         'match' => 'exact',  'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.phpcs.xml',     'match' => 'exact',  'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.ssh/',          'match' => 'prefix', 'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.svn',           'match' => 'prefix', 'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.travis.yml',    'match' => 'exact',  'class' => 'config-leak', 'export' => false],
        ['pattern' => '/.vite/',         'match' => 'prefix', 'class' => 'config-leak', 'export' => false],
        ['pattern' => '.env',            'match' => 'suffix', 'class' => 'config-leak',
         'note' => 'replaces the old config.env/stripe.env pair: any path ending .env'],
        ['pattern' => '/__env.js',       'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/behat.yml',      'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/codeception.yml','match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/composer.json',  'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/composer.lock',  'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/config.inc.php', 'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/config.php',     'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/config.yaml',    'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/config.yml',     'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/configuration.php', 'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/conn.php',       'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/connect.php',    'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/database.php',   'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/db.php',         'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/env.backup',     'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/env.js',         'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/gemfile',        'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/gemfile.lock',   'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/id_dsa',         'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/id_rsa',         'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/jenkinsfile',    'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/localsettings.php', 'match' => 'exact', 'class' => 'config-leak'],
        ['pattern' => '/package.json',   'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/parameters.yml', 'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/phpcs.xml',      'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/phpunit.xml',    'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/rakefile',       'match' => 'exact',  'class' => 'config-leak'],
        ['pattern' => '/settings.php',   'match' => 'suffix', 'class' => 'config-leak'],
        ['pattern' => '/web.config',     'match' => 'exact',  'class' => 'config-leak'],

        // --- build-tool ---
        ['pattern' => '/@vite',                'match' => 'segment', 'class' => 'build-tool'],
        ['pattern' => '/asset-manifest.json',  'match' => 'exact',   'class' => 'build-tool'],
        ['pattern' => '/node_modules',         'match' => 'segment', 'class' => 'build-tool'],

        // --- db-tool (segment stops /phpmyadmin matching nothing legit, and the
        //     dropped /sql|/db|/database entries were content vocabulary — waf#5) ---
        ['pattern' => '/adminer',    'match' => 'segment', 'class' => 'db-tool'],
        ['pattern' => '/dbadmin',    'match' => 'segment', 'class' => 'db-tool'],
        ['pattern' => '/myadmin',    'match' => 'segment', 'class' => 'db-tool'],
        ['pattern' => '/mysql',      'match' => 'segment', 'class' => 'db-tool'],
        ['pattern' => '/phpmyadmin', 'match' => 'segment', 'class' => 'db-tool',
         'note' => 'case-insensitive; also covers /phpMyAdmin'],
        ['pattern' => '/pma',        'match' => 'segment', 'class' => 'db-tool'],

        // --- server-admin ---
        ['pattern' => '/cgi-bin',        'match' => 'segment', 'class' => 'server-admin'],
        ['pattern' => '/cpanel',         'match' => 'segment', 'class' => 'server-admin'],
        ['pattern' => '/fcgi-bin',       'match' => 'segment', 'class' => 'server-admin'],
        ['pattern' => '/manager/html',   'match' => 'prefix',  'class' => 'server-admin'],
        ['pattern' => '/manager/status', 'match' => 'prefix',  'class' => 'server-admin'],
        ['pattern' => '/plesk',          'match' => 'segment', 'class' => 'server-admin',
         'note' => 'segment, not substring — /pleskens (surname) is a plausible slug'],
        ['pattern' => '/server-info',    'match' => 'exact',   'class' => 'server-admin'],
        ['pattern' => '/server-status',  'match' => 'exact',   'class' => 'server-admin'],
        ['pattern' => '/webmin',         'match' => 'segment', 'class' => 'server-admin'],
        ['pattern' => '/~',              'match' => 'prefix',  'class' => 'server-admin',
         'note' => 'unix userdir probes (/~root); was a bare ~ substring matching ANY tilde'],

        // --- mail-probe (Exchange/Outlook autodiscover; no legitimate answer on an SS
        //     site — waf#1). export:false: the nginx parasite blocklist already owns these
        //     as exact-match locations, and a duplicate `location =` is an [emerg]. ---
        ['pattern' => '/autodiscover/autodiscover.xml', 'match' => 'exact', 'class' => 'mail-probe', 'export' => false],
        ['pattern' => '/autodiscover.xml',              'match' => 'exact', 'class' => 'mail-probe', 'export' => false],
        ['pattern' => '/fpurl.xml',                     'match' => 'exact', 'class' => 'mail-probe', 'export' => false,
         'note' => 'matching is case-insensitive; also covers /FPURL.xml'],

        // --- php-probe ---
        ['pattern' => '/admin.php',   'match' => 'exact', 'class' => 'php-probe'],
        ['pattern' => '/debug.php',   'match' => 'exact', 'class' => 'php-probe'],
        ['pattern' => '/i.php',       'match' => 'exact', 'class' => 'php-probe'],
        ['pattern' => '/info.php',    'match' => 'exact', 'class' => 'php-probe'],
        ['pattern' => '/login.php',   'match' => 'exact', 'class' => 'php-probe'],
        ['pattern' => '/php.php',     'match' => 'exact', 'class' => 'php-probe'],
        ['pattern' => '/phpinfo.php', 'match' => 'suffix','class' => 'php-probe'],
        ['pattern' => '/pi.php',      'match' => 'exact', 'class' => 'php-probe'],
        ['pattern' => '/test.php',    'match' => 'exact', 'class' => 'php-probe'],

        // --- debug-endpoint (bare /debug, /console, /health, /metrics, /api/debug,
        //     /api/test dropped as content vocabulary — waf#5) ---
        ['pattern' => '/__debug__',   'match' => 'segment', 'class' => 'debug-endpoint'],
        ['pattern' => '/_debug',      'match' => 'segment', 'class' => 'debug-endpoint'],
        ['pattern' => '/_profiler',   'match' => 'segment', 'class' => 'debug-endpoint'],
        ['pattern' => '/_wdt',        'match' => 'segment', 'class' => 'debug-endpoint'],
        ['pattern' => '/actuator',    'match' => 'segment', 'class' => 'debug-endpoint'],
        ['pattern' => '/elmah.axd',   'match' => 'exact',   'class' => 'debug-endpoint'],
        ['pattern' => '/glimpse.axd', 'match' => 'exact',   'class' => 'debug-endpoint'],
        ['pattern' => '/telescope',   'match' => 'segment', 'class' => 'debug-endpoint'],
        ['pattern' => '/trace.axd',   'match' => 'exact',   'class' => 'debug-endpoint'],

        // --- editor-junk (the archive/db extensions were dropped; downloads are a
        //     feature and SS protected assets stream through PHP — waf#5) ---
        ['pattern' => '.bak',  'match' => 'suffix', 'class' => 'editor-junk'],
        ['pattern' => '.orig', 'match' => 'suffix', 'class' => 'editor-junk'],
        ['pattern' => '.swp',  'match' => 'suffix', 'class' => 'editor-junk'],

        // --- traversal (raw+decoded path; export:false — nginx URI normalisation
        //     rejects these before location matching, emitting them is dead config) ---
        ['pattern' => '../',       'match' => 'traversal', 'class' => 'traversal', 'export' => false],
        ['pattern' => '..\\',      'match' => 'traversal', 'class' => 'traversal', 'export' => false],
        ['pattern' => '..%2f',     'match' => 'traversal', 'class' => 'traversal', 'export' => false],
        ['pattern' => '..%252f',   'match' => 'traversal', 'class' => 'traversal', 'export' => false],
        ['pattern' => '..%5c',     'match' => 'traversal', 'class' => 'traversal', 'export' => false],
        ['pattern' => '..%255c',   'match' => 'traversal', 'class' => 'traversal', 'export' => false],
        ['pattern' => '%2e%2e/',   'match' => 'traversal', 'class' => 'traversal', 'export' => false],
        ['pattern' => '%252e%252e/', 'match' => 'traversal', 'class' => 'traversal', 'export' => false],
        ['pattern' => '%c0%ae',    'match' => 'traversal', 'class' => 'traversal', 'export' => false],
        ['pattern' => '%c1%9c',    'match' => 'traversal', 'class' => 'traversal', 'export' => false],
    ];
}

/**
 * Match a raw URL path (as sent by the client, query string already stripped)
 * against the typed inventory. Returns the matching entry, or null.
 *
 * Pure function, no globals, no exit — the early filter wraps it; tests call it
 * directly. Case-insensitive throughout.
 */
function wafMatchBlockedPath(string $rawPath, ?array $entries = null): ?array
{
    $entries ??= wafBlockedPathEntries();

    $rawLower = strtolower($rawPath);
    # Decoded view for content matching; traversal additionally checks the raw form,
    # because ..%2f only exists pre-decode while ../ only reliably exists post-decode.
    $path = strtolower(rawurldecode($rawPath));

    foreach ($entries as $entry) {
        $p = strtolower($entry['pattern']);
        $hit = match ($entry['match']) {
            'exact'     => $path === $p,
            'prefix'    => str_starts_with($path, $p),
            'segment'   => $path === $p || str_starts_with($path, $p . '/'),
            'suffix'    => str_ends_with($path, $p),
            'contains'  => str_contains($path, $p),
            'traversal' => str_contains($rawLower, $p) || str_contains($path, $p),
            default     => false,
        };
        if ($hit) {
            return $entry;
        }
    }

    return null;
}
