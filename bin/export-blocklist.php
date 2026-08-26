<?php

/**
 * Generates resources/blocklist.json from the typed inventory in _waf_matching.php.
 *
 * Consumers (e.g. forge-helper's nginx/.htaccess generator flags) read the JSON and
 * emit their native anchored config forms. Schema agreed with the forge-helper
 * maintainer, 2026-08-26:
 *
 *   { "schema": 1, "version": "<module version>", "entries": [
 *       { "pattern": "/wp-admin", "match": "prefix", "class": "wordpress", "note": "…" } ] }
 *
 *   match ∈ {exact, prefix, suffix, contains} — consumer mapping:
 *     exact  → `location =`
 *     prefix → `location ^~`
 *     suffix → `location ~* <escaped-pattern>$`  (pattern is the literal the PATH ends
 *              with, leading char included: '/shell.php' → `~* /shell\.php$`, NOT
 *              `~* shell\.php$`; '.bak' → `~* \.bak$`)
 *     contains → escaped-literal regex
 *
 * Internal→export type mapping (the runtime matcher is richer than the export schema):
 *   segment   → flattened to TWO entries: exact `/name` + prefix `/name/`
 *   suffix    → emitted AS suffix (NOT 'extension' — that conflated basename-suffixes
 *               like '/shell.php' with true extensions like '.bak'; see the switch below)
 *   traversal → never exported (nginx URI normalisation already rejects these)
 *   'export' => false entries are skipped (dotfiles: stock vhost deny covers them)
 *
 * Entries are sorted (class, pattern) so regenerated consumer config is byte-stable.
 *
 * Usage:  php bin/export-blocklist.php <version>   (writes resources/blocklist.json)
 *         php bin/export-blocklist.php <version> --stdout
 */

require __DIR__ . '/../_waf_matching.php';

$version = $argv[1] ?? null;
if (!$version || !preg_match('/^\d+\.\d+\.\d+$/', $version)) {
    fwrite(STDERR, "Usage: php bin/export-blocklist.php <x.y.z> [--stdout]\n");
    exit(1);
}

$out = [];
foreach (wafBlockedPathEntries() as $entry) {
    if (($entry['export'] ?? true) === false || $entry['match'] === 'traversal') {
        continue;
    }

    $base = array_filter([
        'pattern' => $entry['pattern'],
        'class'   => $entry['class'],
        'note'    => $entry['note'] ?? null,
    ]);

    switch ($entry['match']) {
        case 'segment':
            # segment is exact-OR-subtree; flatten losslessly to exact + prefix so a
            # consumer only needs those two forms for it.
            $out[] = $base + ['match' => 'exact'];
            $out[] = ['pattern' => $entry['pattern'] . '/', 'class' => $entry['class'], 'match' => 'prefix'];
            break;
        default:
            # exact / prefix / suffix / contains pass through unchanged.
            # NB: suffix is emitted AS suffix — do NOT remap it to 'extension'. The
            # pattern is a literal the PATH must end with, and it is basename-anchored
            # by its own leading char: '/shell.php' means end-with '/shell.php' (so
            # '/notshell.php' does NOT match), '.bak' means end-with '.bak'. A consumer
            # renders both as `~* <escaped-pattern>$`. Collapsing to 'extension' loses
            # that the leading slash is significant and would reintroduce the waf#3
            # false-positive class at the webserver layer (reported by the forge-helper
            # consumer, 2026-08-26).
            $out[] = $base + ['match' => $entry['match']];
    }
}

usort($out, fn($a, $b) => [$a['class'], $a['pattern']] <=> [$b['class'], $b['pattern']]);

# Fixed key order per entry for byte-stable output
$out = array_map(fn($e) => array_filter([
    'pattern' => $e['pattern'],
    'match'   => $e['match'],
    'class'   => $e['class'],
    'note'    => $e['note'] ?? null,
]), $out);

$json = json_encode(
    ['schema' => 1, 'version' => $version, 'entries' => array_values($out)],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . "\n";

if (in_array('--stdout', $argv, true)) {
    echo $json;
    exit(0);
}

$target = __DIR__ . '/../resources/blocklist.json';
@mkdir(dirname($target), 0755, true);
file_put_contents($target, $json);
fwrite(STDERR, sprintf("Wrote %s (%d exported entries)\n", $target, count($out)));
