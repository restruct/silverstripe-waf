<?php

/**
 * WAF upload-probe matcher (shared, dependency-free) - waf#15
 *
 * Catches webshell drop attempts: a multipart POST to any endpoint that accepts files, carrying a file
 * whose name has a PHP/server-config extension or whose first bytes are PHP code. Core upload validation
 * already rejects such files, so a hit would not usually land; what this adds is that the sender is
 * logged (IP, user agent, filename) and counted towards the early ban before it moves on to other probes.
 *
 * Consumed by:
 *   - _waf_early_filter.php  (opt-in: upload_probe_enabled; only loaded for multipart POSTs)
 *   - tests/EarlyFilterUploadTest.php
 *
 * Pure functions, no globals, no exit: the early filter wraps them, tests call them directly.
 * The only I/O is reading the first bytes of each uploaded temp file (wafUploadContentProbe()).
 *
 * @package Restruct\SilverStripe\Waf
 */

/**
 * Extensions a web server may hand to PHP (or that PHP itself runs), matched as any dot-separated part
 * of the name after the first: x.php, x.PHP5, and the double-extension trick x.php.jpg (Apache with
 * AddHandler runs the latter as PHP when .php appears anywhere in the name).
 */
function wafUploadExecutableExtensions(): array
{
    return ['php', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'phtml', 'phar', 'pht', 'phps'];
}

/**
 * Whole file names that reconfigure the server for the dir they land in: .htaccess (Apache) and
 * .user.ini (PHP-FPM/CGI per-dir ini, e.g. auto_prepend_file pointing at an uploaded image).
 */
function wafUploadServerConfigNames(): array
{
    return ['.htaccess', '.user.ini'];
}

/**
 * How many bytes of each uploaded file the content check reads. PHP in a polyglot (GIF89a<?php ...) sits
 * at the start, and reading more would make every upload slower for little gain.
 */
const WAF_UPLOAD_SNIFF_BYTES = 4096;

/**
 * The uploaded files in a $_FILES array as a flat list of ['name' => string, 'tmp_name' => string].
 *
 * $_FILES has two shapes: a plain field (name="file") gives scalar name/tmp_name, an array field
 * (name="files[]" or name="a[b][c]") gives name/tmp_name as nested arrays with the same keys. Both are
 * walked; tmp_name is '' where PHP stored no file (an upload error, or a mismatched shape).
 */
function wafUploadedFiles(array $files): array
{
    $list = [];
    foreach ($files as $field) {
        if (!is_array($field) || !array_key_exists('name', $field)) {
            continue;
        }
        wafCollectUploadedFiles($field['name'], $field['tmp_name'] ?? null, $list, 0);
    }
    return $list;
}

/**
 * Walk one $_FILES field's name/tmp_name pair (recursively for array fields) into $list.
 */
function wafCollectUploadedFiles(mixed $name, mixed $tmpName, array &$list, int $depth): void
{
    if (is_array($name)) {
        # PHP caps nesting at max_input_nesting_level (64); stop well before anything silly
        if ($depth >= 32) {
            return;
        }
        foreach ($name as $key => $childName) {
            $childTmp = is_array($tmpName) ? ($tmpName[$key] ?? null) : null;
            wafCollectUploadedFiles($childName, $childTmp, $list, $depth + 1);
        }
        return;
    }
    if (!is_string($name) || $name === '') {
        return;
    }
    $list[] = ['name' => $name, 'tmp_name' => is_string($tmpName) ? $tmpName : ''];
}

/**
 * What is wrong with an uploaded file's name, or null when nothing is: 'ext:<ext>' for an executable
 * extension anywhere after the first dot, 'name:<name>' for a server-config file. Case-insensitive.
 */
function wafUploadNameProbe(string $name): ?string
{
    # PHP already strips the path from the client's filename; strip it again for either separator in
    # case a client or a proxy sends one through
    $base = strtolower(basename(str_replace('\\', '/', $name)));
    # Windows (and some Samba shares) drop trailing dots and spaces, so x.php. lands as x.php
    $base = rtrim(trim($base), ". \t\0");

    if (in_array($base, wafUploadServerConfigNames(), true)) {
        return 'name:' . $base;
    }

    # A NUL splits parts too: a C-level consumer of the name stops there (x.php\0.jpg is x.php)
    $parts = preg_split('/[.\x00]/', $base);
    # The part before the first dot is the name itself: php.jpg is a JPEG called "php"
    array_shift($parts);
    foreach ($parts as $part) {
        $part = trim($part);
        if (in_array($part, wafUploadExecutableExtensions(), true)) {
            return 'ext:' . $part;
        }
    }

    return null;
}

/**
 * Which PHP opening the first WAF_UPLOAD_SNIFF_BYTES of $data contain, or null. Case-insensitive.
 *
 * - '<?php' and '<script language="php"' (PHP 5 only, still what some droppers send) as they are.
 * - '<?=' only when what follows looks like code: optional whitespace, a variable, name, bracket,
 *   backtick or quote, then three printable characters. A bare '<?=' is three bytes, which turn up by
 *   chance in roughly 1 in 4000 compressed files (JPEG, PNG, PDF streams) of 4 KB; the tail brings that
 *   down to a few in a million, and every real short-tag shell (<?=`$_GET[0]`?>, <?=system(...)?>) still
 *   has it.
 */
function wafUploadContentMarker(string $data): ?string
{
    $data = substr($data, 0, WAF_UPLOAD_SNIFF_BYTES);
    if (preg_match(
        '/<\?php|<\?=\s*[$a-z_(`"\'][\x09\x0a\x0d\x20-\x7e]{3}|<script\s+language\s*=\s*["\']?php/i',
        $data,
        $match
    ) !== 1) {
        return null;
    }
    $found = strtolower($match[0]);
    if (str_starts_with($found, '<?php')) {
        return '<?php';
    }
    return str_starts_with($found, '<?=') ? '<?=' : '<script language=php';
}

/**
 * The PHP opening in the first bytes of the file at $path (an uploaded temp file), or null. Reads at most
 * WAF_UPLOAD_SNIFF_BYTES; a path that is not a readable regular file is null.
 */
function wafUploadContentProbe(string $path): ?string
{
    if ($path === '' || !is_file($path)) {
        return null;
    }
    $handle = @fopen($path, 'rb');
    if ($handle === false) {
        return null;
    }
    $data = (string) @fread($handle, WAF_UPLOAD_SNIFF_BYTES);
    @fclose($handle);

    return wafUploadContentMarker($data);
}

/**
 * The first probe among the uploaded files in $files ($_FILES), or null. Returns ['file' => the
 * client's filename, 'pattern' => 'ext:php' | 'name:.htaccess' | 'content:<?php' | ...].
 *
 * All names are checked before any file is opened: a probe that gives itself away by name costs no I/O.
 */
function wafMatchUploadProbe(array $files): ?array
{
    $uploads = wafUploadedFiles($files);

    foreach ($uploads as $upload) {
        $pattern = wafUploadNameProbe($upload['name']);
        if ($pattern !== null) {
            return ['file' => $upload['name'], 'pattern' => $pattern];
        }
    }
    foreach ($uploads as $upload) {
        $marker = wafUploadContentProbe($upload['tmp_name']);
        if ($marker !== null) {
            return ['file' => $upload['name'], 'pattern' => 'content:' . $marker];
        }
    }

    return null;
}

/**
 * The log form of a probe hit: '<pattern> file=<name>', the name cut to 60 characters and stripped of
 * anything but printable ASCII and of double quotes (the log line quotes the pattern, and a filename is
 * chosen by the sender). The file's content is never logged.
 */
function wafUploadProbeLogPattern(array $hit): string
{
    $file = preg_replace('/[^\x20-\x7E]|"/', '', substr((string) $hit['file'], 0, 60));
    return $hit['pattern'] . ' file=' . $file;
}
