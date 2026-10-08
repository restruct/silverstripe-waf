<?php

/**
 * WAF early-filter data dir (shared, dependency-free) - waf#9
 *
 * Where the early filter keeps its ban files, violation counters and the config.json the middleware
 * writes for it. Consumed by:
 *   - _waf_early_filter.php  (before the framework, the autoloader and .env)
 *   - WafMiddleware::writeEarlyFilterConfig()
 * Both MUST resolve the same dir, so everything here is worked out from what the early filter has too:
 * the module's own path and the real process environment (getenv(), never .env, which Silverstripe
 * keeps in Environment's own store and the filter cannot see).
 *
 * Up to 1.7.0 the dir was sys_get_temp_dir()/waf_<hash>, made 0755 with 0644 files, and trusted as
 * found. On a host where users or sites share the temp dir, anyone could read the trusted proxy list
 * and the counters, or plant files: lift bans, ban an address, or trust every proxy so X-Forwarded-For
 * picks who gets banned. Now:
 *   - WAF_DATA_DIR (real env var, absolute path)/waf-<uid>-<hash>, e.g. inside the project; else
 *   - sys_get_temp_dir()/waf-<uid>-<hash>: per process user, so a CLI user and the web user do not
 *     fight over one dir.
 *   WAF_DATA_DIR names the parent: the WAF only ever changes or cleans the dir it named itself.
 * Either way the dir is only used while it is private: a real dir (not a symlink), owned by this
 * process user, mode 0700. A dir of ours that others can only read is tightened to 0700; one that
 * others can write to is refused, because its contents may be anyone's. Refused means the early ban is
 * off and the filter uses its defaults (pattern blocking is unaffected); the middleware logs why.
 * Files are written 0600 through a temp file and rename(), so a reader never sees half a file.
 *
 * Someone who pre-creates the default path (it is predictable) can make it refused, i.e. switch the
 * early ban off for this site, but can no longer read or change what it holds. WAF_DATA_DIR in a
 * project-owned location takes that away too.
 *
 * @package Restruct\SilverStripe\Waf
 */

/**
 * The data dir path this process would use, whether or not it exists or is safe: a dir named
 * waf-<uid>-<hash> (see wafEarlyDataDirName()) inside WAF_DATA_DIR when that is set, else inside the
 * system temp dir. Null when WAF_DATA_DIR is set but not absolute: a relative path would depend on the
 * cwd, which differs between the filter and the middleware.
 *
 * WAF_DATA_DIR is the parent, never the data dir itself (waf#9 review): it may be a dir that holds other
 * things (the project root, a shared data dir), and the WAF tightens the mode of its data dir and
 * cleans out old files in it. Done to a dir it did not create, that changed the mode of someone's dir
 * and, before the cleanup only took the WAF's own file names, deleted their files. The WAF only
 * touches the dir it named itself.
 */
function wafEarlyDataDirPath(string $moduleDir): ?string
{
    $base = sys_get_temp_dir();
    $configured = trim((string) getenv('WAF_DATA_DIR'));
    if ($configured !== '') {
        # Absolute on POSIX, or a Windows drive / UNC path
        if (!preg_match('#^(/|[A-Za-z]:[\\\\/]|\\\\\\\\)#', $configured)) {
            return null;
        }
        $base = $configured;
    }

    return (rtrim($base, '/\\') ?: $base) . DIRECTORY_SEPARATOR . wafEarlyDataDirName($moduleDir);
}

/**
 * The name of the data dir, waf-<uid>-<hash>: per process user, so a CLI user and the web user do not
 * fight over one dir, and per module install (hash of its path), so two sites sharing a parent dir do not
 * share bans.
 */
function wafEarlyDataDirName(string $moduleDir): string
{
    # posix is near-universal but optional; getmyuid() (owner of the running script) is the fallback.
    # The uid only keeps users apart in the name; wafIsPrivateDir() is what checks ownership.
    $uid = function_exists('posix_geteuid') ? posix_geteuid() : getmyuid();

    return 'waf-' . $uid . '-' . substr(md5($moduleDir), 0, 8);
}

/**
 * Whether $name is one of the files the filter keeps per address: ban_<md5> or viol_<md5>. Housekeeping
 * (the filter's cleanup, the middleware's removal of the 1.7.0 dir) only ever deletes these, and the
 * temp files of wafWriteDataFile() (wafIsDataTempFileName()), never anything else it finds.
 */
function wafIsDataFileName(string $name): bool
{
    return preg_match('/^(ban|viol)_[0-9a-f]{32}$/D', $name) === 1;
}

/**
 * Whether $name is a temp file wafWriteDataFile() makes (.tmp-<12 hex>), left behind when a write was
 * interrupted.
 */
function wafIsDataTempFileName(string $name): bool
{
    return preg_match('/^\.tmp-[0-9a-f]{12}$/D', $name) === 1;
}

/**
 * The data dir to use, or null when there is no private one. With $create the dir is made (0700) when
 * it does not exist yet; without it a missing dir is null, which keeps the per-request cost of the
 * filter to a few stat calls on clean traffic.
 */
function wafEarlyDataDir(string $moduleDir, bool $create): ?string
{
    $dir = wafEarlyDataDirPath($moduleDir);
    if ($dir === null) {
        return null;
    }
    if (!is_link($dir) && !is_dir($dir)) {
        if (!$create) {
            return null;
        }
        # 0700 from the start (umask can only take bits away). A failure is fine if someone else made it
        # meanwhile: the checks below decide whether it can be used.
        @mkdir($dir, 0700, true);
        clearstatcache(true, $dir);
    }

    return wafIsPrivateDir($dir) ? $dir : null;
}

/**
 * Whether $dir is a real dir that only this process user can use, tightening our own dir to 0700 when
 * others can at most read it.
 */
function wafIsPrivateDir(string $dir): bool
{
    # A symlink at our path points wherever its maker likes; never follow it
    if (is_link($dir) || !is_dir($dir)) {
        return false;
    }
    # Windows has no POSIX modes (fileperms() reports 0777, chmod() is a no-op) and its temp dir is
    # per user already, so only the checks above and writability apply there
    if (DIRECTORY_SEPARATOR === '\\') {
        return is_writable($dir);
    }
    if (function_exists('posix_geteuid') && @fileowner($dir) !== posix_geteuid()) {
        return false;
    }
    $perms = @fileperms($dir);
    if ($perms === false) {
        return false;
    }
    # Writable by group or others: anything in it may have been put there by someone else
    if (($perms & 0022) !== 0) {
        return false;
    }
    # Readable or searchable by others (e.g. a 0755 dir made with a default umask): ours, so tighten it.
    # chmod() only succeeds for the owner, which also covers a host without posix.
    if (($perms & 0077) !== 0) {
        if (!@chmod($dir, 0700)) {
            return false;
        }
        clearstatcache(true, $dir);
    }

    # Without posix the owner is not known; a 0700 dir we can write to is ours (or we are root)
    return is_writable($dir);
}

/**
 * Write $content to $dir/$name, mode 0600, atomically: into a new temp file in the same dir (created
 * exclusively, so it never follows a planted name), then rename() over the target.
 */
function wafWriteDataFile(string $dir, string $name, string $content): bool
{
    $tmp = $dir . DIRECTORY_SEPARATOR . '.tmp-' . bin2hex(random_bytes(6));
    $handle = @fopen($tmp, 'x');
    if ($handle === false) {
        return false;
    }
    @chmod($tmp, 0600);
    $written = @fwrite($handle, $content) === strlen($content);
    @fclose($handle);
    if (!$written || !@rename($tmp, $dir . DIRECTORY_SEPARATOR . $name)) {
        @unlink($tmp);
        return false;
    }
    return true;
}
