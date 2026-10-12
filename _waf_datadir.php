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
 * Since 1.9.0 the parent follows the order in which the framework picks its own temp folder (TEMP_PATH,
 * constants.php and TempFolder::getTempParentFolder()), so there is one rule for where a site keeps its
 * caches: WAF_DATA_DIR, else SS_TEMP_PATH (real env; relative = under the project root), else the
 * project's silverstripe-cache/ when it exists and we can write to it, whatever its mode, else the system
 * temp dir. See wafEarlyDataDirParent() for each step and where it differs from the framework.
 * Either way the dir is only used while it is private: a real dir (not a symlink), owned by this
 * process user, mode 0700. A dir of ours that others can only read is tightened to 0700; one that
 * others can write to is refused, because its contents may be anyone's. Refused means the early ban is
 * off and the filter uses its defaults (pattern blocking is unaffected); the middleware logs why.
 * The checks run on one lstat(). Inside the dir only regular files of this user are believed.
 * The parent dir is not checked (1.8.0 required one that only root or this user could rename in, i.e.
 * not writable by others unless sticky): mic 2026-10-12, a local user who can swap dirs in the parent
 * is a bigger problem than a WAF can solve, and the framework itself runs its caches from a 0777 parent.
 * Files are written 0600 through a temp file and rename(), so a reader never sees half a file.
 *
 * Someone who pre-creates the default path (it is predictable) can make it refused, i.e. switch the
 * early ban off for this site, but can no longer read or change what it holds. WAF_DATA_DIR in a
 * project-owned location takes that away too.
 *
 * @package Restruct\SilverStripe\Waf
 */

# Each function is declared only when it is not there yet: the filter and the middleware each require
# the copy next to them, and with two installs of the module (or a copy under _dev) those are two
# files, which would otherwise be a "Cannot redeclare" fatal. A top-level return does not help, PHP
# declares a file's unconditional functions before running it.
if (!function_exists('wafEarlyDataDirPath')) {
    /**
     * The data dir path this process would use, whether or not it exists or is safe: a dir named
     * waf-<uid>-<hash> (see wafEarlyDataDirName()) inside the parent wafEarlyDataDirParent() picks:
     * WAF_DATA_DIR, SS_TEMP_PATH, the project's silverstripe-cache or the system temp dir (1.8.0: WAF_DATA_DIR
     * when set, else the system temp dir). Null when WAF_DATA_DIR is set but not absolute: a relative path
     * would depend on the cwd, which differs between the filter and the middleware.
     *
     * WAF_DATA_DIR is the parent, never the data dir itself (waf#9 review): it may be a dir that holds other
     * things (the project root, a shared data dir), and the WAF tightens the mode of its data dir and
     * cleans out old files in it. Done to a dir it did not create, that changed the mode of someone's dir
     * and, before the cleanup only took the WAF's own file names, deleted their files. The WAF only
     * touches the dir it named itself.
     */
    function wafEarlyDataDirPath(string $moduleDir): ?string
    {
        //$base = sys_get_temp_dir();
        //$configured = trim((string) getenv('WAF_DATA_DIR'));
        //if ($configured !== '') {
        //    # Absolute on POSIX, or a Windows drive / UNC path
        //    if (!preg_match('#^(/|[A-Za-z]:[\\\\/]|\\\\\\\\)#', $configured)) {
        //        return null;
        //    }
        //    $base = $configured;
        //}
        # The parent now follows the framework's temp folder order (1.9.0): see wafEarlyDataDirParent()
        $parent = wafEarlyDataDirParent($moduleDir);
        if ($parent === null) {
            return null;
        }
        $base = $parent['path'];

        return (rtrim($base, '/\\') ?: $base) . DIRECTORY_SEPARATOR . wafEarlyDataDirName($moduleDir);
    }
}

if (!function_exists('wafEarlyDataDirParent')) {
    /**
     * Where the data dir goes, as ['source' => ..., 'path' => parent dir], in the order the framework picks
     * its own temp folder (constants.php for SS_TEMP_PATH, then TempFolder::getTempParentFolder(); same on
     * Silverstripe 5 and 6), so a site has one rule for where its caches live:
     *
     *  1. WAF_DATA_DIR (real env var, absolute path), as in 1.8.0. Null when it is set but not absolute: a
     *     relative path would depend on the cwd, which differs between the filter and the middleware.
     *  2. SS_TEMP_PATH, the framework's own override of TEMP_PATH, from the real environment only. A relative
     *     value is under the project root, as the framework resolves it (relative = not starting with
     *     DIRECTORY_SEPARATOR, its own test). Relative with no known project root: skipped.
     *  3. <project root>/silverstripe-cache when it exists, the framework's first choice, whatever its mode
     *     (the framework chmods it to 0777 on every boot whose mode is not 0777: getTempParentFolder() on 5
     *     and 6). Where the framework only asks file_exists(), this also asks that it is a dir this process
     *     can write to; one that is not (e.g. made by a deploy user, not writable for the web user) falls
     *     through to step 4 rather than switching the early ban off. 1.9.0-dev only took a sticky (1777)
     *     one; dropped by mic 2026-10-12, see the file header.
     *  4. The system temp dir, as in 1.8.0.
     *
     * Steps 2 and 3 are not in the framework's per-user subfolder (TEMP_PATH itself, <parent>/<user>[-php]):
     * that one is a plain mkdir() that anyone who can write to the parent may create first, so the WAF keeps
     * its own waf-<uid>-<hash> dir next to it, with its own checks.
     *
     * Only what the early filter can see counts, because both layers must agree on the dir: the real process
     * environment, never .env (Silverstripe keeps that in Environment's own store, loaded after the filter
     * has run), and the project root as worked out from the module's own path (wafProjectRoot()).
     */
    function wafEarlyDataDirParent(string $moduleDir): ?array
    {
        $configured = trim((string) getenv('WAF_DATA_DIR'));
        if ($configured !== '') {
            # Absolute on POSIX, or a Windows drive / UNC path
            if (!preg_match('#^(/|[A-Za-z]:[\\\\/]|\\\\\\\\)#', $configured)) {
                return null;
            }
            return ['source' => 'WAF_DATA_DIR', 'path' => $configured];
        }

        $projectRoot = wafProjectRoot($moduleDir);

        # The framework: if ($path = Environment::getEnv('SS_TEMP_PATH')), so '' and '0' do not count, and the
        # value is used as it is (not trimmed)
        $tempPath = (string) wafRealEnv('SS_TEMP_PATH');
        if ($tempPath !== '' && $tempPath !== '0') {
            if (ltrim($tempPath, DIRECTORY_SEPARATOR) !== $tempPath) {
                return ['source' => 'SS_TEMP_PATH', 'path' => $tempPath];
            }
            if ($projectRoot !== null) {
                return ['source' => 'SS_TEMP_PATH', 'path' => $projectRoot . DIRECTORY_SEPARATOR . $tempPath];
            }
        }

        if ($projectRoot !== null) {
            $cacheDir = $projectRoot . DIRECTORY_SEPARATOR . 'silverstripe-cache';
            clearstatcache(true, $cacheDir);
            # is_dir() follows a symlink, like the framework's file_exists(): a silverstripe-cache linked in
            # from a shared dir is the one it uses. Windows has no POSIX modes (see wafIsPrivateDir())
            //if (@is_dir($cacheDir) && (DIRECTORY_SEPARATOR === '\\' || wafIsSafeParent($cacheDir))) {
            # Any mode (mic 2026-10-12); is_writable() so one we cannot use falls through to the system temp dir
            if (@is_dir($cacheDir) && @is_writable($cacheDir)) {
                return ['source' => 'silverstripe-cache', 'path' => $cacheDir];
            }
        }

        return ['source' => 'system temp dir', 'path' => sys_get_temp_dir()];
    }
}

if (!function_exists('wafProjectRoot')) {
    /**
     * The project root, from the module's own path: the dir that holds vendor/<vendor>/<package>. That is the
     * framework's BASE_PATH for a Composer install (it takes the dir above vendor/composer/autoload_real.php,
     * realpath()ed; PHP's __DIR__ is a realpath too). The early filter runs before the autoloader and has
     * nothing else to go on, and the middleware uses this too (not BASE_PATH) so both layers agree.
     *
     * Null when the module is not under a vendor dir, e.g. a path repository symlinked in for local
     * development (__DIR__ is then the symlink's target): steps 2 (relative) and 3 of wafEarlyDataDirParent()
     * are skipped there.
     */
    function wafProjectRoot(string $moduleDir): ?string
    {
        if (!preg_match('#^(?<base>.*)[/\\\\]vendor[/\\\\][^/\\\\]+[/\\\\][^/\\\\]+$#D', rtrim($moduleDir, '/\\'), $matches)) {
            return null;
        }
        # Installed at /vendor/... (a chroot): the root is /, as the framework's own fallback has it
        return $matches['base'] !== '' ? $matches['base'] : DIRECTORY_SEPARATOR;
    }
}

if (!function_exists('wafRealEnv')) {
    /**
     * An environment variable as Environment::getEnv() finds it, minus its own store (.env and setEnv()),
     * which the early filter cannot see: $_ENV, then $_SERVER (where a web server's fastcgi_param ends up),
     * then getenv(). False when it is in none of them.
     */
    function wafRealEnv(string $name)
    {
        if (isset($_ENV[$name])) {
            return $_ENV[$name];
        }
        if (isset($_SERVER[$name])) {
            return $_SERVER[$name];
        }
        return getenv($name);
    }
}

if (!function_exists('wafEarlyDataDirName')) {
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
}

if (!function_exists('wafIsDataFileName')) {
    /**
     * Whether $name is one of the files the filter keeps per address: ban_<md5> or viol_<md5>. Housekeeping
     * (the filter's cleanup, the middleware's removal of the 1.7.0 dir) only ever deletes these, and the
     * temp files of wafWriteDataFile() (wafIsDataTempFileName()), never anything else it finds.
     */
    function wafIsDataFileName(string $name): bool
    {
        return preg_match('/^(ban|viol)_[0-9a-f]{32}$/D', $name) === 1;
    }
}

if (!function_exists('wafIsDataTempFileName')) {
    /**
     * Whether $name is a temp file wafWriteDataFile() makes (.tmp-<12 hex>), left behind when a write was
     * interrupted.
     */
    function wafIsDataTempFileName(string $name): bool
    {
        return preg_match('/^\.tmp-[0-9a-f]{12}$/D', $name) === 1;
    }
}

if (!function_exists('wafEarlyDataDir')) {
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
        //if (!is_link($dir) && !is_dir($dir)) {
        # lstat(): nothing at all at the path, not even a (dangling) symlink
        clearstatcache(true, $dir);
        if (@lstat($dir) === false) {
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
}

if (!function_exists('wafIsPrivateDir')) {
    /**
     * Whether $dir is a real dir that only this process user can use, tightening our own dir to 0700 when
     * others can at most read it.
     *
     * Everything is decided on ONE lstat() of the path (waf#9 review): type, owner and mode all describe the
     * same entry. The parent is not checked since 1.9.0 (mic 2026-10-12): 1.8.0 also required a parent that
     * nobody else could rename entries in (not writable by others unless sticky, owned by root or us), which
     * only guarded against another local user swapping the dir right after the check, and kept the WAF out
     * of the framework's own 0777 silverstripe-cache.
     */
    function wafIsPrivateDir(string $dir): bool
    {
        //# A symlink at our path points wherever its maker likes; never follow it
        //if (is_link($dir) || !is_dir($dir)) {
        //    return false;
        //}
        clearstatcache(true, $dir);
        $stat = @lstat($dir);
        # A symlink at our path points wherever its maker likes; never follow it. lstat() reports the link
        # itself, so anything but a real dir (S_IFDIR) is refused
        if ($stat === false || ($stat['mode'] & 0170000) !== 0040000) {
            return false;
        }
        # Windows has no POSIX modes (fileperms() reports 0777, chmod() is a no-op) and its temp dir is
        # per user already, so only the checks above and writability apply there
        if (DIRECTORY_SEPARATOR === '\\') {
            return is_writable($dir);
        }
        # Parent check dropped in 1.9.0 (mic 2026-10-12), see the docblock
        //if (!wafIsSafeParent(dirname($dir))) {
        //    return false;
        //}
        //if (function_exists('posix_geteuid') && @fileowner($dir) !== posix_geteuid()) {
        if (function_exists('posix_geteuid') && $stat['uid'] !== posix_geteuid()) {
            return false;
        }
        //$perms = @fileperms($dir);
        //if ($perms === false) {
        //    return false;
        //}
        $perms = $stat['mode'];
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
}

# wafIsSafeParent() is gone in 1.9.0 (mic 2026-10-12): the data dir's parent is no longer checked, see
# wafIsPrivateDir(). Kept commented out to show what the 1.8.0 check was.
//if (!function_exists('wafIsSafeParent')) {
//    /**
//     * Whether entries in $parent can only be renamed or replaced by their owner: $parent is not writable by
//     * group or others, or it is sticky (mode +t, like /tmp). stat(), not lstat(): the parent itself may be
//     * reached through a symlink the admin chose (on macOS /tmp and /var are symlinks into /private).
//     *
//     * Either way the parent must belong to root or to this process user: the owner of a dir can always
//     * rename or remove what is in it, sticky or not, so a 1777 dir someone else made first (at the
//     * WAF_DATA_DIR path, or as TMPDIR) would let them swap our dir after the check (waf#9 review).
//     * Without posix the owner is not known and only the mode is checked.
//     */
//    function wafIsSafeParent(string $parent): bool
//    {
//        clearstatcache(true, $parent);
//        //$perms = @fileperms($parent);
//        //if ($perms === false) {
//        //    return false;
//        //}
//        $stat = @stat($parent);
//        if ($stat === false) {
//            return false;
//        }
//        if (function_exists('posix_geteuid') && $stat['uid'] !== 0 && $stat['uid'] !== posix_geteuid()) {
//            return false;
//        }
//        $perms = $stat['mode'];
//        return ($perms & 0022) === 0 || ($perms & 01000) !== 0;
//    }
//}

if (!function_exists('wafDataFileStat')) {
    /**
     * lstat() of $dir/$name when it is a regular file of this process user, else null (missing, a symlink,
     * a dir, or someone else's).
     *
     * The data dir is private, but a dir that was open once (or a 0700 dir someone chmods back) can still
     * hold what others put there while it was: a dir of ours that is now 0700 says nothing about the files
     * in it (waf#9 review). So each data file is checked on its own before it is believed. Without posix
     * the owner is not known and only the type is checked. lstat(), so a symlink is never followed.
     */
    function wafDataFileStat(string $dir, string $name): ?array
    {
        $path = $dir . DIRECTORY_SEPARATOR . $name;
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if ($stat === false || ($stat['mode'] & 0170000) !== 0100000) {
            return null;
        }
        if (DIRECTORY_SEPARATOR !== '\\' && function_exists('posix_geteuid') && $stat['uid'] !== posix_geteuid()) {
            return null;
        }
        return $stat;
    }
}

if (!function_exists('wafReadDataFile')) {
    /**
     * The contents of $dir/$name when it is a regular file of this process user (wafDataFileStat()), else
     * null: anything else is treated as if the file was not there.
     */
    function wafReadDataFile(string $dir, string $name): ?string
    {
        if (wafDataFileStat($dir, $name) === null) {
            return null;
        }
        $content = @file_get_contents($dir . DIRECTORY_SEPARATOR . $name);
        return $content === false ? null : $content;
    }
}

if (!function_exists('wafWriteDataFile')) {
    /**
     * Write $content to $dir/$name, mode 0600, atomically: into a new temp file in the same dir, then
     * rename() over the target (rename() replaces a symlink at the target, it does not write through it).
     *
     * The temp file is opened with 'x' (create, fail if it exists), but that is not what keeps it safe:
     * PHP resolves the path before it opens, so 'x' does follow a dangling symlink (checked on PHP 8.3).
     * What does is that $dir is private (0700, ours: wafIsPrivateDir()), so nobody else can plant
     * anything in it, and the name is random, so nothing could be planted under it in advance.
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
}
