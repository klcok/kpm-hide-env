/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hide_env.c - APatch KPM for hiding root environment
 *
 * Hooks faccessat, newfstatat, statx, openat, getdents64 syscalls
 * to hide root-related files and directories from non-root processes.
 *
 * Copyright (C) 2026. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <common.h>
#include <syscall.h>
#include <kputils.h>
#include <hook.h>
#include <asm/current.h>
#include <uapi/asm-generic/unistd.h>

/* Provide memset/memmove if not available */
static inline void *kp_memset(void *s, int c, unsigned long n)
{
    char *p = s;
    while (n--) *p++ = (char)c;
    return s;
}

static inline void *kp_memmove(void *dest, const void *src, unsigned long n)
{
    char *d = dest;
    const char *s = src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dest;
}

KPM_NAME("kpm-hide-env");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("hide_env");
KPM_DESCRIPTION("Hide root environment from detection apps via syscall hooks");

/* ========================================================================
 * Configuration
 * ======================================================================== */

#define TAG "hide_env"
#define logki(fmt, ...) pr_info("[%s] " fmt, TAG, ##__VA_ARGS__)
#define logke(fmt, ...) pr_err("[%s] " fmt, TAG, ##__VA_ARGS__)
#define logkw(fmt, ...) pr_warn("[%s] " fmt, TAG, ##__VA_ARGS__)

/* Maximum number of paths in blacklist */
#define MAX_HIDE_PATHS 64

/* Maximum path length we check */
#define PATH_BUF_LEN 256

/* ENOENT - No such file or directory */
#define ENOENT 2

/* ========================================================================
 * Path blacklist
 * ======================================================================== */

/* Static blacklist - full paths that should be hidden */
static const char *static_hide_paths[] = {
    /* su binaries */
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/vendor/bin/su",
    "/product/bin/su",

    /* Magisk */
    "/system/bin/magisk",
    "/system/bin/magiskhide",
    "/system/bin/magiskinit",
    "/data/adb/magisk",
    "/data/adb/magisk.db",
    "/cache/.magisk",

    /* APatch / KernelPatch */
    "/data/adb/ap",
    "/data/adb/apd",
    "/data/adb/kpatch",

    /* Superuser */
    "/system/app/Superuser.apk",
    "/system/app/Superuser",
    "/system/app/SuperSU",

    /* BusyBox */
    "/system/bin/busybox",
    "/system/xbin/busybox",

    /* Common root indicators */
    "/system/etc/init.d",
    "/system/xbin/daemonsu",

    /* Xposed */
    "/system/framework/XposedBridge.jar",
    "/system/lib/libxposed_art.so",
    "/system/lib64/libxposed_art.so",

    NULL /* sentinel */
};

/* Prefix paths - any path starting with these should be hidden */
static const char *static_hide_prefixes[] = {
    "/data/adb/magisk/",
    "/data/adb/modules/",
    "/data/adb/ap/",
    "/sbin/.magisk/",
    "/debug_ramdisk/",
    NULL /* sentinel */
};

/* Directory entry names to hide from getdents64 */
static const char *hide_dentry_names[] = {
    "su",
    "magisk",
    "magiskhide",
    "magiskinit",
    "busybox",
    "supersu",
    "Superuser.apk",
    "daemonsu",
    ".magisk",
    "ap",
    "apd",
    "kpatch",
    "modules",
    "XposedBridge.jar",
    "libxposed_art.so",
    NULL /* sentinel */
};

/* Dynamic blacklist (can be added via CTL0) */
static char dynamic_paths[MAX_HIDE_PATHS][PATH_BUF_LEN];
static int dynamic_path_count = 0;

/* Module enabled flag */
static int hide_enabled = 1;

/* Cached kernel function pointer for copy_from_user (resolved at init) */
static unsigned long (*kp_copy_from_user)(void *, const void __user *, unsigned long) = 0;

/* ========================================================================
 * Helper functions
 * ======================================================================== */

/**
 * Check if current process should be filtered.
 * Only filter non-root processes (uid != 0).
 */
static inline int should_filter(void)
{
    if (!hide_enabled) return 0;
    uid_t uid = current_uid();
    return uid != 0;
}

/**
 * Read a userspace path string into kernel buffer.
 * Returns string length or negative on error.
 */
static int read_user_path(const char __user *user_path, char *buf, int buflen)
{
    if (!user_path || !buf) return -1;
    long len = compat_strncpy_from_user(buf, user_path, buflen);
    if (len <= 0) return -1;
    buf[buflen - 1] = '\0';
    return (int)len;
}

/**
 * Check if a path matches the blacklist.
 * Returns 1 if should be hidden, 0 otherwise.
 */
static int path_is_hidden(const char *path)
{
    int i;

    if (!path || path[0] == '\0') return 0;

    /* Check exact match against static paths */
    for (i = 0; static_hide_paths[i] != NULL; i++) {
        if (!strcmp(path, static_hide_paths[i]))
            return 1;
    }

    /* Check prefix match */
    for (i = 0; static_hide_prefixes[i] != NULL; i++) {
        int plen = strlen(static_hide_prefixes[i]);
        if (!strncmp(path, static_hide_prefixes[i], plen))
            return 1;
    }

    /* Check dynamic paths */
    for (i = 0; i < dynamic_path_count; i++) {
        if (dynamic_paths[i][0] && !strcmp(path, dynamic_paths[i]))
            return 1;
    }

    return 0;
}

/**
 * Check if a directory entry name should be hidden.
 */
static int dentry_is_hidden(const char *name)
{
    int i;
    if (!name || name[0] == '\0') return 0;

    for (i = 0; hide_dentry_names[i] != NULL; i++) {
        if (!strcmp(name, hide_dentry_names[i]))
            return 1;
    }
    return 0;
}

/* ========================================================================
 * Syscall hooks
 * ======================================================================== */

/*
 * faccessat(int dfd, const char __user *filename, int mode, int flag)
 * Syscall 48 - __NR_faccessat
 *
 * Most root detection apps call access() first to check if su exists.
 */
static void before_faccessat(hook_fargs4_t *args, void *udata)
{
    if (!should_filter()) return;

    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char buf[PATH_BUF_LEN];

    if (read_user_path(filename, buf, sizeof(buf)) <= 0) return;

    if (path_is_hidden(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/*
 * newfstatat / fstatat64(int dfd, const char __user *filename,
 *                        struct stat __user *statbuf, int flag)
 * Syscall 79 - __NR3264_fstatat
 */
static void before_newfstatat(hook_fargs4_t *args, void *udata)
{
    if (!should_filter()) return;

    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char buf[PATH_BUF_LEN];

    if (read_user_path(filename, buf, sizeof(buf)) <= 0) return;

    if (path_is_hidden(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/*
 * statx(int dfd, const char __user *filename, unsigned flags,
 *        unsigned int mask, struct statx __user *buffer)
 * Syscall 291 - __NR_statx
 */
static void before_statx(hook_fargs4_t *args, void *udata)
{
    if (!should_filter()) return;

    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char buf[PATH_BUF_LEN];

    if (read_user_path(filename, buf, sizeof(buf)) <= 0) return;

    if (path_is_hidden(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/*
 * openat(int dfd, const char __user *filename, int flags, umode_t mode)
 * Syscall 56 - __NR_openat
 */
static void before_openat(hook_fargs4_t *args, void *udata)
{
    if (!should_filter()) return;

    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char buf[PATH_BUF_LEN];

    if (read_user_path(filename, buf, sizeof(buf)) <= 0) return;

    if (path_is_hidden(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/* ========================================================================
 * getdents64 hook - directory entry filtering
 *
 * This is the most complex hook. We let the real syscall execute first,
 * then filter the returned buffer to remove hidden entries.
 *
 * struct linux_dirent64 {
 *     u64        d_ino;
 *     s64        d_off;
 *     u16        d_reclen;
 *     u8         d_type;
 *     char       d_name[];
 * };
 * ======================================================================== */

/* linux_dirent64 structure offsets */
#define DIRENT64_D_INO_OFF    0
#define DIRENT64_D_OFF_OFF    8
#define DIRENT64_D_RECLEN_OFF 16
#define DIRENT64_D_TYPE_OFF   18
#define DIRENT64_D_NAME_OFF   19

/*
 * Max buffer size we'll process for getdents64 filtering.
 * Keep small to avoid kernel stack overflow - process in chunks if needed.
 */
#define GETDENTS_BUF_MAX 4096

static void after_getdents64(hook_fargs4_t *args, void *udata)
{
    if (!should_filter()) return;
    if (!kp_copy_from_user) return;

    /* ret = number of bytes read, or negative on error */
    long ret = (long)args->ret;
    if (ret <= 0) return;

    /* getdents64(int fd, struct linux_dirent64 *dirp, unsigned int count)
     * dirp is arg1 */
    char __user *ubuf = (char __user *)syscall_argn(args, 1);
    if (!ubuf) return;

    /* Don't process unreasonably large buffers in kernel */
    if (ret > GETDENTS_BUF_MAX) return;

    /* Use a single buffer: copy in, filter in-place, copy back */
    char kbuf[GETDENTS_BUF_MAX];

    unsigned long not_copied = kp_copy_from_user(kbuf, ubuf, ret);
    if (not_copied) return;

    /* Walk the dirent buffer in-place: copy kept entries forward */
    long new_len = 0;
    long pos = 0;

    while (pos < ret) {
        unsigned short d_reclen = *(unsigned short *)(kbuf + pos + DIRENT64_D_RECLEN_OFF);
        if (d_reclen == 0 || pos + d_reclen > ret) break;

        char *d_name = kbuf + pos + DIRENT64_D_NAME_OFF;

        if (!dentry_is_hidden(d_name)) {
            /* Keep this entry - move forward if gap exists */
            if (new_len != pos) {
                kp_memmove(kbuf + new_len, kbuf + pos, d_reclen);
            }
            new_len += d_reclen;
        }

        pos += d_reclen;
    }

    /* If we removed anything, copy the filtered buffer back to userspace */
    if (new_len != ret) {
        compat_copy_to_user(ubuf, kbuf, new_len);
        args->ret = new_len;
    }
}

/* ========================================================================
 * Module entry points
 * ======================================================================== */

static long hide_env_init(const char *args, const char *event, void *__user reserved)
{
    long ret = 0;
    hook_err_t err;

    logki("init, event: %s, args: %s\n", event ? event : "(null)", args ? args : "(null)");
    logki("kernelpatch version: 0x%x\n", kpver);

    /* Parse args: "disable" to start disabled */
    if (args && !strcmp(args, "disable")) {
        hide_enabled = 0;
        logki("starting in disabled mode\n");
    }

    /* Resolve copy_from_user for getdents64 filtering */
    kp_copy_from_user = (typeof(kp_copy_from_user))kallsyms_lookup_name("_copy_from_user");
    if (!kp_copy_from_user) {
        kp_copy_from_user = (typeof(kp_copy_from_user))kallsyms_lookup_name("copy_from_user");
    }
    if (!kp_copy_from_user) {
        logkw("copy_from_user not found, getdents64 filtering disabled\n");
    } else {
        logki("resolved copy_from_user at %llx\n", (uint64_t)kp_copy_from_user);
    }

    /* Hook faccessat - most common root detection method */
    err = hook_syscalln(__NR_faccessat, 4, before_faccessat, 0, 0);
    if (err) {
        logke("hook faccessat failed: %d\n", err);
        ret = err;
        goto out;
    }
    logki("hooked faccessat\n");

    /* Hook newfstatat */
    err = hook_syscalln(__NR3264_fstatat, 4, before_newfstatat, 0, 0);
    if (err) {
        logke("hook newfstatat failed: %d\n", err);
        ret = err;
        goto unhook_faccessat;
    }
    logki("hooked newfstatat\n");

    /* Hook statx */
    err = hook_syscalln(__NR_statx, 4, before_statx, 0, 0);
    if (err) {
        logkw("hook statx failed: %d (may not exist on older kernels)\n", err);
        /* Non-fatal: statx may not exist on older kernels */
    } else {
        logki("hooked statx\n");
    }

    /* Hook openat */
    err = hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err) {
        logke("hook openat failed: %d\n", err);
        ret = err;
        goto unhook_fstatat;
    }
    logki("hooked openat\n");

    /* Hook getdents64 - directory listing filter (3 args: fd, dirp, count) */
    err = hook_syscalln(__NR_getdents64, 3, 0, after_getdents64, 0);
    if (err) {
        logke("hook getdents64 failed: %d\n", err);
        ret = err;
        goto unhook_openat;
    }
    logki("hooked getdents64\n");

    logki("all hooks installed successfully, hide_enabled=%d\n", hide_enabled);
    return 0;

unhook_openat:
    unhook_syscalln(__NR_openat, before_openat, 0);
unhook_fstatat:
    unhook_syscalln(__NR3264_fstatat, before_newfstatat, 0);
unhook_faccessat:
    unhook_syscalln(__NR_faccessat, before_faccessat, 0);
out:
    return ret;
}

/* Simple string copy for response messages */
static int copy_str(char *dst, const char *src, int max)
{
    int i = 0;
    while (i < max - 1 && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return i;
}

/*
 * CTL0 interface - control the module from userspace via APatch Manager.
 *
 * Commands (passed as args string):
 *   "enable"          - Enable hiding
 *   "disable"         - Disable hiding
 *   "status"          - Report status to out_msg
 *   "add:<path>"      - Add a path to dynamic blacklist
 *   "del:<path>"      - Remove a path from dynamic blacklist
 */
static long hide_env_control0(const char *args, char *__user out_msg, int outlen)
{
    char msg[256];
    int i, j;

    kp_memset(msg, 0, sizeof(msg));

    if (!args) {
        copy_str(msg, "error: no args", sizeof(msg));
        goto send;
    }

    logki("ctl0: %s\n", args);

    if (!strcmp(args, "enable")) {
        hide_enabled = 1;
        copy_str(msg, "enabled", sizeof(msg));

    } else if (!strcmp(args, "disable")) {
        hide_enabled = 0;
        copy_str(msg, "disabled", sizeof(msg));

    } else if (!strcmp(args, "status")) {
        /* Simple status without snprintf */
        copy_str(msg, hide_enabled ? "enabled" : "disabled", sizeof(msg));

    } else if (!strncmp(args, "add:", 4)) {
        const char *path = args + 4;
        if (dynamic_path_count >= MAX_HIDE_PATHS) {
            copy_str(msg, "error: full", sizeof(msg));
        } else if (strlen(path) >= PATH_BUF_LEN) {
            copy_str(msg, "error: too long", sizeof(msg));
        } else {
            strncpy(dynamic_paths[dynamic_path_count], path, PATH_BUF_LEN - 1);
            dynamic_paths[dynamic_path_count][PATH_BUF_LEN - 1] = '\0';
            dynamic_path_count++;
            copy_str(msg, "added", sizeof(msg));
        }

    } else if (!strncmp(args, "del:", 4)) {
        const char *path = args + 4;
        int found = 0;
        for (i = 0; i < dynamic_path_count; i++) {
            if (!strcmp(dynamic_paths[i], path)) {
                for (j = i; j < dynamic_path_count - 1; j++) {
                    strncpy(dynamic_paths[j], dynamic_paths[j + 1], PATH_BUF_LEN);
                }
                dynamic_paths[dynamic_path_count - 1][0] = '\0';
                dynamic_path_count--;
                found = 1;
                break;
            }
        }
        copy_str(msg, found ? "removed" : "not found", sizeof(msg));

    } else {
        copy_str(msg, "unknown cmd", sizeof(msg));
    }

send:
    if (out_msg && outlen > 0) {
        int len = sizeof(msg) < outlen ? sizeof(msg) : outlen;
        compat_copy_to_user(out_msg, msg, len);
    }
    return 0;
}

static long hide_env_exit(void *__user reserved)
{
    logki("unloading, removing all hooks...\n");

    unhook_syscalln(__NR_getdents64, 0, after_getdents64);
    unhook_syscalln(__NR_openat, before_openat, 0);
    unhook_syscalln(__NR_statx, before_statx, 0);
    unhook_syscalln(__NR3264_fstatat, before_newfstatat, 0);
    unhook_syscalln(__NR_faccessat, before_faccessat, 0);

    logki("all hooks removed, module unloaded\n");
    return 0;
}

KPM_INIT(hide_env_init);
KPM_CTL0(hide_env_control0);
KPM_EXIT(hide_env_exit);
