/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hide_env.c - APatch KPM for hiding root environment (minimal version)
 * Hooks faccessat and openat to hide root-related files.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <syscall.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("kpm-hide-env");
KPM_VERSION("1.0.7");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("hide_env");
KPM_DESCRIPTION("Hide root environment via syscall hooks");

#define ENOENT 2

/* Module enabled flag */
static int hide_enabled = 1;

/* Check if path should be hidden - inline to avoid relocation issues */
static int path_is_hidden(const char *path)
{
    if (!path || !path[0]) return 0;

    /* su binaries */
    if (!strcmp(path, "/system/bin/su")) return 1;
    if (!strcmp(path, "/system/xbin/su")) return 1;
    if (!strcmp(path, "/sbin/su")) return 1;
    if (!strcmp(path, "/vendor/bin/su")) return 1;

    /* Magisk */
    if (!strcmp(path, "/system/bin/magisk")) return 1;
    if (!strcmp(path, "/data/adb/magisk")) return 1;
    if (!strcmp(path, "/data/adb/magisk.db")) return 1;

    /* APatch */
    if (!strcmp(path, "/data/adb/ap")) return 1;
    if (!strcmp(path, "/data/adb/apd")) return 1;

    /* Prefix checks */
    if (!strncmp(path, "/data/adb/magisk/", 17)) return 1;
    if (!strncmp(path, "/data/adb/modules/", 18)) return 1;
    if (!strncmp(path, "/data/adb/ap/", 13)) return 1;
    if (!strncmp(path, "/sbin/.magisk/", 14)) return 1;

    return 0;
}

/* faccessat hook */
static void before_faccessat(hook_fargs4_t *args, void *udata)
{
    if (!hide_enabled) return;
    if (current_uid() == 0) return;

    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char buf[256];

    long len = compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (len <= 0) return;

    if (path_is_hidden(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/* openat hook */
static void before_openat(hook_fargs4_t *args, void *udata)
{
    if (!hide_enabled) return;
    if (current_uid() == 0) return;

    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char buf[256];

    long len = compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (len <= 0) return;

    if (path_is_hidden(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/* newfstatat hook */
static void before_newfstatat(hook_fargs4_t *args, void *udata)
{
    if (!hide_enabled) return;
    if (current_uid() == 0) return;

    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char buf[256];

    long len = compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (len <= 0) return;

    if (path_is_hidden(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

static long hide_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("hide_env: init, kpver=0x%x\n", kpver);

    hook_err_t err;

    err = hook_syscalln(__NR_faccessat, 4, before_faccessat, 0, 0);
    if (err) {
        pr_err("hide_env: hook faccessat failed: %d\n", err);
        return err;
    }
    pr_info("hide_env: hooked faccessat\n");

    err = hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err) {
        pr_err("hide_env: hook openat failed: %d\n", err);
        return err;
    }
    pr_info("hide_env: hooked openat\n");

    err = hook_syscalln(__NR3264_fstatat, 4, before_newfstatat, 0, 0);
    if (err) {
        pr_err("hide_env: hook fstatat failed: %d\n", err);
    } else {
        pr_info("hide_env: hooked fstatat\n");
    }

    pr_info("hide_env: loaded successfully\n");
    return 0;
}

static long hide_exit(void *__user reserved)
{
    pr_info("hide_env: unloading\n");
    unhook_syscalln(__NR3264_fstatat, before_newfstatat, 0);
    unhook_syscalln(__NR_openat, before_openat, 0);
    unhook_syscalln(__NR_faccessat, before_faccessat, 0);
    return 0;
}

static long hide_ctl0(const char *args, char *__user out_msg, int outlen)
{
    if (args && !strcmp(args, "disable")) {
        hide_enabled = 0;
        pr_info("hide_env: disabled\n");
    } else if (args && !strcmp(args, "enable")) {
        hide_enabled = 1;
        pr_info("hide_env: enabled\n");
    }
    return 0;
}

KPM_INIT(hide_init);
KPM_CTL0(hide_ctl0);
KPM_EXIT(hide_exit);
