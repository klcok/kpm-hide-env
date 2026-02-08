# kpm-hide-env

APatch KernelPatch Module (KPM) for hiding root environment at the kernel level.

## What it does

Hooks 5 Linux syscalls to intercept file access from non-root processes:

| Syscall | Nr | Action |
|---|---|---|
| `faccessat` | 48 | Block `access()` checks on root files |
| `newfstatat` | 79 | Block `stat()` on root files |
| `statx` | 291 | Block `statx()` on root files |
| `openat` | 56 | Block `open()` on root files |
| `getdents64` | 61 | Filter directory listings to hide root entries |

Hidden paths include: `/system/bin/su`, `/data/adb/`, Magisk files, Xposed, BusyBox, etc.

**Only affects non-root (uid != 0) processes.** Root shells and APatch itself are not affected.

## Build

### Via GitHub Actions (recommended)

1. Push this repo to GitHub
2. GitHub Actions will auto-build on push
3. Download `hide_env.kpm` from Actions artifacts

### Manually on Linux

```bash
# Install cross-compiler
sudo apt install gcc-aarch64-linux-gnu

# Clone KernelPatch
git clone --depth=1 https://github.com/bmax121/KernelPatch.git ../KernelPatch

# Build
make TARGET_COMPILE=aarch64-linux-gnu- KP_DIR=../KernelPatch
```

## Install

### Load (temporary, lost after reboot)
1. Open APatch Manager → KPM tab
2. Click + → Load
3. Select `hide_env.kpm`

### Embed (persistent, survives reboot)
1. Open APatch Manager → KPM tab
2. Click + → Embed
3. Select `hide_env.kpm`
4. Repatch boot.img

## Control

Via APatch Manager's KPM Control interface (CTL0):

- `enable` - Enable hiding
- `disable` - Disable hiding
- `status` - Show module status
- `add:/path/to/hide` - Add path to dynamic blacklist
- `del:/path/to/hide` - Remove path from dynamic blacklist
- `list` - List dynamic paths

## Init args

Pass `disable` as init args to start with hiding disabled.

## Logs

View kernel logs via `dmesg | grep hide_env` on the device.

## License

GPL v2
