# macOS Antigravity (`agy`) Support Verification Probe

- **Target:** Antigravity CLI (`agy`) process identity on macOS (Darwin)
- **Status:** Implemented, unverified on macOS hardware (verified on Linux)

---

## 1. Context

On Linux, `xmsg` verifies Antigravity sessions by reading kernel process information from `/proc/<pid>/exe` and `/proc/<pid>/fd/*` (matching the open presence lock file).
On macOS, `xmsg` implements the equivalent identity proof using Darwin kernel APIs:
- `proc_pidpath(pid, ...)` for the executable path;
- `proc_pidinfo(pid, PROC_PIDLISTFDS, ...)` and `proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, ...)` for inspecting open file descriptor vnodes `(vst_dev, vst_ino)`.

Because neither build orchestrator currently runs on a macOS host, macOS `agy` support is classified as **implemented, unverified**. A user on macOS should execute the following probes to confirm behavior on real Darwin hardware.

---

## 2. Live Verification Commands for macOS Operators

With a live Antigravity (`agy`) session running in a terminal, locate its PID:
```bash
pgrep -f agy
```
Let `<AGY_PID>` be the PID of the running `agy` process.

### Step 1: Confirm `presence/<id>.lock` remains open
Run `lsof` against the running `agy` process:
```bash
lsof -p <AGY_PID> | grep presence
```
**Expected Output:**
One or more open file descriptors showing the presence lock file in `~/.gemini/antigravity-cli/presence/<conversation_id>.lock`:
```
agy  <PID>  <USER>   19u  REG  1,14  0  12345678 /Users/<USER>/.gemini/antigravity-cli/presence/<CONVERSATION_ID>.lock
```
Confirm:
1. The lock file remains open for the entire lifetime of the `agy` process.
2. The file descriptor has write or read-write access.

### Step 2: Confirm `proc_pidpath` returns a stable binary path
Run the Darwin `proc_pidpath` query or check with `ps`:
```bash
ps -p <AGY_PID> -o comm=
```
Or with Python using `ctypes` to call `libproc` directly:
```bash
python3 -c "
import ctypes, os
libproc = ctypes.CDLL('/usr/lib/libproc.dylib')
buf = ctypes.create_string_buffer(4096)
pid = <AGY_PID>
ret = libproc.proc_pidpath(pid, buf, 4096)
if ret > 0:
    print('proc_pidpath:', buf.value.decode('utf-8'))
else:
    print('Failed:', os.strerror(ctypes.get_errno()))
"
```
**Expected Output:**
A clean, absolute, canonical path to the `agy` executable binary (e.g. `/opt/homebrew/bin/agy` or `/nix/store/.../bin/agy`).

### Step 3: Run the ignored Rust test against a live `agy` process
Run the integration probe test in the `xmsg` repository:
```bash
AGY_PID=<AGY_PID> cargo test --test gate_u9_identity -- --ignored test_live_macos_agy_probe
```
This test asserts:
1. `crate::process::exe_path(Path::new("/proc"), pid)` succeeds and resolves the binary.
2. `crate::process::open_file_ids(Path::new("/proc"), pid)` contains the `(dev, ino)` of the lock file in `~/.gemini/antigravity-cli/presence/*.lock`.

---

## 3. Measured Linux Baseline (Reference)

Measured against live Antigravity PID `2739763` on Linux 6.12 (x86_64):

1. **Executable path:**
   ```bash
   readlink /proc/2739763/exe
   # Output: /nix/store/lams9kvhfa5vkqs3wfnfwdd8iwczc8v6-antigravity-cli-1.2.13/bin/agy
   ```
2. **Open presence lock:**
   ```bash
   ls -l /proc/2739763/fd | grep presence
   # Output: lrwx------ 1 sini users 64 Oct  7 07:51 19 -> /home/sini/.gemini/antigravity-cli/presence/660dbde7-73c4-4a08-ad0f-997b93f44e8d.lock
   ```
3. **Stat inode comparison:**
   ```bash
   stat -L /proc/2739763/fd/19
   # Device: 0,46    Inode: 1148992
   stat /home/sini/.gemini/antigravity-cli/presence/660dbde7-73c4-4a08-ad0f-997b93f44e8d.lock
   # Device: 0,46    Inode: 1148992
   ```
Both devices and inodes match identically.
