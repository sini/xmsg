# macOS Antigravity (`agy`) Support Verification Probe

- **Target:** Antigravity CLI (`agy`) process identity on macOS (Darwin)
- **Status:** Implemented; lock semantics measured on macOS 26.5 (aarch64)

---

## 1. Context

On Linux, `xmsg` verifies Antigravity sessions by reading kernel process information from `/proc/<pid>/exe` and `/proc/<pid>/fd/*` (matching the open presence lock file).
On macOS, `xmsg` implements the equivalent identity proof using Darwin kernel APIs:

- `proc_pidpath(pid, ...)` for the executable path;
- `proc_pidinfo(pid, PROC_PIDLISTFDS, ...)` and `proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, ...)` for inspecting open file descriptor vnodes `(vst_dev, vst_ino)`.

The lock semantics in section 4 were measured on macOS 26.5 (aarch64). The steps below confirm a live `agy` on real Darwin hardware.

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

### Step 3: Run the live macOS probe tests

The probes run in every macOS `cargo test`; they need no `agy` binary:

```bash
cargo test --all-features --test gate_u9_identity test_live_macos_agy_probe
cargo test --all-features --test agy_darwin_presence
```

`test_live_macos_agy_probe` asserts, on the test process itself:

1. `crate::process::exe_path(Path::new("/proc"), pid)` succeeds and resolves the binary.
2. `crate::process::open_file_ids(Path::new("/proc"), pid)` contains the `(dev, ino)` of an open temporary file.
3. `has_flock` is clear on that file before `flock(LOCK_EX)` and set after it.

`agy_darwin_presence` runs the holder, release, ambiguity and delivery cases of section 4 with real locks held by this process and by re-executed children.

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

---

## 4. Lock Holder Semantics on macOS (Measured)

The earlier source reading concluded that unprivileged Darwin APIs expose no advisory lock state, and adopted **Option B** (executable path plus open vnode, no lock check). Measurement on macOS 26.5.2 (aarch64) supersedes it.

### Measured

- **`fi_openflags` `FWASLOCKED` (`0x4000`) is sticky.** `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)` reports it on an open file once `flock(2)` has been called on it. It stays set after `LOCK_UN` while that open file (or a dup of it) lives, and clears only when it closes. It is per open file: a sibling descriptor opened separately on the same file reads `0`.
- **kqueue `EVFILT_VNODE` `NOTE_FUNLOCK`** on an `O_EVTONLY` descriptor fires on `LOCK_UN` with the locked descriptor still open, and on the close of a locked descriptor. It does not fire on a lock, a relock, a failed `LOCK_NB` attempt, or a never-locked open and close. It also fires when a descriptor that was locked and then unlocked is closed, even while another process holds the lock. A watcher must never take a test lock itself: its own unlock fires the event.
- **Inherited copies do not release.** An inherited copy of the locked descriptor (a fork without close-on-exec, after which the child exits, closes it, or execs) fires no `NOTE_FUNLOCK` and does not release the lock. Only the last close of the open file, or `LOCK_UN`, does. A second independent open whose `LOCK_NB` attempt fails fires nothing on its close either.
- **A spawning parent shares its descriptors.** While a child is being spawned, `proc_pidfdinfo` on the child briefly shows the parent's descriptors, close-on-exec ones included, until the exec closes them.
- **`KERN_PROCARGS2`** returns a same-UID child's environment for ad-hoc signed and hardened-runtime binaries, and strips it for Apple platform binaries (`/bin/*`).

### What xmsg does

- The flag only **nominates** a holder: a same-UID process whose open file on the presence lock's `(dev, ino)` has `FWASLOCKED` and write access. More than one nominee is ambiguous and fails closed.
- A sole nominee is **held** once xmsg has an `O_EVTONLY` handle on the file (its `(dev, ino)` confirmed by `fstat`) with a `NOTE_FUNLOCK | NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE` watch, has re-read the nominee's flag, and has drained the watch with nothing fired.
- Each later check drains the watch and re-reads the holder's flag. A fired watch, a drain error or a cleared flag **releases** that `(pid, start time)`, and a released process is never attested again, whatever its flag reads. The flag alone is never taken as a live lock.
- A dead or recycled PID's entry is dropped by start time.

### Known limits

- A lock taken and released before xmsg first sees it reads as held: the watch arrives after the event.
- The remaining hide case: a second, independent open of the file that was locked and unlocked (the flag set on it) and is then closed while another process holds the lock. Its close fires `NOTE_FUNLOCK` and releases the current holder, which stays hidden until it restarts. This fails closed.
- More than one unreleased flagged process when no holder is watched yet is ambiguous: no holder, for a call attesting one pid as well as for List.
- A holder that is spawning a child at the first check reads as ambiguous for that check. This is transient and fails closed.

### What xmsg relies on from agy (planned; measured on agy 1.5.3)

Listing and delivering to an agy conversation before its first hook turn relies on two agy behaviours, both measured on agy 1.5.3:

1. agy opens its presence lock close-on-exec: across a live session, its six MCP and child processes never held the lock;
2. agy holds the lock for the whole conversation, with no unlock during tool calls; the only release is at exit.

If another agy version does not behave this way, xmsg treats the lock as unattested, which fails closed, and the conversation is reached through the hook path after its first turn, as before.

agy leaves its presence `.lock` file behind after it exits. A lock file with no holder is the normal finished state of a conversation, and xmsg does not list it.
