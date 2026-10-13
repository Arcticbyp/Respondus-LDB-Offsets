# Respondus LockDown Browser — Offsets, Signatures & Analysis

Offsets, IOCTL protocol, RLDB commands, and analysis for **LockDownBrowser 2.1.6.0.2** (EXE) + **LockDownBrowser.dll** + **LockDownService215.sys**.

**Version:** 2.1.6.0.2
**Updated:** 2026-10-11

---

## What's Inside

### Offsets (`offsets/`)

| File | Description |
| :--- | :--- |
| `offsets.hpp` | C++ header with all offsets, signatures, GSO layout, AKD function RVAs, hook module data, IOCTL codes, and RLDB command VAs |
| `exports.md` | LockDownBrowser.dll export function map (4 obfuscated exports) |
| `process_blacklist.hpp` | Blacklisted process names dumped from a live 2.1.6.0.2 process |
| `ioctl.md` | Driver communication protocol specification (filter port opcodes from dispatcher `FUN_1400015c0`) |
| `rldb_commands.md` | RLDB URL command reference (57 commands documented with VAs) |
| `quiz_active.md` | Quiz active flag analysis (user-mode handler + registry persistence) |

---

## Target: LockDownBrowser.dll (hook module)

| Target | Type |
| :--- | :--- |
| `.cldb` flag slots (LOCKDOWN/PROCTORING/EXIT) | Static RVA + verified x64 access sites |
| DLL exports (4 functions, ordinals 1-4) | Static RVA + Sigscan |
| Keyboard hook callback procedures (5 WH_KEYBOARD_LL + 2 message hooks) | Static RVA + decompiled logic |
| IAT entries for hook imports (SetWindowsHookExA, UnhookWindowsHookEx, CallNextHookEx, SendInput, GetAsyncKeyState) | Computed IAT base + slot offsets |
| Hook state variables (3 HHOOK handles, window handle, scancode, flags) | Static addresses in `.data` |
| Anti-debug canary generator (`FUN_180001F14`) | Static RVA + algorithm |
| CRT init/shutdown lifecycle | Static RVAs + call graph |

### Logic Patterns

* **Find `.cldb` section:**
  `Walk PE sections` → `match name .cldb` → `get VirtualAddress` (expect `0x1C000` on x64)
* **Find flag sites:**
  `Scan .text for RIP-relative 48 89 / 48 8B / 48 83 3D / 48 39` → `resolve disp32 (target = insn_addr + insn_len + disp)` → `check if target falls in .cldb range`
* **Find quiz_active:**
  `Scan .text for C7 05 [disp32] 01/00` → `resolve disp32` → `check if target in .data`
* **Find exports:**
  `Parse PE export directory` → `match ?CLDBDo prefix string`
* **Find hook call sites:**
  `Scan .text for FF 15` → `resolve IAT` → `check if user32!SetWindowsHookExA`

---

## Target: LockDownService215.sys (ApriorIT minifilter driver)

| Target | Type |
| :--- | :--- |
| **Filter Communication Port** (`\\.\ApDriverPort`) | Opcodes read from dispatcher `FUN_1400015c0` + reply framing |
| **Connection gate** | Strict PID allowlist, forced disconnect on mismatch |
| **Kernel notifications** | PsSetCreateProcessNotifyRoutineEx, PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine |
| **Crypto subsystem** | BCrypt AES-256-CBC + RSA-2048 |
| **Code integrity** | CiValidateFileObject signature validation |
| **Overlay detection** | DwmImageResolver, BrowserImageResolver |
| **DriverLogger** | Kernel-side logging to `C:\Users\Public\Documents\` |
| **Whole-process fileless scan** | Opcode `0x14` — batch thread verification via ZwQueryInformationThread + ZwQueryVirtualMemory |

See `ioctl.md` for complete protocol documentation.

---

## Target: LockDownBrowser.exe (Main EXE, 2.1.6.0.2)

| Target | Type |
| :--- | :--- |
| Version detection | Pattern scan `.text` for `sub rsp` operand differences in wrapper_reflection/wrapper_threadhacks |
| AKD detection subsystem | Encrypted driver channel via `akd_mediator`; functions: `parent`, `wrapper_reflection`, `wrapper_threadhacks`, `helper_reflection`, `helper_threadinfo`, `init_stub`, `akd_step1`, `akd_step2` |
| GlobalSecurityObject (GSO) | 26+ fields at known offsets; pointer at `0x140CEDEA0` |
| CheckDetoursKB32 hook detection | `CMP byte ptr [R14], 0xE9` — pattern `41 80 3E E9` |
| Client-side driver install | `FilterLoad` + `SetupAPI` imports |
| Driver communication | `CreateFileW` + `DeviceIoControl`, via `fltlib` hidden IAT |
| Process blacklist | Heap-allocated UTF-16LE strings (3020+ entries) |
| Window class blacklist | Static strings in `.rdata` |
| Registry flags (`active`, `tvc`, `tvd`) | `HKCU\SOFTWARE\Respondus\` |
| RLDB command strings | 57 embedded tokens in `.rdata` |
| Quiz active flag | `rldbqn=1` / `rldbxb=1` handler at `0x14006BCA0` |

---

## New in 2.1.6.0.2 (vs 2.1.6.0.0)

### AKD Detection Subsystem Restructured

2.1.6.0.2 replaces the single `AKD init` function (2.1.6.0.0: `0x140274320`) with a three-stage pipeline:

1. **`init_stub` (`0x140275970`)** — allocates and initializes the GlobalSecurityObject, stores pointer at `0x140CEDEA0`
2. **`akd_step1` (`0x140043480`)** — heavy computation, no API calls reached
3. **`akd_step2` (`0x140024260`)** — heavy computation, sets `GSO+RESULT` on success

### Version Detection Patterns

The `sub rsp` operand in `wrapper_reflection` and `wrapper_threadhacks` differs between versions:

| Function | 2.1.6.0.0 | 2.1.6.0.2 |
|----------|-----------|-----------|
| wrapper_reflection | `sub rsp, 0x260` | `sub rsp, 0x180` |
| wrapper_threadhacks | `sub rsp, 0x120` | `sub rsp, 0xC0` |

### GSO Field Layout

The GlobalSecurityObject is now allocated by `init_stub` rather than being a static/global. Known fields:

| Offset | Field | Description |
|--------|-------|-------------|
| 0x00 | VTABLE_1 | vtable ptr |
| 0x08 | VTABLE_2 | vtable ptr (self-reference) |
| 0x10 | VTABLE_3 | vtable ptr |
| 0x18 | VTBL_WORD | uint16_t |
| 0x50-0x78 | UNKNOWN_* | vtable cluster + ptrs |
| 0xC0 | FLAG_0C0 | uint8_t |
| 0x108 | FLAG_108 | uint8_t |
| 0x150 | FLAG_150 | uint8_t |
| 0x178 | RESULT | uint8_t — set by akd_step2 |
| 0x1B0 | COUNTER_B0 | uint32_t — incremented by wrapper_threadhacks |
| 0x1B9 | FLAG_B9 | uint8_t — set by wrapper_threadhacks |
| 0x210 | SUBOBJ_210 | ptr — vtable of sub-object |
| 0x248 | COUNTER_248 | uint32_t — incremented by wrapper_reflection |
| 0x250 | FLAG_250 | uint8_t — set by wrapper_reflection |
| 0x5F70 | PARENT_DWORD | uint32_t — checked by parent AKD |
| 0x5F78 | PARENT_PTR | ptr |
| 0x5F80-0x6BCC | PARENT_* | parent AKD state fields |

### Hook Module Changes

The hook module (`LockDownBrowser.dll`) in 2.1.6.0.2 uses 5 WH_KEYBOARD_LL procedures (vs fewer in prior versions), selected at install time by flag bits. VK_F12 is no longer blocked globally in the hook procedures.

---

## Credits

* **GitHub:** [arcticdev00](https://github.com/arcticdev00)
* **Discord:** [Join the server](https://discord.gg/GyBxnYZsXN)
