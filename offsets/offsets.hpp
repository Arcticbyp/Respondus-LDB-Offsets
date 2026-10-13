#pragma once
#include <cstdint>

/*
 * LockDownBrowser 2.1.6.0.2 - offsets.hpp
 */

namespace ldb {


// ---------------------------------------------------------------------------
// VERSION DETECTION -- pattern-scan the .text section
// ---------------------------------------------------------------------------

namespace version_detect {
    // wrapper_reflection sub rsp differs:
    //   2.1.6.0.0: 48 81 EC 60 02 00 00  (sub rsp, 0x260)
    //   2.1.6.0.2: 48 81 EC 80 01 00 00  (sub rsp, 0x180)
    static constexpr const uint8_t SIG_REFL_20600[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x81,0xEC,0x60,0x02,0x00,0x00};
    static constexpr const uint8_t SIG_REFL_20602[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x81,0xEC,0x80,0x01,0x00,0x00};

    // wrapper_threadhacks sub rsp differs:
    //   2.1.6.0.0: 48 81 EC 20 01 00 00  (sub rsp, 0x120)
    //   2.1.6.0.2: 48 81 EC C0 00 00 00  (sub rsp, 0xC0)
    static constexpr const uint8_t SIG_THREAD_20600[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x81,0xEC,0x20,0x01,0x00,0x00};
    static constexpr const uint8_t SIG_THREAD_20602[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x56,0x41,0x57,
        0x48,0x81,0xEC,0xC0,0x00,0x00,0x00};
};

// ---------------------------------------------------------------------------
// AKD FUNCTION SIGNATURES
// ---------------------------------------------------------------------------

namespace akd {

    // "parent" -- main AKD dispatcher
    // 2.1.6.0.2: 0x1402BB840 (4707 bytes)  2.1.6.0.0: 0x1402BF390 (4643 bytes)
    // Deobfuscated: calls GetSystemTime, SystemTimeToFileTime.
    // Accesses globals 0x140CEDF60, 0x140CEDF80, 0x140CEDF40 with many sub-offsets.
    // Stopped early at 0x1402BBFBC (partial trace -- 70 instrs, 20.6% filler).
    static constexpr uint32_t RVA_20602 = 0x2BB840;
    static constexpr uint32_t RVA_20600 = 0x2BF390;
    static constexpr uint32_t SIZE_20602 = 4707;
    static constexpr uint32_t SIZE_20600 = 4643;

    static constexpr const uint8_t SIG[] = {
        0x48,0x89,0x5C,0x24,0x08, 0x48,0x89,0x74,0x24,0x10, 0x57,
        0x48,0x83,0xEC,0x70, 0x48,0x8B,0x05,0x00,0x00,0x00,0x00,
        0x48,0x33,0xC4, 0x48,0x89,0x44,0x24,0x68, 0x48,0x8B};

    // wrapper_reflection -- reflection load detection
    // 2.1.6.0.2: 0x140277BF0 (1949 bytes)  2.1.6.0.0: 0x1402786B0 (7358 bytes)
    // Deobfuscated: 38 instrs, 73% filler. reads GS cookie, increments GSO+0x248,
    // reads GSO+0x210 vtable, calls helper_reflection, sets GSO+0x250 on success.
    static constexpr uint32_t RVA_WRAP_REFL_20602 = 0x277BF0;
    static constexpr uint32_t RVA_WRAP_REFL_20600 = 0x2786B0;
    static constexpr uint32_t SIZE_WRAP_REFL_20602 = 1949;
    static constexpr uint32_t SIZE_WRAP_REFL_20600 = 7358;

    static constexpr const uint8_t SIG_WRAP_REFL_20602[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x81,0xEC,0x80,0x01,0x00,0x00, 0x48,0x8B,0x05,0x00,0x00,0x00,0x00};
    static constexpr const uint8_t SIG_WRAP_REFL_20600[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x81,0xEC,0x60,0x02,0x00,0x00, 0x48,0x8B,0x05,0x00,0x00,0x00,0x00};

    // wrapper_threadhacks -- thread hack detection
    // 2.1.6.0.2: 0x140278390 (966 bytes)  2.1.6.0.0: 0x14027A370 (4566 bytes)
    // Deobfuscated: 37 instrs, 79.4% filler. increments GSO+0x1B0,
    // calls helper_threadinfo, sets GSO+0x1B9 on success, calls display check.
    static constexpr uint32_t RVA_WRAP_THREAD_20602 = 0x278390;
    static constexpr uint32_t RVA_WRAP_THREAD_20600 = 0x27A370;
    static constexpr uint32_t SIZE_WRAP_THREAD_20602 = 966;
    static constexpr uint32_t SIZE_WRAP_THREAD_20600 = 4566;

    static constexpr const uint8_t SIG_WRAP_THREAD_20602[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x56,0x41,0x57,
        0x48,0x81,0xEC,0xC0,0x00,0x00,0x00, 0x48,0x8B,0x05,0x00,0x00,0x00,0x00};
    static constexpr const uint8_t SIG_WRAP_THREAD_20600[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x81,0xEC,0x20,0x01,0x00,0x00, 0x48,0x8B,0x05,0x00,0x00,0x00,0x00};

    // helper_reflection -- reflection status request path to driver
    // STABLE: 0x14002E170 (5545 bytes) in both versions
    static constexpr uint32_t RVA_HELP_REFL = 0x2E170;
    static constexpr uint32_t SIZE_HELP_REFL = 5545;

    static constexpr const uint8_t SIG_HELP_REFL[] = {
        0x48,0x89,0x5C,0x24,0x18, 0x55,0x56,0x57, 0x41,0x54,0x41,0x55,
        0x41,0x56,0x41,0x57, 0x48,0x8D,0xAC,0x24,0xC0,0xFE,0xFF,0xFF,
        0x48,0x81,0xEC,0x40,0x02,0x00,0x00, 0x48};

    // helper_threadinfo -- thread info request path to driver
    // STABLE RVA: 0x14002F720. Size grew: 4850 (20600)   6910 (20602).
    static constexpr uint32_t RVA_HELP_THREAD = 0x2F720;
    static constexpr uint32_t SIZE_HELP_THREAD_20600 = 4850;
    static constexpr uint32_t SIZE_HELP_THREAD_20602 = 6910;

    static constexpr const uint8_t SIG_HELP_THREAD[] = {
        0x48,0x89,0x5C,0x24,0x18, 0x55,0x56,0x57, 0x41,0x54,0x41,0x55,
        0x41,0x56,0x41,0x57, 0x48,0x8D,0xAC,0x24,0x00,0xFF,0xFF,0xFF,
        0x48,0x81,0xEC,0x00,0x02,0x00,0x00, 0x48};

    // init_stub (2.1.6.0.2 only) -- allocates and initializes GSO
    // 0x140275970 (327 bytes). Deobfuscated: 37 instrs, 90.9% filler.
    static constexpr uint32_t RVA_INIT_STUB = 0x275970;
    static constexpr uint32_t SIZE_INIT_STUB = 327;

    static constexpr const uint8_t SIG_INIT_STUB[] = {
        0x48,0x89,0x5C,0x24,0x18, 0x55,0x56,0x57,
        0x48,0x83,0xEC,0x20, 0x48,0x8B,0xF1, 0xB9,0x20,0x00,0x00,0x00, 0xE8};

    // akd_step1 (2.1.6.0.2 only) -- 0x140043480 (3047 bytes)
    // Heavy computation, no API calls reached, 81.8% filler dropped.
    static constexpr uint32_t RVA_STEP1 = 0x43480;
    static constexpr uint32_t SIZE_STEP1 = 3047;

    static constexpr const uint8_t SIG_STEP1[] = {
        0x48,0x89,0x4C,0x24,0x08, 0x55,0x53,0x56,0x57, 0x41,0x54,0x41,0x55,
        0x41,0x56,0x41,0x57, 0x48,0x8D,0x6C,0x24,0xE1, 0x48,0x81,0xEC,0xC8,
        0x00,0x00,0x00, 0x48,0x8B,0xF9};

    // akd_step2 (2.1.6.0.2 only) -- 0x140024260 (3200 bytes)
    // Heavy computation, no API calls reached, 84.7% filler dropped.
    static constexpr uint32_t RVA_STEP2 = 0x24260;
    static constexpr uint32_t SIZE_STEP2 = 3200;

    static constexpr const uint8_t SIG_STEP2[] = {
        0x48,0x89,0x4C,0x24,0x08, 0x53,0x55,0x56,0x57, 0x41,0x54,0x41,0x55,
        0x41,0x56,0x41,0x57, 0x48,0x83,0xEC,0x38, 0x4C,0x8D,0x4C,0x24,0x78,
        0xBB,0xC6,0xB4,0x00,0x00, 0x41};

    // AKD init (2.1.6.0.0 only, replaced by init_stub/step1/step2 in 20602)
    // 0x140274320 (3881 bytes)
    static constexpr uint32_t RVA_INIT_20600 = 0x274320;
    static constexpr uint32_t SIZE_INIT_20600 = 3881;

    static constexpr const uint8_t SIG_INIT_20600[] = {
        0x48,0x89,0x4C,0x24,0x08, 0x53,0x55,0x56,0x57, 0x41,0x54,0x41,0x55,
        0x41,0x56,0x41,0x57, 0x48,0x83,0xEC,0x48, 0x4C,0x8D,0x8C,0x24,
        0x88,0x00,0x00,0x00, 0xBB,0x6A,0x18};
};

// ---------------------------------------------------------------------------
// GlobalSecurityObject 
// ---------------------------------------------------------------------------

namespace gso {
    // Byte offsets within the GlobalSecurityObject.
    // Object allocated by init_stub (0x140275970), passed to akd_step1/step2.
    enum : uint32_t {
        VTABLE_1      = 0x00,  // vtable ptr (initialized by init_stub)
        VTABLE_2      = 0x08,  // vtable ptr (self-reference)
        VTABLE_3      = 0x10,  // vtable ptr
        VTBL_WORD     = 0x18,  // uint16_t = 0x101
        UNKNOWN_50    = 0x50,  // int32_t = -1
        UNKNOWN_54    = 0x54,  // ptr
        UNKNOWN_60    = 0x60,  // ptr (second vtable cluster)
        UNKNOWN_68    = 0x68,  // ptr
        UNKNOWN_70    = 0x70,  // ptr
        UNKNOWN_78    = 0x78,  // ptr
        FLAG_0C0      = 0xC0,  // uint8_t = 0
        FLAG_108      = 0x108, // uint8_t = 0
        FLAG_150      = 0x150, // uint8_t = 0
        RESULT        = 0x178, // uint8_t = 1 on success (set by akd_step2)
        COUNTER_B0    = 0x1B0, // uint32_t -- incremented by wrapper_threadhacks
        FLAG_B9       = 0x1B9, // uint8_t -- set to 1 by wrapper_threadhacks on success
        SUBOBJ_210    = 0x210, // ptr -- read by wrapper_reflection, vtable of sub-object
        COUNTER_248   = 0x248, // uint32_t -- incremented by wrapper_reflection
        FLAG_250      = 0x250, // uint8_t -- set to 1 by wrapper_reflection on success
        // ... gap to 0x5F70 ...
        PARENT_DWORD  = 0x5F70,// uint32_t -- checked against 0x4 by parent AKD
        PARENT_PTR    = 0x5F78,// ptr -- written with RSI, tested for null by parent
        PARENT_BYTE   = 0x5F88,// uint8_t -- tested against SIL by parent
        PARENT_DWORD2 = 0x5F80,// uint32_t -- moved into EDX for call by parent
        PARENT_DWORD3 = 0x5F84,// uint32_t -- decremented, tested against 0 by parent
        PARENT_DWORD4 = 0x6BC8,// uint32_t -- tested against 0 by parent
        PARENT_DWORD5 = 0x6BCC,// uint32_t -- tested against 0 by parent
    };

    // Convert GSO offset to VA given a GSO base pointer
    inline uintptr_t offset_to_va(uintptr_t gso_base, uint32_t offset) {
        return gso_base + offset;
    }

    // GSO pointer stored globally by init_stub at:
    static constexpr uintptr_t GSO_GLOBAL_PTR = 0x140CEDEA0;
};

// ---------------------------------------------------------------------------
// GLOBAL DATA ADDRESSES (from code references in Ghidra)
// ---------------------------------------------------------------------------

namespace globals {

    // GS cookie / security cookie
    static constexpr uintptr_t GS_COOKIE_RESULT = 0x140CEDE78;  // byte, SETNZ target
    static constexpr uintptr_t GS_COOKIE_STR    = 0x140CEDE79;  // string ptr

    // Security cookie check globals (from FUN_140001020)
    static constexpr uintptr_t SEC_CHK_DWORD_1  = 0x140CEDE30;
    static constexpr uintptr_t SEC_CHK_DWORD_2  = 0x140CEDE68;
    static constexpr uintptr_t SEC_INIT_PTR_1   = 0x140CEDE38;
    static constexpr uintptr_t SEC_INIT_PTR_2   = 0x140CEDE40;
    static constexpr uintptr_t SEC_INIT_PTR_3   = 0x140CEDE50;
    static constexpr uintptr_t SEC_INIT_DWORD   = 0x140CEDE58;  // = 2

    // Parent AKD object pointers (from parent deobfuscation)
    static constexpr uintptr_t PARENT_MAIN_OBJ   = 0x140CEDF60;  // read by parent AKD
    static constexpr uintptr_t PARENT_SECOND_OBJ = 0x140CEDF80;  // read/written by parent
    static constexpr uintptr_t PARENT_TERTIARY_OBJ = 0x140CEDF40; // read by parent (many sub-offs)

    // Threadhacks call target (from wrapper_threadhacks deobfuscation)
    static constexpr uintptr_t THREADHACKS_TARG  = 0x140CEDF48;  // ptr deref by wrapper

    // Monitor ID counters (from FUN_140007960)
    static constexpr uintptr_t MONITOR_PROC_ID  = 0x140CF3A90;
    static constexpr uintptr_t MONITOR_THREAD_ID = 0x140CF3A78;
    static constexpr uintptr_t MONITOR_GLOB_ID   = 0x140CF4550;

    // Sub-object init fields (from FUN_140006190/200/280)
    static constexpr uintptr_t SUBOBJ_1_SIZE  = 0x140CF3248;  // = 1
    static constexpr uintptr_t SUBOBJ_1_FLAGS = 0x140CF3250;  // = 0xf
    static constexpr uintptr_t SUBOBJ_2_SIZE  = 0x140CF3228;  // = 0xc
    static constexpr uintptr_t SUBOBJ_3_SIZE  = 0x140CF32A0;  // = 9

    // Monitor init (from FUN_140007DD0)
    static constexpr uintptr_t MONITOR_PTR  = 0x140CE9E08;
    static constexpr uintptr_t MONITOR_DWORD = 0x140CE8C38;  // = 0x47b33b74
};

// ---------------------------------------------------------------------------
// KEY FUNCTION ADDRESSES (verified in Ghidra)
// ---------------------------------------------------------------------------

namespace funcs {

    // Entry / init
    static constexpr uintptr_t ENTRY_POINT     = 0x140001000;
    static constexpr uintptr_t SEC_INIT        = 0x140001020;
    static constexpr uintptr_t SEC_CHECK       = 0x1400010AF0;

    // ApDriver init wrappers (thin, register notification callbacks)
    static constexpr uintptr_t APDRV_WRAP_1 = 0x140006010;
    static constexpr uintptr_t APDRV_WRAP_2 = 0x140006040;
    static constexpr uintptr_t APDRV_WRAP_3 = 0x140006070;
    static constexpr uintptr_t APDRV_WRAP_4 = 0x1400060A0;
    static constexpr uintptr_t APDRV_WRAP_5 = 0x1400060D0;
    static constexpr uintptr_t APDRV_WRAP_6 = 0x140006100;
    static constexpr uintptr_t APDRV_INIT_1 = 0x140006190;
    static constexpr uintptr_t APDRV_INIT_2 = 0x140006200;
    static constexpr uintptr_t APDRV_INIT_3 = 0x140006280;
    static constexpr uintptr_t APDRV_REG    = 0x14036E0F0;

    // Monitor callbacks
    static constexpr uintptr_t MONITOR_CB      = 0x140007960;
    static constexpr uintptr_t MONITOR_INIT    = 0x140007DD0;

    // Utility (readable, non-obfuscated)
    static constexpr uintptr_t PE_CHECK        = 0x140AB0880;  // MZ+PE+PE32+ validation
    static constexpr uintptr_t FIND_PE_SECTION = 0x140AB07E0;
    static constexpr uintptr_t INT_TO_STR      = 0x140035890;  // integer decimal string
    static constexpr uintptr_t GS_VALIDATE     = 0x140A450E0;  // GS cookie check
    static constexpr uintptr_t ALLOC_256       = 0x140A44F90;  // allocator (size in ECX)
    static constexpr uintptr_t GET_SINGLETON   = 0x140A88BA0;  // getter (called  4 by threadhacks)
    static constexpr uintptr_t MEMCPY_16       = 0x140AB0AD0;  // 16-byte copy
    static constexpr uintptr_t VTBL_DISPATCH   = 0x140AB0AA0;  // virtual method dispatch
};

// ---------------------------------------------------------------------------
// IMPORT STUBS 
// ---------------------------------------------------------------------------

namespace imports {

    // FLTLIB -- driver communication (these are the ones Layer A / driver comm code uses)
    namespace fltlib {
        static constexpr uintptr_t filter_connect_port = 0x140364CC8;
        static constexpr uintptr_t filter_send_message = 0x140364CCE;
        static constexpr uintptr_t filter_get_message  = 0x140364CD4;
        static constexpr uintptr_t filter_load         = 0x140364CDA;
    };

    // BCrypt -- crypto (used by driver code, possibly by AKD encrypted channel)
    namespace bcrypt {
        static constexpr uintptr_t encrypt        = 0x140364D04;
        static constexpr uintptr_t decrypt        = 0x140364D0A;
        static constexpr uintptr_t gen_random     = 0x140364D28;
        static constexpr uintptr_t gen_symmetric  = 0x140364CF8;
        static constexpr uintptr_t gen_key_pair   = 0x140364CFE;
    };

    // Driver port opcodes (from analysis docs, unchanged in 2.1.6.0.2)
    namespace port {
        static constexpr uint32_t OPCODE_QUERY_SET_MIN     = 0x6;
        static constexpr uint32_t OPCODE_QUERY_SET_MAX     = 0xF;
        static constexpr uint32_t OPCODE_GET_VERSION       = 0x11;
        static constexpr uint32_t OPCODE_SET_STATE_FLAG    = 0x13;
        static constexpr uint32_t OPCODE_WHOLE_PROCESS    = 0x14;  // thread fileless scan
    };
};

// ---------------------------------------------------------------------------
// AKD ERROR/STATUS STRING ADDRESSES 
// ---------------------------------------------------------------------------

namespace akd_str {
    // These are in .rdata at 0x140B138xx in 2.1.6.0.2
    // (different from 2.1.6.0.0 which had them at 0x140B0Fxxx)
    static constexpr uintptr_t INVALID_PID              = 0x140B13840;
    static constexpr uintptr_t FAILED_1ST_REFLECT_REQ  = 0x140B13850;
    static constexpr uintptr_t FAILED_REFLECT_REQ      = 0x140B13880;
    static constexpr uintptr_t FAILED_DECRYPT_REFLECT  = 0x140B138B0;
    static constexpr uintptr_t FAILED_ENCRYPT_THREAD   = 0x140B138E0;
    static constexpr uintptr_t DWM_LATE_DRIVER         = 0x140B13910;
    static constexpr uintptr_t FAILED_1ST_THREAD_REQ   = 0x140B13958;
    static constexpr uintptr_t FAILED_2ND_THREAD_REQ   = 0x140B13988;
    static constexpr uintptr_t FAILED_DECRYPT_THREAD   = 0x140B139B8;
};

// ---------------------------------------------------------------------------
// DETECTION PATTERNS 
// ---------------------------------------------------------------------------

namespace patterns {

    //    CheckDetoursKB32 -- Detours-style hook detection   
    // From deobfuscation docs: reads first byte at target address, checks for 0xE9 (JMP rel32)
    // This is the actual hook test instruction. Find this pattern to locate the check.
    //
    // Verified instruction:  CMP byte ptr [R14], 0xE9
    // In shellcode:  41 80 3E E9
    //
    // Usage: scan .text for this 4-byte pattern. The surrounding function is CheckDetoursKB32.
    // Note: the function is in obfuscated Layer A and is NOT disassembled by Ghidra.
    //       Its address shifts between versions -- pattern scan is the reliable way to find it.
    static constexpr const uint8_t DETOURS_HOOK_CHECK[] = { 0x41, 0x80, 0x3E, 0xE9 };
    static constexpr size_t DETOURS_HOOK_CHECK_LEN = 4;

    //    AKD function entry signatures (for locating AKD code at runtime)   
    // These are the first bytes of each AKD function. Use with wildcard scanning
    // (the 0x00 bytes in RIP-relative displacements are wildcards).

    // "parent" -- same first 16 bytes in both versions
    static constexpr const uint8_t PARENT_ENTRY[] = {
        0x48,0x89,0x5C,0x24,0x08, 0x48,0x89,0x74,0x24,0x10, 0x57,0x48,0x83,0xEC,0x70, 0x48,0x8B};

    // wrapper_reflection entry (version-dependent at byte 22)
    static constexpr const uint8_t WRAP_REFL_ENTRY_20602[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57, 0x48,0x81,0xEC,0x80,0x01};
    static constexpr const uint8_t WRAP_REFL_ENTRY_20600[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57, 0x48,0x81,0xEC,0x60,0x02};

    // wrapper_threadhacks entry (version-dependent at byte 18)
    static constexpr const uint8_t WRAP_THREAD_ENTRY_20602[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x56,0x41,0x57, 0x48,0x81,0xEC,0xC0,0x00};
    static constexpr const uint8_t WRAP_THREAD_ENTRY_20600[] = {
        0x48,0x89,0x5C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57, 0x48,0x81,0xEC,0x20,0x01};

    // helper_reflection -- stable across versions
    static constexpr const uint8_t HELP_REFL_ENTRY[] = {
        0x48,0x89,0x5C,0x24,0x18, 0x55,0x56,0x57, 0x41,0x54,0x41,0x55,
        0x41,0x56,0x41,0x57, 0x48,0x8D,0xAC,0x24,0xC0,0xFE,0xFF,0xFF,
        0x48,0x81,0xEC,0x40,0x02};

    // helper_threadinfo -- stable entry
    static constexpr const uint8_t HELP_THREAD_ENTRY[] = {
        0x48,0x89,0x5C,0x24,0x18, 0x55,0x56,0x57, 0x41,0x54,0x41,0x55,
        0x41,0x56,0x41,0x57, 0x48,0x8D,0xAC,0x24,0x00,0xFF,0xFF,0xFF,
        0x48,0x81,0xEC,0x00,0x02};
};

// ---------------------------------------------------------------------------
// HIDDEN IAT (from iat_calls.py -- 1181 slots recovered)
// ---------------------------------------------------------------------------
//
// The PE import table only lists CEF runtime imports. The AKD security code
// resolves its own API surface through hidden IAT slots in .rdata.
//
//
// The AKD code (wrapper_reflection, wrapper_threadhacks, helper_*)
// makes ZERO API calls when emulated with stubbed returns.
// The parent AKD function calls: GetSystemTime, SystemTimeToFileTime.
//
// Known IAT slot location: .rdata section starts at RVA 0xB0F000 (VA 0x140B0F000)
// The slots are 8-byte aligned, interspersed with IMAGE_IMPORT_BY_NAME RVAs.
//
// ---------------------------------------------------------------------------
// Hook Module (lockdownbrowser.dll, 2.1.6.0.2)
// ---------------------------------------------------------------------------
//
// lockdownbrowser.dll is a separate PE loaded by LockDownBrowser.exe.
// It implements the keyboard/mouse hook subsystem that blocks input during exams.
// All functions use obfuscated names (CLDBDo*). The real logic is in the
// hook procedures and the data used to track hook state.

namespace hookdll {

    //    Base / layout   
    static constexpr uintptr_t DLL_BASE   = 0x180000000;
    static constexpr uintptr_t TEXT_START = 0x180001000;
    static constexpr uintptr_t TEXT_END   = 0x18000E9FF;
    static constexpr uintptr_t RDATA_START = 0x18000F000;
    static constexpr uintptr_t RDATA_END   = 0x180018BFF;
    static constexpr uintptr_t DATA_START  = 0x180019000;
    static constexpr uintptr_t DATA_END    = 0x18001AB6F;

    //    Exported (obfuscated) entry points   
    // Only the DLL entry point (DllMain) is informative from the exports.
    // The CLDB-named exports are stubs -- the real logic is internal.
    static constexpr uintptr_t EXPORT_DLLMAIN      = 0x180001ED4;  // entry / DllMain
    static constexpr uintptr_t EXPORT_CLDB_DO_1    = 0x180001000;  // CLDBDoSomeOtherStuff
    static constexpr uintptr_t EXPORT_CLDB_DO_2    = 0x1800010E0;  // CLDBDoSomeOtherStuffs
    static constexpr uintptr_t EXPORT_CLDB_DO_3    = 0x180001110;  // CLDBDoSomeStuff
    static constexpr uintptr_t EXPORT_CLDB_DO_4    = 0x180001330;  // CLDBDoYetMoreStuff

    //    IAT: hook-related imports   
    // IAT base in .rdata. Each slot is 8 bytes (x64). Verified by disassembly:
    //   GetAsyncKeyState is called via [0x18000F278] confirmed in FUN_1800013A0/14A0/17C0/18E0/1AD0.
    //   EXTERNAL ordinals: Unhook=1, SetWindowsHookExA=2, SendInput=3, CallNextHookEx=4, GetAsyncKeyState=5.
    static constexpr uintptr_t IAT_BASE = 0x18000F250;

    static constexpr uintptr_t IAT_UnhookWindowsHookEx = 0x18000F258;
    static constexpr uintptr_t IAT_SetWindowsHookExA    = 0x18000F260;
    static constexpr uintptr_t IAT_SendInput           = 0x18000F268;
    static constexpr uintptr_t IAT_CallNextHookEx      = 0x18000F270;
    static constexpr uintptr_t IAT_GetAsyncKeyState     = 0x18000F278;

    //    Hook state (in .data, tracked at runtime)   
    // These are HHOOK handles written by SetWindowsHookExA and cleared by UnhookWindowsHookEx.
    // Three WH_KEYBOARD_LL hooks can be active simultaneously (one per hook procedure).
    static constexpr uintptr_t HOOK_HANDLE_1 = 0x18001C000;  // DAT_18001C000 -- WH_KEYBOARD_LL (proc 0x1800013A0 or 0x1800018E0 or 0x1800016F0 or 0x1800014A0 or 0x1800017C0)
    static constexpr uintptr_t HOOK_HANDLE_2 = 0x18001C010;  // DAT_18001C010 -- WH_MOUSE_LL (proc LAB_180001B80)
    static constexpr uintptr_t HOOK_HANDLE_3 = 0x18001C008;  // DAT_18001C008 -- WH_GETMESSAGE (proc LAB_1800019E0 or FUN_180001AD0)

    //    Hook installation / removal (by CLDBDoSomeStuff family)   
    // CLDBDoSomeStuff (0x180001110):
    //   - On input & 0x40 == 0: unhook all 3 hooks, send synthetic key input via SendInput.
    //   - On input & 0x40 != 0: install hooks based on flag bits (bit 0xF, 9, 8, 0xE, 0x2000, 0x80).
    //     Installs WH_KEYBOARD_LL (id=0xD) and WH_MOUSE_LL (id=10) always.
    //     Installs WH_GETMESSAGE (id=7) when bit 0x2000 or bit 0x80 set.
    // CLDBDoSomeOtherStuff (0x180001000): install WH_KEYBOARD_LL only, bump flag by 0x800.
    // CLDBDoSomeOtherStuffs (0x1800010E0): query active hooks, return bitmask (0x400/0x1000/0x800).
    // CLDBDoYetMoreStuff (0x180001330): install WH_GETMESSAGE only.
    // WH_MSGFILTER hook procedure (LAB_180001B80):
    //   Blocks WM_SYSCOMMAND (0x204..0x20D range, bits in 0x387) and WM_CONTEXTMENU (0xA3..0xAE range, bits in 0x70F).
    //   Blocks WM_SYSKEYDOWN (0x201) if Alt (0x11) is held.
    //   Calls CallNextHookEx(DAT_18001C008, ...) for allowed messages.
    //
    // WH_GETMESSAGE hook procedure (LAB_1800019E0):
    //   Already seen as part of FUN_180001AD0 disassembly (the function at 1AD0 handles the logic).
    //   Actually the label at 19E0 is the start of the getmessage hook proc body.
    //   Blocks specific window messages, returns 1 to eat them.

    static constexpr uintptr_t HOOK_PROC_KBD_13A0 = 0x1800013A0;
    static constexpr uintptr_t HOOK_PROC_KBD_14A0 = 0x1800014A0;
    static constexpr uintptr_t HOOK_PROC_KBD_16F0 = 0x1800016F0;
    static constexpr uintptr_t HOOK_PROC_KBD_17C0 = 0x1800017C0;
    static constexpr uintptr_t HOOK_PROC_KBD_18E0 = 0x1800018E0;
    static constexpr uintptr_t HOOK_PROC_MSGFILTER = 0x180001B80;  // label, not a named function
    static constexpr uintptr_t HOOK_PROC_GETMSG    = 0x1800019E0;  // label, not a named function
    static constexpr uintptr_t HOOK_PROC_WH_GETMESSAGE_AD = 0x180001AD0;  // alternative WH_GETMESSAGE proc

    //    Hook configuration / window handle   
    static constexpr uintptr_t HOOK_WINDOW_HANDLE = 0x180019AD0;  // DAT_180019AD0 -- window handle passed to SetWindowsHookExA (4th param)
    static constexpr uintptr_t HOOK_LAST_SCANCODE = 0x180019AD8;  // DAT_180019AD8 -- last pressed scancode (0x5B/0x5C/0)
    static constexpr uintptr_t HOOK_FLAG_ADC = 0x180019ADC;       // DAT_180019ADC -- flag byte (reset in FUN_1800014A0)
    static constexpr uintptr_t HOOK_FLAG_ADE = 0x180019AE0;       // DAT_180019AE0 -- flag byte (reset in FUN_1800014A0)
    static constexpr uintptr_t HOOK_FLAG_AE4 = 0x180019AE4;       // DAT_180019AE4 -- flag byte (set/used in FUN_1800014A0)
    static constexpr uintptr_t HOOK_REFCOUNT = 0x180019AE8;       // DAT_180019AE8 -- reference count for CRT init/shutdown
    static constexpr uintptr_t HOOK_SLIST = 0x180019AF0;         // DAT_180019AF0 -- singly-linked list head (initialized by FUN_180001FC4)

    //    Anti-debug / anti-tamper state   
    static constexpr uintptr_t ANTI_DEBUG_INIT_DONE = 0x18000F330;  // DAT_18000F330 -- flag checked in FUN_180001DAC
    static constexpr uintptr_t ANTI_DEBUG_GUARD_DISPATCH = 0x18000F298;  // PTR__guard_dispatch_icall -- CFG dispatch
    static constexpr uintptr_t ANTI_DEBUG_EXCEPTION_FILTER = 0x18001C000;  // set by __scrt_dllmain_exception_filter

    
    static constexpr uintptr_t ANTI_DEBUG_RANDOM_CANARY  = 0x180019040;  // DAT_180019040 -- 48-bit random value
    static constexpr uintptr_t ANTI_DEBUG_RANDOM_CANARY2 = 0x180019080; // DAT_180019080 -- ~canary (complement)

 

    //    Other notable functions   
    static constexpr uintptr_t FUN_180001F14 = 0x180001F14;  // random canary generator (GetSystemTimeAsFileTime + PID/TID + QPC)
    static constexpr uintptr_t FUN_180001FC4 = 0x180001FC4;  // InitializeSListHead(&DAT_180019AF0)
    static constexpr uintptr_t FUN_180001FD4 = 0x180001FD4;  // FUN_1800029E0(&DAT_180019AF0) -- flush slist
    static constexpr uintptr_t FUN_180001FF0 = 0x180001FF0;  // sets DAT_180019B00 |= 0x24, DAT_180019B08 |= 2
    static constexpr uintptr_t FUN_18000207C = 0x18000207C;  // returns FUN_1800021B4(0) != 0
    static constexpr uintptr_t FUN_1800020BC = 0x1800020BC;  // DLL_PROCESS_DETACH: calls FUN_180005D58 + FUN_180002A48
    static constexpr uintptr_t FUN_180002178 = 0x180002178;  // called from FUN_180001C10, returns char
    static constexpr uintptr_t FUN_180002488 = 0x180002488;  // checks array at 0x180017230 for nonzero entries, calls guard_icall
    static constexpr uintptr_t FUN_1800024C4 = 0x1800024C4;  // checks array at 0x180017240 for nonzero entries, calls guard_icall

    //    Guard/callback array base (used by FUN_180002488/24C4)   
    static constexpr uintptr_t GUARD_ARRAY_1 = 0x180017230;  // array checked by FUN_180002488
    static constexpr uintptr_t GUARD_ARRAY_2 = 0x180017240;  // array checked by FUN_1800024C4

    //    SLIST header   
    static constexpr uintptr_t SLIST_HEADER = 0x180019AF0;  // initialized by FUN_180001FC4, flushed by FUN_180001FD4

    //    Flag bytes at 0x180019B00/19B08 (set by FUN_180001FF0)   
    static constexpr uintptr_t FLAG_B00 = 0x180019B00;  // set to 0x24 (36) by FUN_180001FF0
    static constexpr uintptr_t FLAG_B08 = 0x180019B08;  // set to 2 by FUN_180001FF0
};

