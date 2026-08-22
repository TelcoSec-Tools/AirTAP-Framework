-- TelcoSec.net - Samsung Shannon Baseband Crash & Panic Triage Dissector
-- Description: Dissects Shannon DM Group 0x10 (System Core & Crash Dump).
--              Extracts ARM Cortex-R7 baseband registers (PC, LR, SP, CPSR), assertion strings,
--              and memory fault locations for over-the-air baseband fuzzing and exploit triage.

local ok, shannon_crash_proto = pcall(Proto, "shannon_crash", "Samsung Shannon Baseband Crash & Panic Triage")
if not ok or not shannon_crash_proto then return end

-- Protocol fields
local f_panic_type   = ProtoField.string("shannon_crash.type", "Crash / Panic Type")
local f_core_id      = ProtoField.uint8("shannon_crash.core", "ARM Core ID", base.DEC)
local f_pc           = ProtoField.uint32("shannon_crash.pc", "Program Counter (R15/PC)", base.HEX)
local f_lr           = ProtoField.uint32("shannon_crash.lr", "Link Register (R14/LR)", base.HEX)
local f_sp           = ProtoField.uint32("shannon_crash.sp", "Stack Pointer (R13/SP)", base.HEX)
local f_cpsr         = ProtoField.uint32("shannon_crash.cpsr", "CPSR", base.HEX)
local f_reason       = ProtoField.string("shannon_crash.reason", "Assertion / Fault String")
local f_sec_alert    = ProtoField.string("shannon_crash.alert", "TelcoSec Baseband Fuzzing Alert")
local f_dump         = ProtoField.bytes("shannon_crash.dump", "Raw Register/Stack Dump")

shannon_crash_proto.fields = {
    f_panic_type,
    f_core_id,
    f_pc,
    f_lr,
    f_sp,
    f_cpsr,
    f_reason,
    f_sec_alert,
    f_dump
}

function shannon_crash_proto.dissector(tvb, pinfo, tree)
    -- Shannon Crash DM Payload:
    -- [0]: Panic Type (0=Assert, 1=Data Abort, 2=Prefetch Abort, 3=Undef Instruction)
    -- [1]: Core ID (0=Cortex-R7 Core 0, 1=Cortex-R7 Core 1)
    -- [2-5]: PC (4 bytes LE)
    -- [6-9]: LR (4 bytes LE)
    -- [10-13]: SP (4 bytes LE)
    -- [14-17]: CPSR (4 bytes LE)
    -- [18..N]: ASCII Assertion string / Stack dump
    if tvb:len() < 18 then return end

    pinfo.cols.protocol = "Shannon Crash"

    local panic_id = tvb(0, 1):uint()
    local core_id = tvb(1, 1):uint()
    local pc = tvb(2, 4):le_uint()
    local lr = tvb(6, 4):le_uint()
    local sp = tvb(10, 4):le_uint()
    local cpsr = tvb(14, 4):le_uint()

    local panic_names = {
        [0] = "Baseband Assertion Failure",
        [1] = "Data Abort (Memory Fault / Crash)",
        [2] = "Prefetch Abort (Execution Violation)",
        [3] = "Undefined Instruction (Corrupted Code)"
    }
    local panic_str = panic_names[panic_id] or string.format("Panic (0x%02X)", panic_id)

    local subtree = tree:add(shannon_crash_proto, tvb(), string.format("Samsung Shannon %s (PC: 0x%08X)", panic_str, pc))
    subtree:add(f_panic_type, panic_str)
    subtree:add(f_core_id, tvb(1, 1), core_id)
    subtree:add(f_pc, tvb(2, 4), pc)
    subtree:add(f_lr, tvb(6, 4), lr)
    subtree:add(f_sp, tvb(10, 4), sp)
    subtree:add(f_cpsr, tvb(14, 4), cpsr)

    local info_str = string.format("[SHANNON BASEBAND CRASH] %s | PC: 0x%08X, LR: 0x%08X", panic_str, pc, lr)

    local offset = 18
    local msg_len = math.min(tvb:len() - offset, 128)
    if msg_len > 0 then
        local raw_str = tvb(offset, msg_len):string()
        local clean_str = string.gsub(raw_str, "[^%w%s%p]", ".")
        subtree:add(f_reason, clean_str)
        info_str = string.format("[SHANNON CRASH] PC: 0x%08X | %s", pc, clean_str)
    end

    pinfo.cols.info = info_str
    subtree:add(f_sec_alert, "[CRITICAL] Baseband Crash / Memory Fault in Shannon Modem! Potential Remote Code Execution (RCE) via OTA signaling fuzzing.")
    pinfo.cols.info:append(" [TELCOSEC: BASEBAND PANIC]")

    if tvb:len() > offset then
        subtree:add(f_dump, tvb(offset, tvb:len() - offset))
    end
end

-- Register to Shannon DM Group table
local dm_table = DissectorTable.get("shannon_dm.group")
if dm_table then
    dm_table:add(0x10, shannon_crash_proto) -- Shannon System Core Crash Group
end
