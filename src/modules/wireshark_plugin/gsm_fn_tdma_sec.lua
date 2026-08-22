-- TelcoSec.net - GSM TDMA 51-Multiframe Hyperframe (FN) & Burst Collision Analyzer
-- Target Standard: 3GPP TS 45.002 (Physical layer / Multiplexing and multiple access on radio path)
-- Description: Dissects 32-bit GSM Frame Numbers (FN), calculates TDMA structural counters
--              (T1, T2, T3, T3'), maps logical timeslots (TS0-TS7) to 51-multiframe control
--              and 26-multiframe traffic frames, and detects TDMA clock drift, desynchronization,
--              and burst insertion attacks from rogue SDR transmitters.

local ok, gsm_fn_proto = pcall(Proto, "gsm_fn_sec", "TelcoSec GSM TDMA Frame Number & Physical Sync Analyzer")
if not ok or not gsm_fn_proto then return end

-- Protocol fields
local f_fn          = ProtoField.uint32("gsm_fn_sec.fn", "TDMA Frame Number (FN)", base.DEC)
local f_fn_mod_hyper= ProtoField.uint32("gsm_fn_sec.fn_hyper", "Hyperframe Index (FN / 2715648)", base.DEC)
local f_t1          = ProtoField.uint16("gsm_fn_sec.t1", "T1 (Superframe index = FN div 1326)", base.DEC)
local f_t2          = ProtoField.uint8("gsm_fn_sec.t2", "T2 (Traffic sub-index = FN mod 26)", base.DEC)
local f_t3          = ProtoField.uint8("gsm_fn_sec.t3", "T3 (Control sub-index = FN mod 51)", base.DEC)
local f_t3_prime    = ProtoField.uint8("gsm_fn_sec.t3_prime", "T3' (Signaling block = (T3-1) div 10)", base.DEC)
local f_tc          = ProtoField.uint8("gsm_fn_sec.tc", "TC (BCCH 8-multiframe cycle = (FN div 51) mod 8)", base.DEC)
local f_timeslot    = ProtoField.uint8("gsm_fn_sec.timeslot", "Timeslot Number (TN)", base.DEC)
local f_channel_map = ProtoField.string("gsm_fn_sec.channel_map", "51-Multiframe Mapped Channel")
local f_delta_fn    = ProtoField.int32("gsm_fn_sec.delta_fn", "FN Delta to Previous Packet", base.DEC)
local f_sec_alert   = ProtoField.string("gsm_fn_sec.alert", "TelcoSec TDMA Sync Alert")

gsm_fn_proto.fields = {
    f_fn,
    f_fn_mod_hyper,
    f_t1,
    f_t2,
    f_t3,
    f_t3_prime,
    f_tc,
    f_timeslot,
    f_channel_map,
    f_delta_fn,
    f_sec_alert
}

-- 51-Multiframe Control Channel Mapping (TS 45.002 Section 6.3 - Combined CCCH+SDCCH/4 or Non-combined CCCH)
local function get_51_mf_mapping(t3, timeslot)
    if timeslot == 0 then
        -- TS0: Broadcast & Common Control
        if t3 == 0 then return "FSB (Frequency Correction Burst / FCCH)"
        elseif (t3 >= 1 and t3 <= 4) then return "SCH (Synchronization Burst)"
        elseif (t3 >= 5 and t3 <= 8) then return "BCCH Block 0"
        elseif (t3 >= 9 and t3 <= 12) then return "BCCH Block 1"
        elseif (t3 >= 13 and t3 <= 16) then return "CCCH (PCH/AGCH Block 0)"
        elseif (t3 >= 17 and t3 <= 20) then return "CCCH (PCH/AGCH Block 1)"
        elseif (t3 >= 21 and t3 <= 24) then return "CCCH (PCH/AGCH Block 2)"
        elseif (t3 >= 25 and t3 <= 28) then return "CCCH (PCH/AGCH Block 3)"
        elseif (t3 >= 29 and t3 <= 32) then return "CCCH (PCH/AGCH Block 4)"
        elseif (t3 >= 33 and t3 <= 36) then return "CCCH (PCH/AGCH Block 5)"
        elseif (t3 >= 37 and t3 <= 40) then return "CCCH (PCH/AGCH Block 6)"
        elseif (t3 >= 41 and t3 <= 44) then return "CCCH (PCH/AGCH Block 7)"
        elseif (t3 >= 45 and t3 <= 48) then return "CCCH (PCH/AGCH Block 8)"
        elseif t3 >= 49 then return "IDLE Frame"
        else return "Common Control Block"
        end
    elseif timeslot == 1 then
        -- TS1: SDCCH/8 Dedicated Signaling
        local subslot = math.floor(t3 / 4)
        if t3 >= 0 and t3 <= 31 then
            return string.format("SDCCH/8 Subslot %d", subslot)
        elseif t3 >= 32 and t3 <= 47 then
            return string.format("SACCH/8 Subslot %d", subslot - 8)
        else
            return "IDLE Frame"
        end
    else
        -- Traffic TS2..TS7 (26-multiframe TCH)
        return string.format("TCH / Data Slot (TS%d)", timeslot)
    end
end

-- State tracking for FN jump and clock drift detection
local last_fn_per_stream = {}

function gsm_fn_proto.dissector(tvb, pinfo, tree)
    -- Requires at least 5 bytes: [0..3]: FN (32-bit BE or LE), [4]: Timeslot (1 byte)
    if tvb:len() < 5 then return end

    local fn = tvb(0, 4):uint()
    local timeslot = tvb(4, 1):uint()

    -- 3GPP TS 45.002 Equation Formulas:
    -- Hyperframe = 2715648 frames (~3.48 hours)
    -- Superframe = 1326 frames
    local t1 = math.floor((fn % 2715648) / 1326)
    local t2 = fn % 26
    local t3 = fn % 51
    local t3_prime = (t3 >= 1) and math.floor((t3 - 1) / 10) or 0
    local tc = math.floor(fn / 51) % 8
    local chan_map = get_51_mf_mapping(t3, timeslot)

    local subtree = tree:add(gsm_fn_proto, tvb(0, 5), string.format("GSM TDMA Physical Sync: FN %d (T1:%d, T2:%d, T3:%d, TS:%d)", fn, t1, t2, t3, timeslot))
    subtree:add(f_fn, tvb(0, 4), fn)
    subtree:add(f_fn_mod_hyper, math.floor(fn / 2715648))
    subtree:add(f_t1, t1)
    subtree:add(f_t2, t2)
    subtree:add(f_t3, t3)
    subtree:add(f_t3_prime, t3_prime)
    subtree:add(f_tc, tc)
    subtree:add(f_timeslot, tvb(4, 1), timeslot)
    subtree:add(f_channel_map, chan_map)

    -- Detect TDMA Frame Number Desynchronization / Clock Drift
    local stream_key = tostring(pinfo.src) .. ":" .. tostring(timeslot)
    local prev_fn = last_fn_per_stream[stream_key]
    if prev_fn ~= nil then
        local delta_fn = fn - prev_fn
        subtree:add(f_delta_fn, delta_fn)

        -- Security Heuristic 1: Negative Jump or Sudden Gap in Frame Number
        if delta_fn < 0 then
            subtree:add(f_sec_alert, string.format("[CRITICAL] TDMA Frame Counter rolled backward (Delta: %d)! Suspected SDR transmitter reset / rogue BTS burst insertion.", delta_fn))
            pinfo.cols.info:append(" [TELCOSEC: TDMA CLOCK ROLLBACK DETECTED]")
        elseif delta_fn > 5000 and delta_fn < 2000000 then
            subtree:add(f_sec_alert, string.format("[WARNING] Massive Frame Number gap (+%d frames / ~%.2f sec). Possible RF fading or transmitter swap.", delta_fn, delta_fn * 0.004615))
        end
    end
    last_fn_per_stream[stream_key] = fn
end

-- Export helper for parent dissectors
_G.gsm_fn_dissect = function(tvb_fn, pinfo, tree)
    gsm_fn_proto.dissector(tvb_fn, pinfo, tree)
end
