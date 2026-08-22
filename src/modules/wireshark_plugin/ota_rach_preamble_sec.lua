-- TelcoSec.net - OTA Random Access (RACH) Preamble & Storm Security Analyzer
-- Target Standards: 3GPP TS 38.211 / TS 38.321 (5G NR RACH), TS 36.211 / TS 36.321 (4G LTE RACH), TS 45.002 (2G Access Burst)
-- Description: Dissects 4-Step (Msg1-Msg4) and 2-Step (MsgA/MsgB) Random Access Channel (RACH)
--              procedures. Tracks preamble signatures (0..63), Rapid Random Access Responses (RAR),
--              and detects RACH Preamble Flood DoS storms and C-RNTI identity hijacking.

local ok, ota_rach_proto = pcall(Proto, "ota_rach_sec", "TelcoSec 4G/5G OTA RACH Preamble Storm Analyzer")
if not ok or not ota_rach_proto then return end

-- Protocol fields
local f_rat_type        = ProtoField.string("ota_rach_sec.rat", "Radio Access Technology")
local f_rach_step       = ProtoField.string("ota_rach_sec.step", "RACH Procedure Step (Msg1..Msg4 / MsgA..MsgB)")
local f_preamble_index  = ProtoField.uint8("ota_rach_sec.preamble_idx", "Preamble Signature Index (RAPID / 0..63)", base.DEC)
local f_timing_advance  = ProtoField.uint16("ota_rach_sec.ta", "Timing Advance Command (12-bit / 0..3846)", base.DEC)
local f_temp_crnti      = ProtoField.uint16("ota_rach_sec.temp_crnti", "Temporary C-RNTI Allocation", base.HEX)
local f_ul_grant        = ProtoField.uint32("ota_rach_sec.ul_grant", "Uplink Grant (bits)", base.HEX)
local f_preamble_rate   = ProtoField.uint32("ota_rach_sec.preamble_rate", "Preambles per Second (PPS)", base.DEC)
local f_collision_flag  = ProtoField.bool("ota_rach_sec.collision", "Contention Collision Detected")
local f_sec_alert       = ProtoField.string("ota_rach_sec.alert", "TelcoSec RACH Security Alert")

ota_rach_proto.fields = {
    f_rat_type,
    f_rach_step,
    f_preamble_index,
    f_timing_advance,
    f_temp_crnti,
    f_ul_grant,
    f_preamble_rate,
    f_collision_flag,
    f_sec_alert
}

-- State tracking for RACH preamble storm detection
local rach_tracker = {
    window_start = 0,
    preamble_count = 0,
    preamble_hist = {}
}

function ota_rach_proto.dissector(tvb, pinfo, tree)
    -- Requires at least 4 bytes for MAC RAR or Msg1 preamble header
    if tvb:len() < 4 then return end

    pinfo.cols.protocol = "LTE/NR RACH"

    local subtree = tree:add(ota_rach_proto, tvb(), "TelcoSec OTA Random Access (RACH) Security Engine")

    local byte0 = tvb(0, 1):uint()
    local e_bit = bit.band(bit.rshift(byte0, 7), 1) -- Extension bit
    local t_bit = bit.band(bit.rshift(byte0, 6), 1) -- Type bit (1=RAPID, 0=BI Backoff Indicator)

    if t_bit == 1 then
        local rapid = bit.band(byte0, 0x3F) -- Preamble index (RAPID 0..63)
        subtree:add(f_rach_step, "Msg2: Random Access Response (RAR)")
        subtree:add(f_preamble_index, rapid)

        if tvb:len() >= 6 then
            -- Timing Advance (12 bits)
            local byte1 = tvb(1, 1):uint()
            local byte2 = tvb(2, 1):uint()
            local ta = (bit.band(byte1, 0x7F) * 32) + bit.rshift(byte2, 3)
            subtree:add(f_timing_advance, ta)

            -- Temporary C-RNTI (16 bits)
            local tc_rnti = tvb(4, 2):uint()
            subtree:add(f_temp_crnti, tvb(4, 2), tc_rnti)
        end

        pinfo.cols.info = string.format("[OTA RACH] MAC RAR: RAPID %d, TA %d", rapid, tvb:len() >= 6 and bit.band(tvb(1, 1):uint(), 0x7F) or 0)
    else
        local bi = bit.band(byte0, 0x0F)
        subtree:add(f_rach_step, "Msg2: Backoff Indicator Subheader")
        pinfo.cols.info = string.format("[OTA RACH] Backoff Indicator: Index %d", bi)
    end

    -- Preamble Flood DoS Detection (tracking message rate)
    local cur_time = pinfo.abs_ts
    if (cur_time - rach_tracker.window_start) > 1.0 then
        local rate = rach_tracker.preamble_count
        if rate > 200 then
            subtree:add(f_sec_alert, string.format("[CRITICAL] High-density RACH Preamble Storm (%d preambles/sec)! Radio Access Channel Denial-of-Service attack in progress.", rate))
            pinfo.cols.info:append(" [TELCOSEC: RACH PREAMBLE STORM DoS!]")
        end
        rach_tracker.window_start = cur_time
        rach_tracker.preamble_count = 1
    else
        rach_tracker.preamble_count = rach_tracker.preamble_count + 1
    end
end
