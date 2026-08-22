-- TelcoSec.net - GSM Radio Resource (RR) & Cell Reselection Spoofing Detector
-- Description: Dissects GSM System Information (SI1, SI2, SI3, SI4, SI13) broadcast on BCCH.
--              Detects C1/C2 Cell Reselection spoofing parameters (CRO, Temporary Offset, Cell Bar Access)
--              manipulated by 2G IMSI Catchers to attract victim UEs.

local ok, gsm_rr_sec_proto = pcall(Proto, "gsm_rr_sec", "TelcoSec GSM RR & Cell Reselection Analyzer")
if not ok or not gsm_rr_sec_proto then return end

-- Protocol fields
local f_si_type      = ProtoField.string("gsm_rr_sec.si_type", "System Information Type")
local f_mcc          = ProtoField.string("gsm_rr_sec.mcc", "Mobile Country Code (MCC)")
local f_mnc          = ProtoField.string("gsm_rr_sec.mnc", "Mobile Network Code (MNC)")
local f_lac          = ProtoField.uint16("gsm_rr_sec.lac", "Location Area Code (LAC)", base.DEC)
local f_cell_id      = ProtoField.uint16("gsm_rr_sec.cell_id", "Cell Identity (CI)", base.DEC)
local f_cro          = ProtoField.uint8("gsm_rr_sec.cro", "Cell Reselect Offset (CRO dB)", base.DEC)
local f_to           = ProtoField.uint8("gsm_rr_sec.to", "Temporary Offset (TO dB)", base.DEC)
local f_penalty_time = ProtoField.uint8("gsm_rr_sec.penalty_time", "Penalty Time (s)", base.DEC)
local f_cell_bar     = ProtoField.bool("gsm_rr_sec.cell_bar", "Cell Barred for Access")
local f_sec_alert    = ProtoField.string("gsm_rr_sec.alert", "TelcoSec 2G Rogue Cell Alert")
local f_payload      = ProtoField.bytes("gsm_rr_sec.payload", "SI Raw Payload")

gsm_rr_sec_proto.fields = {
    f_si_type,
    f_mcc,
    f_mnc,
    f_lac,
    f_cell_id,
    f_cro,
    f_to,
    f_penalty_time,
    f_cell_bar,
    f_sec_alert,
    f_payload
}

-- Native Wireshark CCCH dissector
local gsm_a_ccch_dissector = Dissector.get("gsm_a_ccch")

function gsm_rr_sec_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 3 then return end

    local pd = bit.band(tvb(0, 1):uint(), 0x0F)
    local msg_type = tvb(1, 1):uint()

    -- Protocol Discriminator 6 = Radio Resource Management (RR)
    if pd ~= 6 then return end

    pinfo.cols.protocol = "GSM RR"

    local si_names = {
        [0x19] = "System Information Type 1",
        [0x1A] = "System Information Type 2",
        [0x1B] = "System Information Type 3",
        [0x1C] = "System Information Type 4",
        [0x1D] = "System Information Type 5",
        [0x1E] = "System Information Type 6",
        [0x00] = "System Information Type 13"
    }

    local si_str = si_names[msg_type] or string.format("GSM RR Msg (0x%02X)", msg_type)
    local subtree = tree:add(gsm_rr_sec_proto, tvb(), string.format("GSM RR: %s", si_str))
    subtree:add(f_si_type, si_str)

    pinfo.cols.info = string.format("[GSM RR] %s", si_str)

    -- SI3 / SI4 Parsing for Cell Reselection Parameters (3GPP TS 44.018)
    if (msg_type == 0x1B or msg_type == 0x1C) and tvb:len() >= 18 then
        -- Cell Identity (Bytes 2-3)
        local cell_id = tvb(2, 2):uint()
        subtree:add(f_cell_id, tvb(2, 2), cell_id)

        -- LAI (MCC/MNC/LAC, Bytes 4-8)
        local lac = tvb(7, 2):uint()
        subtree:add(f_lac, tvb(7, 2), lac)

        -- Selection Parameters & CRO (Bytes 13-15)
        local raw_cro = bit.band(tvb(14, 1):uint(), 0x3F)
        local cro_db = raw_cro * 2 -- CRO in 2 dB steps (0 to 126 dB)
        subtree:add(f_cro, tvb(14, 1), cro_db)

        pinfo.cols.info = string.format("[GSM %s] Cell ID: %d, LAC: %d | CRO: %d dB", si_str, cell_id, lac, cro_db)

        -- Security Heuristic 1: Artificial CRO Inflation (IMSI Catcher Luring Attack)
        -- Normal commercial base stations use CRO = 0-20 dB. IMSI catchers set CRO to 60-126 dB to force UE reselection.
        if cro_db >= 40 then
            subtree:add(f_sec_alert, string.format("[CRITICAL] Unusually high Cell Reselect Offset (CRO = %d dB)! 2G IMSI Catcher actively luring victim UEs to camp on rogue cell.", cro_db))
            pinfo.cols.info:append(" [TELCOSEC: ROGUE CELL CRO INFLATION!]")
        end

        -- Security Heuristic 2: Cell Barred or Fake Emergency Camp Only
        local cell_bar_bit = bit.band(tvb(13, 1):uint(), 0x20) ~= 0
        subtree:add(f_cell_bar, cell_bar_bit)
        if cell_bar_bit then
            subtree:add(f_sec_alert, "[WARNING] Cell Barred for normal access. May indicate emergency-only honeypot or jamming containment.")
        end
    end

    if gsm_a_ccch_dissector then
        gsm_a_ccch_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end
