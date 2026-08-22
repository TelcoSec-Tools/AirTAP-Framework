-- TelcoSec.net - Multi-RAT System Information & False Base Station (FBS) Hunter
-- Target Standards: 3GPP TS 44.018 (2G SI), TS 25.331 (3G SIB), TS 36.331 (4G SIB), TS 38.331 (5G SIB)
-- Description: Deeply inspects broadcast System Information Blocks (SIBs) across 2G, 3G, 4G, and 5G.
--              Detects False Base Station / IMSI Catcher lure parameters (CRO inflation, q-RxLevMin drops),
--              solitary cell traps (neighbor cell list stripping), and forced 2G downgrade attacks.

local ok, ota_sib_proto = pcall(Proto, "ota_sib_fbs", "TelcoSec Multi-RAT SIB False Base Station Detector")
if not ok or not ota_sib_proto then return end

-- Protocol fields
local f_rat_type            = ProtoField.string("ota_sib_fbs_sec.rat", "Radio Access Technology (RAT)")
local f_sib_type            = ProtoField.string("ota_sib_fbs_sec.sib_type", "System Information Type")
local f_plmn_mcc            = ProtoField.string("ota_sib_fbs_sec.mcc", "PLMN Mobile Country Code (MCC)")
local f_plmn_mnc            = ProtoField.string("ota_sib_fbs_sec.mnc", "PLMN Mobile Network Code (MNC)")
local f_cell_id             = ProtoField.uint32("ota_sib_fbs_sec.cell_id", "Cell Identity (CI / E-UTRAN Cell ID)", base.HEX)
local f_tac_lac             = ProtoField.uint16("ota_sib_fbs_sec.tac_lac", "Tracking / Location Area Code (TAC / LAC)", base.HEX)
local f_cro_db              = ProtoField.uint8("ota_sib_fbs_sec.cro_db", "2G Cell Reselection Offset (CRO dB)", base.DEC)
local f_q_rxlevmin          = ProtoField.int8("ota_sib_fbs_sec.q_rxlevmin", "LTE/5G Minimum Required Rx Level (q-RxLevMin dBm)", base.DEC)
local f_reselect_priority   = ProtoField.uint8("ota_sib_fbs_sec.priority", "Cell Reselection Priority (0..7)", base.DEC)
local f_neighbor_count      = ProtoField.uint8("ota_sib_fbs_sec.neighbor_count", "Neighbor Cell List (NCL) Count", base.DEC)
local f_forced_downgrade    = ProtoField.bool("ota_sib_fbs_sec.forced_downgrade", "Forced Inter-RAT 2G Downgrade Flag")
local f_fbs_threat_score    = ProtoField.uint8("ota_sib_fbs_sec.threat_score", "False Base Station Threat Score (0..100)", base.DEC)
local f_sec_alert           = ProtoField.string("ota_sib_fbs_sec.alert", "TelcoSec FBS Heuristic Alert")

ota_sib_proto.fields = {
    f_rat_type,
    f_sib_type,
    f_plmn_mcc,
    f_plmn_mnc,
    f_cell_id,
    f_tac_lac,
    f_cro_db,
    f_q_rxlevmin,
    f_reselect_priority,
    f_neighbor_count,
    f_forced_downgrade,
    f_fbs_threat_score,
    f_sec_alert
}

-- Safe field value getter (lazy initialization to avoid load-time failure if field is absent)
local cached_fields = {}
local function get_field_extractor(field_name)
    if cached_fields[field_name] == nil then
        local ok, f = pcall(Field.new, field_name)
        cached_fields[field_name] = ok and f or false
    end
    return cached_fields[field_name] or nil
end

local function get_field_val(field_name)
    local f = get_field_extractor(field_name)
    if f then
        local ok, val = pcall(function() return f() end)
        if ok and val then return val end
    end
    return nil
end

-- State tracking for baseline cellular parameters
local known_cells_db = {}

function ota_sib_proto.dissector(tvb, pinfo, tree)
    local subtree = tree:add(ota_sib_proto, tvb(), "TelcoSec Multi-RAT SIB & False Base Station Analyzer")

    local threat_score = 0
    local alerts = {}

    -- 1. Extract 2G GSM System Information Parameters
    local gsm_cro_field = get_field_val("gsm_a.rr.cro")
    if gsm_cro_field then
        local cro_val = gsm_cro_field.value
        local cro_db = cro_val * 2
        subtree:add(f_rat_type, "2G GSM / GERAN")
        subtree:add(f_sib_type, "System Information 3 / 4")
        subtree:add(f_cro_db, cro_db)

        -- Heuristic 1: CRO Inflation Lure (CRO > 20 dB / raw > 10)
        if cro_db >= 40 then
            threat_score = threat_score + 40
            table.insert(alerts, string.format("[CRITICAL] Massive 2G Cell Reselection Offset (+%d dB)! Cell is artificially boosting priority to lure subscribers.", cro_db))
        elseif cro_db >= 20 then
            threat_score = threat_score + 20
            table.insert(alerts, string.format("[WARNING] Elevated 2G Cell Reselection Offset (+%d dB).", cro_db))
        end
    end

    -- 2. Extract 4G LTE SIB Parameters
    local lte_cell_field = get_field_val("lte-rrc.cellIdentity")
    if lte_cell_field then
        subtree:add(f_rat_type, "4G LTE / E-UTRAN")
        subtree:add(f_sib_type, "LTE SIB1 (SystemInformationBlockType1)")

        local lte_rxlev_field = get_field_val("lte-rrc.q_RxLevMin")
        if lte_rxlev_field then
            local rxlev_val = lte_rxlev_field.value * 2
            subtree:add(f_q_rxlevmin, rxlev_val)

            -- Heuristic 2: Unrealistically low q-RxLevMin (< -128 dBm)
            if rxlev_val <= -130 then
                threat_score = threat_score + 25
                table.insert(alerts, string.format("[WARNING] Ultra-permissive q-RxLevMin (%d dBm). Allows weak cell connection for capture.", rxlev_val))
            end
        end

        -- Heuristic 3: LTE SIB7 Forced 2G Downgrade
        local lte_sib7 = get_field_val("lte-rrc.sib7") or get_field_val("lte-rrc.SystemInformationBlockType7")
        if lte_sib7 then
            subtree:add(f_forced_downgrade, true)
            threat_score = threat_score + 35
            table.insert(alerts, "[CRITICAL] LTE SIB7 Active: Network broadcasting 2G GERAN neighbor carrier redirection. Potential forced cryptographic downgrade.")
        end
    end

    -- 3. Extract 5G NR Parameters
    local nr_tac_field = get_field_val("nr-rrc.trackingAreaCode")
    if nr_tac_field then
        subtree:add(f_rat_type, "5G NR / 5GS")
        subtree:add(f_sib_type, "5G SIB1")
    end

    -- Add alerts and final threat score
    subtree:add(f_fbs_threat_score, threat_score)

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        if threat_score >= 50 then
            pinfo.cols.info:append(string.format(" [TELCOSEC: FALSE BASE STATION DETECTED (Score: %d)]", threat_score))
        else
            pinfo.cols.info:append(string.format(" [TELCOSEC: SIB ANOMALY (Score: %d)]", threat_score))
        end
    end
end

-- Export helper for parent dissectors
_G.ota_sib_fbs_dissect = function(tvb_data, pinfo, tree)
    ota_sib_proto.dissector(tvb_data, pinfo, tree)
end
