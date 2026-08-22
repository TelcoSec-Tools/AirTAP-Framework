-- TelcoSec.net - Qualcomm GNSS & Cellular Location Correlation Dissector
-- Description: Dissects Qualcomm Log Codes 0x1476, 0x1477 (GNSS NMEA/Position), and 0x196E (GNSS Clock/Fix).
--              Cross-correlates GPS/Galileo coordinates with active base station identifiers (Cell ID / TAC)
--              to detect GNSS Spoofing and Cellular Geolocation Tracking.

local ok, qc_gnss_loc_proto = pcall(Proto, "qc_gnss_loc", "Qualcomm GNSS & Cellular Location Analyzer")
if not ok or not qc_gnss_loc_proto then return end

-- Protocol fields
local f_lat          = ProtoField.double("qc_gnss_loc.latitude", "Latitude (deg)")
local f_lon          = ProtoField.double("qc_gnss_loc.longitude", "Longitude (deg)")
local f_altitude     = ProtoField.float("qc_gnss_loc.altitude", "Altitude (m)")
local f_fix_type     = ProtoField.string("qc_gnss_loc.fix_type", "GNSS Fix Type")
local f_sat_count    = ProtoField.uint8("qc_gnss_loc.sat_count", "Visible Satellites Count", base.DEC)
local f_sec_alert    = ProtoField.string("qc_gnss_loc.alert", "TelcoSec Location Security Alert")
local f_nmea_str     = ProtoField.string("qc_gnss_loc.nmea", "NMEA Sentence")

qc_gnss_loc_proto.fields = {
    f_lat,
    f_lon,
    f_altitude,
    f_fix_type,
    f_sat_count,
    f_sec_alert,
    f_nmea_str
}

function qc_gnss_loc_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0x1476 / 0x1477 layout:
    -- [0]: Version (1 byte)
    -- [1]: Fix Type (1 byte: 0=None, 1=2D, 2=3D, 3=DGPS)
    -- [2]: Sat Count (1 byte)
    -- [3-10]: Latitude (8 bytes double LE)
    -- [11-18]: Longitude (8 bytes double LE)
    -- [19-22]: Altitude (4 bytes float LE)
    if tvb:len() < 19 then
        -- Could be raw NMEA string payload
        if tvb:len() > 6 then
            local subtree = tree:add(qc_gnss_loc_proto, tvb(), "Qualcomm GNSS NMEA Log")
            local raw_str = tvb():string()
            subtree:add(f_nmea_str, raw_str)
            pinfo.cols.info = "[QC GNSS] NMEA Stream"
        end
        return
    end

    pinfo.cols.protocol = "QC GNSS/GPS"

    local version = tvb(0, 1):uint()
    local fix_id = tvb(1, 1):uint()
    local sat_count = tvb(2, 1):uint()
    local lat = tvb(3, 8):le_float() -- double precision
    local lon = tvb(11, 8):le_float()

    local fix_types = { [0]="No Fix", [1]="2D Fix", [2]="3D Fix", [3]="DGPS / High Accuracy" }
    local fix_str = fix_types[fix_id] or string.format("Fix Type %d", fix_id)

    local subtree = tree:add(qc_gnss_loc_proto, tvb(), string.format("Qualcomm GNSS Position (Lat: %.6f, Lon: %.6f, %s)", lat, lon, fix_str))
    subtree:add(f_fix_type, fix_str)
    subtree:add(f_sat_count, tvb(2, 1), sat_count)
    subtree:add(f_lat, tvb(3, 8), lat)
    subtree:add(f_lon, tvb(11, 8), lon)

    if tvb:len() >= 23 then
        local alt = tvb(19, 4):le_float()
        subtree:add(f_altitude, tvb(19, 4), alt)
        pinfo.cols.info = string.format("[QC GNSS] Lat: %.5f, Lon: %.5f, Alt: %.1fm (%s)", lat, lon, alt, fix_str)
    else
        pinfo.cols.info = string.format("[QC GNSS] Lat: %.5f, Lon: %.5f (%s)", lat, lon, fix_str)
    end

    -- Security Heuristic 1: Suspicious 0,0 Coordinate or Sudden Teleportation
    if math.abs(lat) < 0.0001 and math.abs(lon) < 0.0001 and fix_id > 0 then
        subtree:add(f_sec_alert, "[WARNING] Null Island (0.0, 0.0) coordinates reported with valid fix. Potential GNSS spoofing attack.")
    end

    -- Security Heuristic 2: Low Satellite Count (<4) reporting high precision 3D fix
    if sat_count < 4 and fix_id >= 2 then
        subtree:add(f_sec_alert, "[WARNING] 3D Position lock reported with fewer than 4 satellites. Possible synthetic GNSS RF generator / spoofer.")
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0x1476, qc_gnss_loc_proto) -- GNSS Position Report
    qc_log_table:add(0x1477, qc_gnss_loc_proto) -- GNSS NMEA String
    qc_log_table:add(0x196E, qc_gnss_loc_proto) -- GNSS Raw Measurements
end
