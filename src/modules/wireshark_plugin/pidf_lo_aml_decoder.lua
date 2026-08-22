-- TelcoSec.net - Emergency Location Telemetry (PIDF-LO & AML) Full Dissector & Decoder
-- Target Standards:
--   RFC 4119 (A Presence-based GEOPRIV Location Object Format - PIDF-LO)
--   RFC 5139 (Revised Civic Location Format for GEOPRIV Location Objects)
--   RFC 5491 (GEOPRIV Presence Information Data Format Location Object (PIDF-LO) Usage Clarification)
--   ETSI TS 103 493 (Emergency Communications; Advanced Mobile Location (AML) for Emergency Calls)
--
-- Description: Fully decodes and parses emergency location telemetry containers:
--              1) RFC 4119/5139 PIDF-LO XML bodies with 2D/3D WGS84 coordinates & Civic Address tags.
--              2) ETSI TS 103 493 AML (Advanced Mobile Location) SMS and HTTPS location payloads.

local ok, loc_telemetry_proto = pcall(Proto, "emergency_loc", "Emergency Location Telemetry Decoder (PIDF-LO & AML)")
if not ok or not loc_telemetry_proto then return end

-- Protocol Fields
local f_loc_type        = ProtoField.string("emergency_loc.type", "Telemetry Format Type")
local f_entity          = ProtoField.string("emergency_loc.entity", "Target Entity / Presentity URI")
local f_method          = ProtoField.string("emergency_loc.method", "Location Method (GPS, Wi-Fi, Cell-ID)")
local f_lat             = ProtoField.string("emergency_loc.latitude", "WGS84 Latitude")
local f_lon             = ProtoField.string("emergency_loc.longitude", "WGS84 Longitude")
local f_altitude        = ProtoField.string("emergency_loc.altitude", "Altitude (meters)")
local f_uncertainty     = ProtoField.string("emergency_loc.radius", "Uncertainty Radius (meters)")
local f_confidence      = ProtoField.string("emergency_loc.confidence", "Position Confidence Level")
local f_timestamp       = ProtoField.string("emergency_loc.timestamp", "Fix Timestamp")
local f_civic_country   = ProtoField.string("emergency_loc.civic.country", "Country Code (ISO 3166-1)")
local f_civic_a1        = ProtoField.string("emergency_loc.civic.a1", "A1: State / Region / Province")
local f_civic_a2        = ProtoField.string("emergency_loc.civic.a2", "A2: County / District")
local f_civic_a3        = ProtoField.string("emergency_loc.civic.a3", "A3: City / Municipality")
local f_civic_a6        = ProtoField.string("emergency_loc.civic.a6", "A6: Street / Road Name")
local f_civic_hno       = ProtoField.string("emergency_loc.civic.hno", "HNO: House Number")
local f_civic_pc        = ProtoField.string("emergency_loc.civic.pc", "PC: Postal Code")
local f_civic_room      = ProtoField.string("emergency_loc.civic.room", "Room / Apartment / Floor")
local f_aml_imsi        = ProtoField.string("emergency_loc.aml.imsi", "AML Originating IMSI")
local f_aml_imei        = ProtoField.string("emergency_loc.aml.imei", "AML Device IMEI")
local f_aml_cell        = ProtoField.string("emergency_loc.aml.cell", "Serving Cell (MCC/MNC/LAC/CID)")
local f_retransmission  = ProtoField.string("emergency_loc.retransmission", "Retransmission Allowed")
local f_retention_exp   = ProtoField.string("emergency_loc.retention_expiry", "Retention Expiry Date")

loc_telemetry_proto.fields = {
    f_loc_type,
    f_entity,
    f_method,
    f_lat,
    f_lon,
    f_altitude,
    f_uncertainty,
    f_confidence,
    f_timestamp,
    f_civic_country,
    f_civic_a1,
    f_civic_a2,
    f_civic_a3,
    f_civic_a6,
    f_civic_hno,
    f_civic_pc,
    f_civic_room,
    f_aml_imsi,
    f_aml_imei,
    f_aml_cell,
    f_retransmission,
    f_retention_exp
}

-- XML Tag Extractor Helper
local function extract_xml_tag(xml, tag)
    local pattern = "<" .. tag .. "[^>]*>(.-)</" .. tag .. ">"
    local val = string.match(xml, pattern)
    if val then
        -- Clean XML comments or whitespace
        val = string.gsub(val, "^%s+", "")
        val = string.gsub(val, "%s+$", "")
        return val
    end
    return nil
end

-- Positioning Class mapping for AML (ETSI TS 103 493)
local AML_POS_METHODS = {
    ["G"] = "GNSS (GPS / Galileo / GLONASS)",
    ["W"] = "Wi-Fi BSSID Triangulation",
    ["C"] = "Cell-ID / Network Triangulation",
    ["N"] = "No Location Available"
}

function loc_telemetry_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 8 then return end

    local payload_str = tvb():string()
    local is_pidf_lo = false
    local is_aml = false

    -- Check for PIDF-LO XML markers
    if string.find(payload_str, "<presence") or string.find(payload_str, "<geopriv") or string.find(payload_str, "urn:ietf:params:xml:ns:pidf:geopriv10") then
        is_pidf_lo = true
    end

    -- Check for AML Key-Value or JSON markers
    if string.find(payload_str, "LT=") and string.find(payload_str, "LG=") then
        is_aml = true
    elseif string.find(payload_str, '"latitude"') and string.find(payload_str, '"longitude"') and string.find(payload_str, "aml") then
        is_aml = true
    end

    if not is_pidf_lo and not is_aml then return end

    pinfo.cols.protocol = is_pidf_lo and "PIDF-LO" or "AML"

    local loc_tree = tree:add(loc_telemetry_proto, tvb(), is_pidf_lo and "RFC 4119 / RFC 5139 PIDF-LO Location Object" or "ETSI TS 103 493 Advanced Mobile Location (AML)")

    if is_pidf_lo then
        loc_tree:add(f_loc_type, "PIDF-LO (Presence Information Data Format Location Object)")

        -- Entity URI
        local entity = string.match(payload_str, 'entity="([^"]+)"')
        if entity then loc_tree:add(f_entity, entity) end

        -- Location Method
        local method = extract_xml_tag(payload_str, "method")
        if method then loc_tree:add(f_method, method) end

        -- Geographic Coordinates (GML 2D / 3D)
        local gml_pos = extract_xml_tag(payload_str, "gml:pos") or extract_xml_tag(payload_str, "pos")
        if gml_pos then
            local parts = {}
            for part in string.gmatch(gml_pos, "[%d%.%-]+") do
                table.insert(parts, part)
            end
            if #parts >= 2 then
                loc_tree:add(f_lat, parts[1] .. "°")
                loc_tree:add(f_lon, parts[2] .. "°")
                if #parts >= 3 then
                    loc_tree:add(f_altitude, parts[3] .. " meters")
                end
            end
        else
            local lat = extract_xml_tag(payload_str, "latitude")
            local lon = extract_xml_tag(payload_str, "longitude")
            local alt = extract_xml_tag(payload_str, "altitude")
            if lat then loc_tree:add(f_lat, lat .. "°") end
            if lon then loc_tree:add(f_lon, lon .. "°") end
            if alt then loc_tree:add(f_altitude, alt .. " meters") end
        end

        -- Uncertainty / Radius
        local radius = extract_xml_tag(payload_str, "radius") or extract_xml_tag(payload_str, "uncertainty")
        if radius then loc_tree:add(f_uncertainty, radius .. " meters") end

        -- Timestamp
        local timestamp = extract_xml_tag(payload_str, "timestamp") or extract_xml_tag(payload_str, "time")
        if timestamp then loc_tree:add(f_timestamp, timestamp) end

        -- Civic Address Fields (RFC 5139)
        local civic_tree = nil
        local function add_civic(field, tag, name)
            local val = extract_xml_tag(payload_str, tag)
            if val and val ~= "" then
                if not civic_tree then civic_tree = loc_tree:add(loc_telemetry_proto, tvb(), "Civic Address Elements (Geopriv)") end
                civic_tree:add(field, val)
            end
        end

        add_civic(f_civic_country, "country", "Country")
        add_civic(f_civic_a1, "A1", "State/Province")
        add_civic(f_civic_a2, "A2", "County")
        add_civic(f_civic_a3, "A3", "City")
        add_civic(f_civic_a6, "A6", "Street Name")
        add_civic(f_civic_hno, "HNO", "House Number")
        add_civic(f_civic_pc, "PC", "Postal Code")
        add_civic(f_civic_room, "LOC", "Location / Room")

        -- Privacy & Usage Rules
        local retrans = extract_xml_tag(payload_str, "re-transmission-allowed")
        if retrans then loc_tree:add(f_retransmission, retrans) end
        local ret_exp = extract_xml_tag(payload_str, "retention-expiry")
        if ret_exp then loc_tree:add(f_retention_exp, ret_exp) end

        pinfo.cols.info = "PIDF-LO Location Telemetry: " .. (gml_pos or (extract_xml_tag(payload_str, "A3") or "Civic Object"))
    end

    if is_aml then
        loc_tree:add(f_loc_type, "AML (ETSI TS 103 493 Advanced Mobile Location)")

        -- Parse AML Key-Value string (LT=...;LG=...;RD=...;TC=...;PC=...;CA=...;SI=...;EI=...;MCC=...;MNC=...)
        local lat = string.match(payload_str, "LT=([%d%.%-]+)") or string.match(payload_str, '"latitude"%s*:%s*([%d%.%-]+)')
        local lon = string.match(payload_str, "LG=([%d%.%-]+)") or string.match(payload_str, '"longitude"%s*:%s*([%d%.%-]+)')
        local radius = string.match(payload_str, "RD=(%d+)") or string.match(payload_str, '"radius"%s*:%s*(%d+)')
        local ts_raw = string.match(payload_str, "TC=(%d+)") or string.match(payload_str, '"timestamp"%s*:%s*(%d+)')
        local pos_class = string.match(payload_str, "PC=([A-Za-z])") or string.match(payload_str, '"positioningMethod"%s*:%s*"([^"]+)"')
        local confidence = string.match(payload_str, "CA=(%d+)") or string.match(payload_str, '"confidence"%s*:%s*(%d+)')
        local imsi = string.match(payload_str, "SI=(%d+)") or string.match(payload_str, '"imsi"%s*:%s*"([^"]+)"')
        local imei = string.match(payload_str, "EI=(%d+)") or string.match(payload_str, '"imei"%s*:%s*"([^"]+)"')
        local mcc = string.match(payload_str, "MCC=(%d+)")
        local mnc = string.match(payload_str, "MNC=(%d+)")
        local lac = string.match(payload_str, "LAC=(%d+)")
        local cid = string.match(payload_str, "CID=(%d+)")

        if lat then loc_tree:add(f_lat, lat .. "°") end
        if lon then loc_tree:add(f_lon, lon .. "°") end
        if radius then loc_tree:add(f_uncertainty, radius .. " meters") end
        if confidence then loc_tree:add(f_confidence, confidence .. "%") end
        if pos_class then
            local desc = AML_POS_METHODS[pos_class] or pos_class
            loc_tree:add(f_method, string.format("%s (%s)", desc, pos_class))
        end
        if ts_raw then loc_tree:add(f_timestamp, ts_raw) end
        if imsi then loc_tree:add(f_aml_imsi, imsi) end
        if imei then loc_tree:add(f_aml_imei, imei) end
        if mcc and mnc then
            loc_tree:add(f_aml_cell, string.format("MCC:%s MNC:%s LAC:%s CID:%s", mcc, mnc, lac or "?", cid or "?"))
        end

        pinfo.cols.info = string.format("AML Fast Location: Lat=%s Lon=%s Radius=%sm (%s)", 
            lat or "?", lon or "?", radius or "?", AML_POS_METHODS[pos_class] or pos_class or "GNSS")
    end
end

-- Register media types for SIP / HTTP MIME bodies
local media_table = DissectorTable.get("media_type")
if media_table then
    media_table:add("application/pidf+xml", loc_telemetry_proto)
    media_table:add("application/held+xml", loc_telemetry_proto)
    media_table:add("application/aml+json", loc_telemetry_proto)
end
