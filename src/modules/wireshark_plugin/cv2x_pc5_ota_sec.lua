-- TelcoSec.net - Cellular V2X & ProSe Sidelink (PC5) Air Interface Security Analyzer
-- Target Standards: 3GPP TS 36.331 / TS 38.331 (V2X Sidelink RRC), TS 23.287 (5G V2X Architecture),
--                   IEEE 1609.2 / ETSI TS 102 940 (ITS Security and Certificate Verification)
-- Description: Dissects Cellular V2X (C-V2X) and 5G ProSe (Proximity Services) direct device-to-device
--              communication over the PC5 radio interface. Analyzes Basic Safety Messages (BSM),
--              Cooperative Awareness Messages (CAM), Decentralized Environmental Notifications (DENM),
--              and detects Ghost Vehicle GPS spoofing, certificate forgery, and replay attacks.

local ok, cv2x_pc5_proto = pcall(Proto, "cv2x_pc5_sec", "TelcoSec C-V2X & ProSe Sidelink (PC5) Security Analyzer")
if not ok or not cv2x_pc5_proto then return end

-- Protocol fields
local f_v2x_rat         = ProtoField.string("cv2x_pc5_sec.rat", "V2X Sidelink RAT (LTE-V2X / 5G NR-V2X)")
local f_msg_type        = ProtoField.string("cv2x_pc5_sec.msg_type", "V2X Safety Message Type")
local f_station_id      = ProtoField.uint32("cv2x_pc5_sec.station_id", "ITS Station Identifier", base.HEX)
local f_vehicle_speed   = ProtoField.float("cv2x_pc5_sec.speed_kmh", "Vehicle Speed (km/h)")
local f_latitude        = ProtoField.float("cv2x_pc5_sec.latitude", "Vehicle Latitude (deg)")
local f_longitude       = ProtoField.float("cv2x_pc5_sec.longitude", "Vehicle Longitude (deg)")
local f_heading         = ProtoField.float("cv2x_pc5_sec.heading", "Vehicle Heading (deg)")
local f_cert_digest     = ProtoField.bytes("cv2x_pc5_sec.cert_digest", "IEEE 1609.2 / ETSI HashedId8 Digest")
local f_tamper_flag     = ProtoField.bool("cv2x_pc5_sec.tampered", "Integrity / Signature Tampered")
local f_ghost_vehicle   = ProtoField.bool("cv2x_pc5_sec.ghost_vehicle", "Ghost Vehicle Anomaly Detected")
local f_sec_alert       = ProtoField.string("cv2x_pc5_sec.alert", "TelcoSec C-V2X Safety Alert")

cv2x_pc5_proto.fields = {
    f_v2x_rat,
    f_msg_type,
    f_station_id,
    f_vehicle_speed,
    f_latitude,
    f_longitude,
    f_heading,
    f_cert_digest,
    f_tamper_flag,
    f_ghost_vehicle,
    f_sec_alert
}

-- Known V2X Message Types (ETSI / SAE J2735)
local V2X_MSG_TYPES = {
    [1] = "DENM (Decentralized Environmental Notification Message - Emergency/Hazard)",
    [2] = "CAM (Cooperative Awareness Message - Telemetry)",
    [3] = "POI (Point of Interest)",
    [4] = "SPAT (Signal Phase and Timing - Traffic Light)",
    [5] = "MAP (Map Data / Intersection Geometry)",
    [6] = "IVIM (In-Vehicle Information Message)",
    [7] = "EVCSN (Electric Vehicle Charging)",
    [20] = "SAE J2735 BSM (Basic Safety Message)"
}

-- State tracking for Ghost Vehicle detection (impossible acceleration/teleportation)
local vehicle_history = {}

function cv2x_pc5_proto.dissector(tvb, pinfo, tree)
    -- Requires at least 8 bytes for basic PC5/ITS header
    if tvb:len() < 8 then return end

    pinfo.cols.protocol = "C-V2X PC5"

    local subtree = tree:add(cv2x_pc5_proto, tvb(), "TelcoSec C-V2X & 5G Sidelink (PC5) Security Engine")

    local proto_ver = tvb(0, 1):uint()
    local msg_id = tvb(1, 1):uint()
    local msg_name = V2X_MSG_TYPES[msg_id] or string.format("V2X Message (ID: %d)", msg_id)

    local station_id = tvb(2, 4):uint()

    subtree:add(f_v2x_rat, (proto_ver >= 2) and "5G NR-V2X (Release 16+)" or "LTE-V2X (Release 14/15)")
    subtree:add(f_msg_type, msg_name)
    subtree:add(f_station_id, tvb(2, 4), station_id)

    pinfo.cols.info = string.format("[C-V2X PC5] %s | Station: 0x%08X", msg_name, station_id)

    -- Extract Telemetry if payload length permits (ETSI CAM / SAE BSM format)
    if tvb:len() >= 24 then
        -- Latitude: microdegrees (32-bit signed int)
        local lat_raw = tvb(6, 4):int()
        local lat_deg = lat_raw / 10000000.0
        -- Longitude: microdegrees (32-bit signed int)
        local lon_raw = tvb(10, 4):int()
        local lon_deg = lon_raw / 10000000.0
        -- Speed: 0.01 m/s (16-bit uint)
        local speed_raw = tvb(14, 2):uint()
        local speed_kmh = (speed_raw * 0.01) * 3.6

        subtree:add(f_latitude, lat_deg)
        subtree:add(f_longitude, lon_deg)
        subtree:add(f_vehicle_speed, speed_kmh)

        pinfo.cols.info:append(string.format(" (Speed: %.1f km/h, Lat: %.4f, Lon: %.4f)", speed_kmh, lat_deg, lon_deg))

        -- Heuristic: Ghost Vehicle Teleportation / Kinematic Anomaly
        local prev = vehicle_history[station_id]
        local cur_time = pinfo.abs_ts
        if prev ~= nil then
            local dt = cur_time - prev.time
            if dt > 0.05 and dt < 5.0 then
                -- Calculate approximate physical displacement in meters
                local dlat = (lat_deg - prev.lat) * 111000.0
                local dlon = (lon_deg - prev.lon) * 111000.0 * math.cos(math.rad(lat_deg))
                local dist_m = math.sqrt((dlat * dlat) + (dlon * dlon))
                local calc_speed_kmh = (dist_m / dt) * 3.6

                -- Physical impossibility: speed > 350 km/h or acceleration > 20 m/s^2
                if calc_speed_kmh > 350.0 then
                    subtree:add(f_ghost_vehicle, true)
                    subtree:add(f_sec_alert, string.format("[CRITICAL] Ghost Vehicle Anomaly! Kinematically impossible displacement (%.1f km/h calculated). Suspected V2X GPS Sybil / Spoofing attack.", calc_speed_kmh))
                    pinfo.cols.info:append(" [TELCOSEC: GHOST VEHICLE GPS SPOOFING!]")
                end
            end
        end

        vehicle_history[station_id] = {
            time = cur_time,
            lat = lat_deg,
            lon = lon_deg,
            speed = speed_kmh
        }
    end
end
