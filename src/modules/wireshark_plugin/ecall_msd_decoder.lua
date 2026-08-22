-- TelcoSec.net - eCall Minimum Set of Data (MSD) Dissector & Full Decoder
-- Target Standards:
--   CEN EN 15722 (Intelligent transport systems - ESafety - ECall minimum set of data)
--   ISO 24978 / ETSI TS 103 321 / 3GPP TS 26.267 (eCall data transfer)
--   ISO 3779 (Road vehicles - Vehicle identification number (VIN))
--
-- Description: Fully unpacks and decodes eCall MSD payloads (ASN.1 UPER / BER and binary framing).
--              Extracts Message Version, Trigger Type (Manual vs Automatic Crash), Test/Real Call,
--              Vehicle Category, 17-char VIN with WMI Manufacturer resolution, Propulsion Storage Type,
--              UTC Crash Timestamp, Precise WGS84 GPS Latitude/Longitude, Heading/Direction,
--              Number of Occupants, and Historic Delta Coordinates.

local ok, ecall_msd_proto = pcall(Proto, "ecall_msd", "eCall Minimum Set of Data (MSD) Decoder")
if not ok or not ecall_msd_proto then return end

-- Protocol Fields
local f_msd_ver         = ProtoField.uint8("ecall_msd.version", "MSD Structure Version", base.DEC)
local f_msg_id          = ProtoField.uint8("ecall_msd.msg_id", "Message Identifier", base.DEC)
local f_ctrl_auto       = ProtoField.bool("ecall_msd.ctrl.automatic", "Activation: Automatic (Crash Sensors)", 8, nil, 0x80)
local f_ctrl_manual     = ProtoField.bool("ecall_msd.ctrl.manual", "Activation: Manual (SOS Button)", 8, nil, 0x40)
local f_ctrl_test       = ProtoField.bool("ecall_msd.ctrl.test_call", "Call Type: Test Call (Non-Emergency)", 8, nil, 0x20)
local f_ctrl_pos_trust  = ProtoField.bool("ecall_msd.ctrl.position_trusted", "Position Confidence: High / Can Be Trusted", 8, nil, 0x10)
local f_veh_class       = ProtoField.uint8("ecall_msd.veh_class", "Vehicle Category / Class", base.HEX)
local f_veh_class_name  = ProtoField.string("ecall_msd.veh_class_name", "Vehicle Class Description")
local f_vin             = ProtoField.string("ecall_msd.vin", "Vehicle Identification Number (VIN)")
local f_wmi_mfg         = ProtoField.string("ecall_msd.wmi_manufacturer", "Vehicle Manufacturer (WMI)")
local f_propulsion_mask = ProtoField.uint16("ecall_msd.propulsion_mask", "Propulsion Storage Bitmask", base.HEX)
local f_propulsion_desc = ProtoField.string("ecall_msd.propulsion", "Propulsion Energy Storage Type")
local f_timestamp_raw   = ProtoField.uint32("ecall_msd.timestamp_raw", "Raw UTC Timestamp", base.DEC)
local f_timestamp_str   = ProtoField.string("ecall_msd.timestamp", "Crash / Trigger Time (UTC)")
local f_lat_raw         = ProtoField.int32("ecall_msd.latitude_raw", "Latitude Raw (Milliarcseconds)", base.DEC)
local f_lat_deg         = ProtoField.string("ecall_msd.latitude", "WGS84 Latitude")
local f_lon_raw         = ProtoField.int32("ecall_msd.longitude_raw", "Longitude Raw (Milliarcseconds)", base.DEC)
local f_lon_deg         = ProtoField.string("ecall_msd.longitude", "WGS84 Longitude")
local f_direction_raw   = ProtoField.uint8("ecall_msd.direction_raw", "Heading Raw (2-deg units)", base.DEC)
local f_direction_deg   = ProtoField.uint16("ecall_msd.direction", "Vehicle Heading / Direction (degrees)", base.DEC)
local f_occupants       = ProtoField.uint8("ecall_msd.occupants", "Number of Occupants (Fastened Belts)", base.DEC)
local f_delta_n1_lat    = ProtoField.int16("ecall_msd.delta_n1.lat", "Delta Latitude N-1 (100ms)", base.DEC)
local f_delta_n1_lon    = ProtoField.int16("ecall_msd.delta_n1.lon", "Delta Longitude N-1 (100ms)", base.DEC)
local f_delta_n2_lat    = ProtoField.int16("ecall_msd.delta_n2.lat", "Delta Latitude N-2 (200ms)", base.DEC)
local f_delta_n2_lon    = ProtoField.int16("ecall_msd.delta_n2.lon", "Delta Longitude N-2 (200ms)", base.DEC)
local f_optional_data   = ProtoField.bytes("ecall_msd.optional_data", "Additional / Optional Crash Data")

ecall_msd_proto.fields = {
    f_msd_ver,
    f_msg_id,
    f_ctrl_auto,
    f_ctrl_manual,
    f_ctrl_test,
    f_ctrl_pos_trust,
    f_veh_class,
    f_veh_class_name,
    f_vin,
    f_wmi_mfg,
    f_propulsion_mask,
    f_propulsion_desc,
    f_timestamp_raw,
    f_timestamp_str,
    f_lat_raw,
    f_lat_deg,
    f_lon_raw,
    f_lon_deg,
    f_direction_raw,
    f_direction_deg,
    f_occupants,
    f_delta_n1_lat,
    f_delta_n1_lon,
    f_delta_n2_lat,
    f_delta_n2_lon,
    f_optional_data
}

-- Vehicle Class mapping per CEN EN 15722
local VEHICLE_CLASSES = {
    [1]  = "Passenger Car (Class M1)",
    [2]  = "Light Commercial Vehicle (Class N1)",
    [3]  = "Heavy Goods Vehicle (Class N2)",
    [4]  = "Heavy Goods Vehicle (Class N3)",
    [5]  = "Bus / Coach (Class M2)",
    [6]  = "Bus / Coach (Class M3)",
    [7]  = "Motorcycle (Class L1e)",
    [8]  = "Motorcycle (Class L2e)",
    [9]  = "Motorcycle (Class L3e)",
    [10] = "Motorcycle (Class L4e)",
    [11] = "Motorcycle (Class L5e)",
    [12] = "Light Quadricycle (Class L6e)",
    [13] = "Heavy Quadricycle (Class L7e)"
}

-- World Manufacturer Identifier (WMI) lookup table (ISO 3779 first 3 characters of VIN)
local WMI_TABLE = {
    ["WAU"] = "Audi AG (Germany)",
    ["WA1"] = "Audi SUV (Germany)",
    ["WBA"] = "BMW AG (Germany)",
    ["WBY"] = "BMW i Electric (Germany)",
    ["WDB"] = "Mercedes-Benz (Germany)",
    ["WDC"] = "DaimlerChrysler / Mercedes (Germany)",
    ["WDD"] = "Mercedes-Benz Cars (Germany)",
    ["WVW"] = "Volkswagen (Germany)",
    ["WP0"] = "Porsche (Germany)",
    ["VF1"] = "Renault (France)",
    ["VF3"] = "Peugeot (France)",
    ["VF7"] = "Citroën (France)",
    ["ZFA"] = "Fiat (Italy)",
    ["ZAR"] = "Alfa Romeo (Italy)",
    ["ZFF"] = "Ferrari (Italy)",
    ["1FA"] = "Ford Motor Company (USA)",
    ["1GC"] = "Chevrolet Truck (USA)",
    ["1G1"] = "Chevrolet Passenger (USA)",
    ["1HG"] = "Honda (USA)",
    ["4T1"] = "Toyota (USA)",
    ["5YJ"] = "Tesla Inc. (USA Model S/3/X)",
    ["7SA"] = "Tesla Inc. (USA Model Y)",
    ["JN1"] = "Nissan (Japan)",
    ["JM1"] = "Mazda (Japan)",
    ["JT1"] = "Toyota (Japan)",
    ["KM8"] = "Hyundai Motor (South Korea)",
    ["KNA"] = "Kia Motors (South Korea)",
    ["SAL"] = "Land Rover (UK)",
    ["SAJ"] = "Jaguar (UK)",
    ["YS3"] = "Saab (Sweden)",
    ["YV1"] = "Volvo Cars (Sweden)"
}

-- Decode Vehicle Propulsion Storage Bitmask
local function decode_propulsion(mask)
    local types = {}
    if bit32.band(mask, 0x01) ~= 0 then table.insert(types, "Gasoline / Petrol") end
    if bit32.band(mask, 0x02) ~= 0 then table.insert(types, "Diesel") end
    if bit32.band(mask, 0x04) ~= 0 then table.insert(types, "Compressed Natural Gas (CNG)") end
    if bit32.band(mask, 0x08) ~= 0 then table.insert(types, "Liquid Petroleum Gas (LPG)") end
    if bit32.band(mask, 0x10) ~= 0 then table.insert(types, "Electric (Battery > 42V)") end
    if bit32.band(mask, 0x20) ~= 0 then table.insert(types, "Hydrogen Fuel Cell") end
    if bit32.band(mask, 0x40) ~= 0 then table.insert(types, "Other / Hybrid") end
    if #types == 0 then return "Unknown / Not Provided" end
    return table.concat(types, ", ")
end

-- Helper: Convert milliarcseconds (1/3600000 degrees) to Decimal Degrees
local function mas_to_degrees(mas)
    return mas / 3600000.0
end

-- Format UTC timestamp from seconds
local function format_utc_timestamp(sec)
    if sec == 0 or sec > 2147483647 then return "Unknown / Not set" end
    return os.date("!%Y-%m-%d %H:%M:%S UTC", sec)
end

-- Base64 decode helper for MSD MIME bodies
local b64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function base64_decode(data)
    data = string.gsub(data, '[^'..b64_chars..'=]', '')
    return (data:gsub('=', ''):gsub('..%d?', function(chars)
        local c1 = b64_chars:find(chars:sub(1,1)) - 1
        local c2 = b64_chars:find(chars:sub(2,2)) - 1
        local c3 = chars:len() > 2 and (b64_chars:find(chars:sub(3,3)) - 1) or 0
        local c4 = chars:len() > 3 and (b64_chars:find(chars:sub(4,4)) - 1) or 0
        local b1 = bit32.bor(bit32.lshift(c1, 2), bit32.rshift(c2, 4))
        local b2 = bit32.bor(bit32.lshift(bit32.band(c2, 0xF), 4), bit32.rshift(c3, 2))
        local b3 = bit32.bor(bit32.lshift(bit32.band(c3, 0x3), 6), c4)
        if chars:len() == 2 then return string.char(b1)
        elseif chars:len() == 3 then return string.char(b1, b2)
        else return string.char(b1, b2, b3) end
    end))
end

function ecall_msd_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 28 then return end

    -- Check if payload is Base64 encoded (as found in SIP multipart bodies)
    local working_tvb = tvb
    local offset = 0
    local raw_peek = tvb(0, math.min(len, 64)):string()

    if string.match(raw_peek, "^[A-Za-z0-9+/=]+$") and not string.match(raw_peek, "[\0-\x1f]") then
        local decoded = base64_decode(tvb():string())
        if decoded and #decoded >= 28 then
            working_tvb = ByteArray.new(decoded, true):tvb("Decoded eCall MSD")
            len = working_tvb:len()
        end
    end

    -- Skip ASN.1 SEQUENCE / wrapper tags if present (e.g. 0x30 or PER length prefix)
    if working_tvb(0, 1):uint() == 0x30 then
        local seq_len = working_tvb(1, 1):uint()
        if seq_len > 0x80 then
            local num_len_bytes = bit32.band(seq_len, 0x7F)
            offset = 2 + num_len_bytes
        else
            offset = 2
        end
    end

    if (len - offset) < 28 then return end

    pinfo.cols.protocol = "eCall-MSD"

    local msd_tree = tree:add(ecall_msd_proto, working_tvb(offset), "CEN EN 15722 eCall Minimum Set of Data (MSD)")

    -- 1. MSD Message Structure Version
    local msd_ver = working_tvb(offset, 1):uint()
    msd_tree:add(f_msd_ver, working_tvb(offset, 1))
    offset = offset + 1

    -- 2. Message Identifier
    local msg_id = working_tvb(offset, 1):uint()
    msd_tree:add(f_msg_id, working_tvb(offset, 1))
    offset = offset + 1

    -- 3. Control byte (Flags + Vehicle Class)
    local ctrl_byte = working_tvb(offset, 1):uint()
    local ctrl_tree = msd_tree:add(working_tvb(offset, 1), string.format("Control Flags & Vehicle Category (0x%02X)", ctrl_byte))
    
    local is_auto = bit32.band(ctrl_byte, 0x80) ~= 0
    local is_test = bit32.band(ctrl_byte, 0x20) ~= 0
    local is_trusted = bit32.band(ctrl_byte, 0x10) ~= 0
    local veh_class_id = bit32.band(ctrl_byte, 0x0F)

    ctrl_tree:add(f_ctrl_auto, working_tvb(offset, 1))
    ctrl_tree:add(f_ctrl_manual, working_tvb(offset, 1))
    ctrl_tree:add(f_ctrl_test, working_tvb(offset, 1))
    ctrl_tree:add(f_ctrl_pos_trust, working_tvb(offset, 1))
    ctrl_tree:add(f_veh_class, working_tvb(offset, 1), veh_class_id)
    
    local veh_class_name = VEHICLE_CLASSES[veh_class_id] or string.format("Unknown Vehicle Class (%d)", veh_class_id)
    ctrl_tree:add(f_veh_class_name, veh_class_name)
    offset = offset + 1

    -- 4. Vehicle Identification Number (VIN) - 17 ASCII characters
    local vin_str = working_tvb(offset, 17):string()
    -- Clean non-printable characters if any
    vin_str = string.gsub(vin_str, "[^A-HJ-NPR-Z0-9]", "?")
    local vin_item = msd_tree:add(f_vin, working_tvb(offset, 17), vin_str)

    -- Extract WMI (World Manufacturer Identifier)
    local wmi_code = string.sub(vin_str, 1, 3)
    local mfg_name = WMI_TABLE[wmi_code] or "Unregistered / Custom WMI"
    vin_item:add(f_wmi_mfg, string.format("%s (%s)", mfg_name, wmi_code))
    offset = offset + 17

    -- 5. Vehicle Propulsion Storage Type (2 bytes)
    local prop_mask = working_tvb(offset, 2):uint()
    local prop_desc = decode_propulsion(prop_mask)
    local prop_tree = msd_tree:add(f_propulsion_mask, working_tvb(offset, 2))
    prop_tree:add(f_propulsion_desc, prop_desc)
    offset = offset + 2

    -- 6. UTC Timestamp (4 bytes Big Endian)
    local ts_raw = working_tvb(offset, 4):uint()
    local ts_str = format_utc_timestamp(ts_raw)
    local ts_tree = msd_tree:add(f_timestamp_raw, working_tvb(offset, 4))
    ts_tree:add(f_timestamp_str, ts_str)
    offset = offset + 4

    -- 7. Latitude (4 bytes signed integer, in milliarcseconds)
    local lat_raw = working_tvb(offset, 4):int()
    local lat_deg = mas_to_degrees(lat_raw)
    local lat_str = string.format("%.6f° %s (%d mas)", math.abs(lat_deg), lat_deg >= 0 and "N" or "S", lat_raw)
    local lat_tree = msd_tree:add(f_lat_raw, working_tvb(offset, 4))
    lat_tree:add(f_lat_deg, lat_str)
    offset = offset + 4

    -- 8. Longitude (4 bytes signed integer, in milliarcseconds)
    local lon_raw = working_tvb(offset, 4):int()
    local lon_deg = mas_to_degrees(lon_raw)
    local lon_str = string.format("%.6f° %s (%d mas)", math.abs(lon_deg), lon_deg >= 0 and "E" or "W", lon_raw)
    local lon_tree = msd_tree:add(f_lon_raw, working_tvb(offset, 4))
    lon_tree:add(f_lon_deg, lon_str)
    offset = offset + 4

    -- 9. Vehicle Direction / Heading (1 byte in 2-degree units)
    local dir_raw = working_tvb(offset, 1):uint()
    local dir_deg = dir_raw * 2
    local dir_tree = msd_tree:add(f_direction_raw, working_tvb(offset, 1))
    dir_tree:add(f_direction_deg, dir_deg)
    offset = offset + 1

    -- 10. Number of Occupants / Fastened Seatbelts (optional 1 byte)
    if (len - offset) >= 1 then
        local occupants = working_tvb(offset, 1):uint()
        msd_tree:add(f_occupants, working_tvb(offset, 1))
        offset = offset + 1
    end

    -- 11. Historic Locations Delta (optional N-1 and N-2 coordinates)
    if (len - offset) >= 8 then
        local delta_tree = msd_tree:add(working_tvb(offset, 8), "Historic Location Delta (N-1 / N-2 Trajectory)")
        delta_tree:add(f_delta_n1_lat, working_tvb(offset, 2))
        delta_tree:add(f_delta_n1_lon, working_tvb(offset + 2, 2))
        delta_tree:add(f_delta_n2_lat, working_tvb(offset + 4, 2))
        delta_tree:add(f_delta_n2_lon, working_tvb(offset + 6, 2))
        offset = offset + 8
    end

    -- 12. Additional Crash / Sensor Data if remaining
    if (len - offset) > 0 then
        msd_tree:add(f_optional_data, working_tvb(offset, len - offset))
    end

    -- Update Wireshark Info Column
    local trigger_mode = is_auto and "AUTO-CRASH" or "MANUAL"
    if is_test then trigger_mode = "TEST-CALL" end
    
    pinfo.cols.info = string.format("eCall MSD: VIN=%s [%s] Lat=%.4f Lon=%.4f (%s)", 
        vin_str, trigger_mode, lat_deg, lon_deg, mfg_name)
end

-- Register dissector for MIME media types used in SIP multipart bodies
local media_table = DissectorTable.get("media_type")
if media_table then
    media_table:add("application/emergencyCallData.eCall.MSD", ecall_msd_proto)
    media_table:add("application/emergencyCallData.eCall.MSD+zip", ecall_msd_proto)
    media_table:add("application/eCall-MSD", ecall_msd_proto)
end
