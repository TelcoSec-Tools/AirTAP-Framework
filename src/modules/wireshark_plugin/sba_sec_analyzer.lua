-- TelcoSec.net - 5G SBA Security Post-Dissector
-- Description: Analyzes HTTP/2 payloads in 5G SBA traffic for security anomalies.

local ok, telcosec_sba_proto = pcall(Proto, "sba_sec", "TelcoSec 5G SBA (HTTP/2 JSON Core) Security Analyzer")
if not ok or not telcosec_sba_proto then return end

-- Define fields we want to highlight or extract
local f_warning = ProtoField.string("telcosec_sba.warning", "Security Warning")
local f_supi = ProtoField.string("telcosec_sba.supi", "Detected SUPI/IMSI")
local f_api_endpoint = ProtoField.string("telcosec_sba.endpoint", "API Endpoint")

telcosec_sba_proto.fields = { f_warning, f_supi, f_api_endpoint }

local f_http2_headers_path = nil
local f_http2_headers_method = nil

function telcosec_sba_proto.dissector(tvb, pinfo, tree)
    if not f_http2_headers_path then
        pcall(function()
            f_http2_headers_path = Field.new("http2.header.path")
            f_http2_headers_method = Field.new("http2.header.method")
        end)
    end

    if not f_http2_headers_path then return end

    -- Retrieve all HTTP/2 path headers in the packet
    local paths = { f_http2_headers_path() }
    
    if #paths == 0 then
        return -- No HTTP/2 path found, nothing to do
    end

    local is_sba = false
    local endpoint_str = ""

    -- Check if the HTTP/2 path resembles a 5G SBA API endpoint
    for i, path_info in ipairs(paths) do
        local path = tostring(path_info.value)
        -- 5G SBA APIs typically start with /n<nf>- or contain 3gpp
        if string.find(path, "/n[a-z]+%-") or string.find(path, "3gpp") then
            is_sba = true
            endpoint_str = path
            break
        end
    end

    if not is_sba then return end

    -- We found 5G SBA traffic! Create the TelcoSec analysis tree
    local subtree = tree:add(telcosec_sba_proto, "TelcoSec 5G SBA Security Analysis")
    subtree:add(f_api_endpoint, endpoint_str)

    -- 1. Security Heuristic: Unencrypted Traffic
    -- If we see this natively on port 80/8080 without a decryption profile, it's a huge risk
    if pinfo.src_port == 80 or pinfo.dst_port == 80 or pinfo.src_port == 8080 or pinfo.dst_port == 8080 then
         subtree:add(f_warning, "[HIGH RISK] Unencrypted SBA Traffic detected on standard HTTP port!")
    end

    -- 2. Security Heuristic: Sensitive Endpoints (UDM/AUSF)
    if string.find(endpoint_str, "/nudm%-") then
         subtree:add(f_warning, "[INFO] UDM API accessed (Authentication/Subscription Data). Verify authorization.")
    elseif string.find(endpoint_str, "/nausf%-") then
         subtree:add(f_warning, "[INFO] AUSF API accessed (Authentication Server).")
    end

    -- 3. Data Extraction: SUPI / IMSI
    -- Often passed in the URI, e.g., /nudm-ueau/v1/imsi-123456789012345/...
    local supi_match = string.match(endpoint_str, "(imsi%-%d+)") or string.match(endpoint_str, "(supi%-[%w%-]+)")
    if supi_match then
        subtree:add(f_supi, supi_match)
        -- Also add this to the Wireshark info column for easy viewing
        pinfo.cols.info:append(" [TelcoSec: " .. supi_match .. "]")
    end
end

-- Register as a postdissector so it runs AFTER Wireshark's native HTTP/2 dissector
register_postdissector(telcosec_sba_proto)
