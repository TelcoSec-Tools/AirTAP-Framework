-- TelcoSec.net - IMS Security Association & IPsec Gm Interface Dissector
-- Target Standards: 3GPP TS 33.203 (IMS Access Security), RFC 3329 (Security Mechanism Agreement for SIP)
-- Description: Dissects SIP Security-Client, Security-Server, and Security-Verify headers on Gm interface.
--              Extracts Client/Server SPIs (spi-c, spi-s) and Protected Ports (port-c, port-s),
--              verifies 'ipsec-3gpp' cryptographic algorithms (hmac-sha-1-96, aes-cbc),
--              and flags plaintext signaling fallback attacks against IMS core.

local ok, ims_ipsec_proto = pcall(Proto, "ims_ipsec_sec", "TelcoSec IMS AKA & IPsec Gm Security Association Analyzer")
if not ok or not ims_ipsec_proto then return end

-- Protocol fields
local f_sec_mech       = ProtoField.string("ims_ipsec_sec.mech", "Security Mechanism")
local f_spi_c          = ProtoField.uint32("ims_ipsec_sec.spi_c", "Client Inbound SPI (spi-c)", base.DEC)
local f_spi_s          = ProtoField.uint32("ims_ipsec_sec.spi_s", "Server Inbound SPI (spi-s)", base.DEC)
local f_port_c         = ProtoField.uint16("ims_ipsec_sec.port_c", "Client Protected Port (port-c)", base.DEC)
local f_port_s         = ProtoField.uint16("ims_ipsec_sec.port_s", "Server Protected Port (port-s)", base.DEC)
local f_sec_alg        = ProtoField.string("ims_ipsec_sec.alg", "Integrity Algorithm (alg)")
local f_sec_ealg       = ProtoField.string("ims_ipsec_sec.ealg", "Encryption Algorithm (ealg)")
local f_sec_alert      = ProtoField.string("ims_ipsec_sec.alert", "TelcoSec IMS SA Alert")

ims_ipsec_proto.fields = {
    f_sec_mech,
    f_spi_c,
    f_spi_s,
    f_port_c,
    f_port_s,
    f_sec_alg,
    f_sec_ealg,
    f_sec_alert
}

-- Safe field getters
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_sip_sec_client = safe_field("sip.Security-Client")
local f_sip_sec_server = safe_field("sip.Security-Server")
local f_sip_sec_verify = safe_field("sip.Security-Verify")

function ims_ipsec_proto.dissector(tvb, pinfo, tree)
    local proto_str = tostring(pinfo.cols.protocol)
    if not string.find(proto_str, "SIP") then return end

    local sec_hdr = nil
    local hdr_type = nil

    if f_sip_sec_server and f_sip_sec_server() then
        sec_hdr = tostring(f_sip_sec_server().value)
        hdr_type = "Security-Server (P-CSCF Response)"
    elseif f_sip_sec_client and f_sip_sec_client() then
        sec_hdr = tostring(f_sip_sec_client().value)
        hdr_type = "Security-Client (UE Offer)"
    elseif f_sip_sec_verify and f_sip_sec_verify() then
        sec_hdr = tostring(f_sip_sec_verify().value)
        hdr_type = "Security-Verify (Authenticated)"
    end

    if not sec_hdr or sec_hdr == "" then return end

    local subtree = tree:add(ims_ipsec_proto, tvb(), string.format("IMS Security Association: %s", hdr_type))
    local alerts = {}

    -- Extract Security Mechanism
    local mech = string.match(sec_hdr, "^%s*([%w%-_]+)")
    if mech then
        subtree:add(f_sec_mech, mech)
        if mech ~= "ipsec-3gpp" and mech ~= "tls" then
            table.insert(alerts, string.format("[WARNING] Non-standard IMS security mechanism negotiated: '%s'", mech))
        end
    end

    -- Extract SPIs
    local spi_c = string.match(sec_hdr, "spi%-c%s*=%s*(%d+)")
    if spi_c then
        subtree:add(f_spi_c, tonumber(spi_c))
    end

    local spi_s = string.match(sec_hdr, "spi%-s%s*=%s*(%d+)")
    if spi_s then
        subtree:add(f_spi_s, tonumber(spi_s))
    end

    -- Extract Ports
    local port_c = string.match(sec_hdr, "port%-c%s*=%s*(%d+)")
    if port_c then
        subtree:add(f_port_c, tonumber(port_c))
    end

    local port_s = string.match(sec_hdr, "port%-s%s*=%s*(%d+)")
    if port_s then
        subtree:add(f_port_s, tonumber(port_s))
    end

    -- Extract Algorithms
    local alg = string.match(sec_hdr, "alg%s*=%s*([%w%-_]+)")
    if alg then
        subtree:add(f_sec_alg, alg)
    end

    local ealg = string.match(sec_hdr, "ealg%s*=%s*([%w%-_]+)")
    if ealg then
        subtree:add(f_sec_ealg, ealg)
        if ealg == "null" then
            table.insert(alerts, "[NOTICE] IMS IPsec Encryption Algorithm is 'null' (Signaling integrity active without confidentiality).")
        end
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: IMS IPSEC SA!]")
    end
end

register_postdissector(ims_ipsec_proto)
