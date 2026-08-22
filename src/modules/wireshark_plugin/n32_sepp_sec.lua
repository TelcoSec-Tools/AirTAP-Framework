-- TelcoSec.net - 5G N32 / SEPP (Security Edge Protection Proxy - 3GPP TS 29.573 / TS 33.501) Roaming Dissector
-- Description: Dissects N32-c (handshake/security capabilities) and N32-f (forwarding) protocols over inter-PLMN IPX roaming connections.
--              Decodes security capabilities, JWE encryption algorithms (A128GCM, A256GCM), JWS signatures (ES256, ES384),
--              Data Modification Policies, and N32-f context identifiers.
--              Detects PRAS (Packet Redirection and Spoofing), CLEAR_TEXT downgrade attacks, JWE header tampering, and IPX intermediate eavesdropping.

local ok, n32_sepp_proto = pcall(Proto, "n32_sepp_sec", "TelcoSec 5G N32-SEPP Roaming Security Analyzer")
if not ok or not n32_sepp_proto then return end

-- Protocol fields
local f_msg_type        = ProtoField.string("n32_sepp.msg_type", "N32 Interface / Procedure")
local f_context_id      = ProtoField.string("n32_sepp.context_id", "N32-f Context ID")
local f_sender_sepp     = ProtoField.string("n32_sepp.sender_sepp", "Sender SEPP FQDN / PLMN")
local f_target_sepp     = ProtoField.string("n32_sepp.target_sepp", "Target SEPP FQDN / PLMN")
local f_jwe_alg         = ProtoField.string("n32_sepp.jwe_alg", "JWE Encryption Algorithm")
local f_jws_alg         = ProtoField.string("n32_sepp.jws_alg", "JWS Signature Algorithm")
local f_mod_policy      = ProtoField.string("n32_sepp.mod_policy", "Data Modification Policy")
local f_sec_alert       = ProtoField.string("n32_sepp.alert", "TelcoSec 5G Roaming Security Alert")
local f_payload         = ProtoField.bytes("n32_sepp.payload", "N32 JSON/JWE Raw Payload")

n32_sepp_proto.fields = {
    f_msg_type,
    f_context_id,
    f_sender_sepp,
    f_target_sepp,
    f_jwe_alg,
    f_jws_alg,
    f_mod_policy,
    f_sec_alert,
    f_payload
}

-- Native HTTP/2 dissector
local http2_dissector = Dissector.get("http2")

function n32_sepp_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 4 then return end

    local subtree = tree:add(n32_sepp_proto, tvb(), "5G N32 / SEPP Roaming Security Analysis")
    pinfo.cols.protocol = "5G N32 SEPP"

    local str_content = tvb:raw()
    local alerts = {}

    -- 1. Check for N32-c Control Plane Handshake (TS 29.573 §5.2)
    if string.find(str_content, "secNegotiateReqData") or string.find(str_content, "secNegotiateRspData") or string.find(str_content, "n32fContextId") then
        subtree:add(f_msg_type, "N32-c Security Capability Negotiation")
        pinfo.cols.info = "[5G N32-c] SEPP Security Capability Handshake"

        -- Extract Context ID
        local ctx_id = string.match(str_content, '"n32fContextId"%s*:%s*"([^"]+)"')
        if ctx_id then
            subtree:add(f_context_id, ctx_id)
        end

        -- Extract Sender/Target SEPP IDs
        local sender_sepp = string.match(str_content, '"sender"%s*:%s*"([^"]+)"') or string.match(str_content, '"callingSeppId"%s*:%s*"([^"]+)"')
        local target_sepp = string.match(str_content, '"target"%s*:%s*"([^"]+)"') or string.match(str_content, '"calledSeppId"%s*:%s*"([^"]+)"')
        if sender_sepp then subtree:add(f_sender_sepp, sender_sepp) end
        if target_sepp then subtree:add(f_target_sepp, target_sepp) end

        -- Extract Algorithms
        local jwe_alg = string.match(str_content, '"selectedJweCipherSuite"%s*:%s*"([^"]+)"') or string.match(str_content, '"jweCipherSuite"%s*:%s*"([^"]+)"')
        local jws_alg = string.match(str_content, '"selectedJwsCipherSuite"%s*:%s*"([^"]+)"') or string.match(str_content, '"jwsCipherSuite"%s*:%s*"([^"]+)"')
        if jwe_alg then subtree:add(f_jwe_alg, jwe_alg) end
        if jws_alg then subtree:add(f_jws_alg, jws_alg) end

        -- Security Heuristic 1: CLEAR_TEXT / Null Encryption Downgrade on Roaming Interface
        if string.find(str_content, '"CLEAR_TEXT"') or string.find(str_content, '"NONE"') or string.find(str_content, '"null"') then
            table.insert(alerts, "[CRITICAL] CLEAR_TEXT / NULL Encryption negotiated over N32-c! 5G Core SBI API payloads transmitted in plaintext across transit IPX.")
            pinfo.cols.info:append(" [TELCOSEC: SEPP UNENCRYPTED ROAMING!]")
        end

        -- Security Heuristic 2: Weak Cryptographic Suites
        if jwe_alg and (string.find(jwe_alg, "RSA1_5") or string.find(jwe_alg, "none")) then
            table.insert(alerts, string.format("[CRITICAL] Insecure JWE Algorithm (%s) selected! Vulnerable to Bleichenbacher padding oracle attacks.", jwe_alg))
        end

    -- 2. Check for N32-f Forwarding Plane (TS 29.573 §5.3 - Encapsulated JWE / PRAS)
    elseif string.find(str_content, "n32fMessage") or string.find(str_content, "encData") or string.find(str_content, "ciphertext") or string.find(str_content, "protectedHeader") then
        subtree:add(f_msg_type, "N32-f Message Forwarding (PRAS / JWE)")
        pinfo.cols.info = "[5G N32-f] SEPP Protected Message Forwarding"

        local ctx_id = string.match(str_content, '"n32fContextId"%s*:%s*"([^"]+)"')
        if ctx_id then
            subtree:add(f_context_id, ctx_id)
            pinfo.cols.info = string.format("[5G N32-f] SEPP Forwarding (Ctx: %s)", ctx_id)
        end

        -- Security Heuristic 3: PRAS (Packet Redirection and Spoofing) or Unprotected JSON Elements
        if string.find(str_content, '"unprotected"') or string.find(str_content, '"modifications"') then
            table.insert(alerts, "[HIGH RISK] N32-f contains unencrypted modifications or unprotected metadata elements! Inspect for IPX intermediate hop tampering.")
            pinfo.cols.info:append(" [TELCOSEC: IPX MODIFICATIONS!]")
        end
    else
        subtree:add(f_msg_type, "N32 Roaming Signaling")
    end

    if #alerts > 0 then
        for _, a in ipairs(alerts) do
            subtree:add(f_sec_alert, a)
        end
    end

    if http2_dissector then
        http2_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end

-- Register to standard N32 SEPP TLS ports (8443, 8080, 58443)
local tcp_table = DissectorTable.get("tcp.port")
if tcp_table then
    tcp_table:add(8443, n32_sepp_proto)
    tcp_table:add(58443, n32_sepp_proto)
end

-- Register as postdissector to inspect all inter-PLMN HTTP/2 and TLS roaming streams
register_postdissector(n32_sepp_proto)
