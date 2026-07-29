-- UDP port used for decoding AirTap 5G NAS log frames
local CONSTANT_UDP_PORT = 47929

local diag_5g_nas_protocol = Proto('qcdiag.log.5g_nas', 'Qualcomm Diag 5G NAS log')

local diag_5g_nas_fields = {
    ['packet_version'] = ProtoField.uint8('qcdiag.log.5g_nas.packet_version', 'Packet version', base.DEC),
    ['security_header'] = ProtoField.uint8('qcdiag.log.5g_nas.security_header', 'Security Header Type', base.HEX),
    ['proto_discriminator'] = ProtoField.uint8('qcdiag.log.5g_nas.proto_discriminator', 'Extended Protocol Discriminator', base.HEX),
    ['msg_type'] = ProtoField.uint8('qcdiag.log.5g_nas.msg_type', 'Message Type', base.HEX),
    ['msg_length'] = ProtoField.uint16('qcdiag.log.5g_nas.msg_length', 'Message Length', base.DEC)
}
diag_5g_nas_protocol.fields = diag_5g_nas_fields

function diag_5g_nas_protocol.dissector(buffer, packet, tree)
    local subtree = tree:add(diag_5g_nas_protocol, buffer(0, math.min(buffer:len(), 6)))

    if buffer:len() >= 4 then
        subtree:add_le(diag_5g_nas_fields.packet_version, buffer(0, 1))
        subtree:add_le(diag_5g_nas_fields.security_header, buffer(1, 1))
        subtree:add_le(diag_5g_nas_fields.proto_discriminator, buffer(2, 1))
        subtree:add_le(diag_5g_nas_fields.msg_type, buffer(3, 1))
    end

    if buffer:len() > 4 then
        Dissector.get('nas-5gs'):call(buffer(4):tvb(), packet, tree)
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(CONSTANT_UDP_PORT, diag_5g_nas_protocol)
