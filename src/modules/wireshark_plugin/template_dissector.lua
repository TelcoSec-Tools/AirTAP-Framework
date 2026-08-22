-- TelcoSec.net - Wireshark Lua Dissector Template
-- Usage: Copy this template and modify it for your specific telecom protocol.

-- 1. Define the protocol
local ok, custom_proto = pcall(Proto, "CustomTelco", "Custom Telecom Protocol")
if not ok or not custom_proto then return end

-- 2. Define the protocol fields (these will appear in the packet details pane)
local f_msg_type = ProtoField.uint8("custom_telco.msg_type", "Message Type", base.DEC)
local f_length   = ProtoField.uint16("custom_telco.length", "Length", base.DEC)
local f_payload  = ProtoField.string("custom_telco.payload", "Payload")

-- Register the fields to the protocol
custom_proto.fields = { f_msg_type, f_length, f_payload }

-- 3. Define the dissect function
-- tvb (Testy Virtual Buffer) contains the packet payload
-- pinfo contains packet information (source, dest, etc.)
-- tree is the root of the packet details pane
function custom_proto.dissector(tvb, pinfo, tree)
    -- Check if the packet is long enough (e.g., at least 3 bytes for our header)
    if tvb:len() < 3 then return end

    -- Set the protocol column in the packet list pane
    pinfo.cols.protocol = custom_proto.name

    -- Create a subtree for our protocol
    local subtree = tree:add(custom_proto, tvb(), "Custom Telecom Protocol Data")

    -- Extract data from the buffer and add it to the subtree
    -- tvb(offset, length)
    local msg_type = tvb(0, 1):uint()
    subtree:add(f_msg_type, tvb(0, 1))
    
    local length = tvb(1, 2):uint()
    subtree:add(f_length, tvb(1, 2))

    -- Add a generic payload field if there's data left
    if tvb:len() > 3 then
        subtree:add(f_payload, tvb(3, tvb:len() - 3))
    end
    
    -- Example of adding conversational/informational info to the Info column
    pinfo.cols.info = string.format("MsgType: %d, Len: %d", msg_type, length)
end

-- 4. Hook the dissector into a specific port (e.g., UDP 9999)
-- Adjust according to your protocol's underlying transport layer
local udp_port = DissectorTable.get("udp.port")
udp_port:add(9999, custom_proto)

-- Alternatively, register for TCP:
-- local tcp_port = DissectorTable.get("tcp.port")
-- tcp_port:add(8888, custom_proto)
