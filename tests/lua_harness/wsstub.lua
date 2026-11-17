-- Minimal Wireshark Lua API stub for offline dissector testing.
--
-- Purpose: load an AirTap .lua dissector outside Wireshark and invoke its
-- dissector() against synthetic packet bytes, so CI can catch runtime faults
-- (missing globals such as 'bit'/'bit32', nil indexing, bad tvb offsets) that
-- a syntax-only check cannot see. Globals in Lua resolve at call time, so a
-- dissector referencing an absent library loads cleanly and only fails when a
-- packet reaches the heuristic -- exactly the class of bug this catches.
--
-- This models only the surface the dissectors actually touch. It is a test
-- fixture, not a Wireshark reimplementation.

local M = {}

-- Everything written to the tree or the info column, for assertions.
local recorded = {}
function M.recorded() return table.concat(recorded, " || ") end
function M.reset() recorded = {} end

-- ---------------------------------------------------------------- columns
-- A column supports :append/:prepend/:set/:clear and tostring(). Dissectors
-- also assign a bare string (pinfo.cols.protocol = "GSM MM"), so the cols
-- table re-wraps any raw string assignment to keep method calls working.
local function mkcol(init)
    local buf = init or ""
    local c = {}
    function c:append(s) buf = buf .. tostring(s); recorded[#recorded + 1] = tostring(s); return c end
    function c:prepend(s) buf = tostring(s) .. buf; return c end
    function c:set(s) buf = tostring(s); recorded[#recorded + 1] = tostring(s); return c end
    function c:clear() buf = ""; return c end
    function c:fence() return c end
    function c:value() return buf end
    return setmetatable(c, {
        __tostring = function() return buf end,
        __concat = function(a, b) return tostring(a) .. tostring(b) end,
    })
end
M.mkcol = mkcol

-- -------------------------------------------------------------- ByteArray
-- Wireshark ByteArray surface used by the dissectors (:tohex, :len, :subset,
-- :get_index, tostring). Backed by a plain Lua string of raw bytes.
function M.bytearray(raw)
    local b = {}
    function b:len() return #raw end
    function b:tohex(lowercase, separator)
        local fmt = lowercase and "%02x" or "%02X"
        local out = {}
        for i = 1, #raw do out[#out + 1] = string.format(fmt, raw:byte(i)) end
        return table.concat(out, separator or "")
    end
    function b:raw() return raw end
    function b:get_index(i) return raw:byte(i + 1) end
    function b:subset(off, len) return M.bytearray(raw:sub(off + 1, off + len)) end
    function b:tvb() return M.tvb(raw) end
    return setmetatable(b, {
        __tostring = function() return b:tohex() end,
        __len = function() return #raw end,
        __concat = function(x, y) return tostring(x) .. tostring(y) end,
    })
end

-- ------------------------------------------------------------------- tvb
-- Byte-accurate tvb over a Lua string. Out-of-bounds access raises, mirroring
-- Wireshark, so tests surface offset bugs instead of silently passing.
function M.tvb(bytes)
    local tv
    local function rng(off, len)
        len = len or (#bytes - off)
        if off < 0 or len < 0 or off + len > #bytes then
            error(string.format("tvb out of bounds: off=%d len=%d buflen=%d", off, len, #bytes), 0)
        end
        local r = {}
        function r:uint()
            local v = 0
            for i = off + 1, off + len do v = v * 256 + bytes:byte(i) end
            return v
        end
        function r:le_uint()
            local v = 0
            for i = off + len, off + 1, -1 do v = v * 256 + bytes:byte(i) end
            return v
        end
        function r:uint64() return r:uint() end
        function r:int() return r:uint() end
        function r:len() return len end
        function r:string() return bytes:sub(off + 1, off + len) end
        function r:stringz() return (bytes:sub(off + 1, off + len):gsub("%z.*", "")) end
        -- Wireshark's :bytes() returns a ByteArray, not a string: dissectors
        -- chain :tohex() / :len() / :subset() on it, so model that object.
        function r:bytes() return M.bytearray(bytes:sub(off + 1, off + len)) end
        function r:raw() return bytes:sub(off + 1, off + len) end
        function r:range(o, l) return rng(off + (o or 0), l) end
        -- Wireshark's range:tvb() returns a NEW buffer re-based on the slice,
        -- so sub(0,1) is the slice's first byte, not the outer buffer's.
        -- Returning the outer tvb here silently shifted every offset in any
        -- dissector that delegates a sub-PDU.
        function r:tvb() return M.tvb(bytes:sub(off + 1, off + len)) end
        function r:offset() return off end
        function r:bitfield(b, n)
            local byte = bytes:byte(off + 1 + math.floor(b / 8)) or 0
            local shift = 8 - (b % 8) - (n or 1)
            return math.floor(byte / 2 ^ shift) % 2 ^ (n or 1)
        end
        return setmetatable(r, { __tostring = function() return r:raw() end })
    end

    tv = setmetatable({}, {
        __call = function(_, off, len)
            if off == nil then return rng(0, #bytes) end
            return rng(off, len)
        end,
    })
    function tv:len() return #bytes end
    function tv:captured_len() return #bytes end
    function tv:reported_len() return #bytes end
    function tv:range(o, l) return rng(o or 0, l) end
    function tv:bytes() return M.bytearray(bytes) end
    function tv:raw() return bytes end
    function tv:offset() return 0 end
    return tv
end

-- ------------------------------------------------------------------ tree
function M.tree()
    local node = {}
    local function record(...)
        for _, v in ipairs({ ... }) do
            local t = type(v)
            if t == "string" or t == "number" then
                recorded[#recorded + 1] = tostring(v)
            elseif t == "table" and getmetatable(v) and getmetatable(v).__tostring then
                recorded[#recorded + 1] = tostring(v)
            end
        end
        return node
    end
    node.add = function(self, ...) return record(...) end
    node.add_le = function(self, ...) return record(...) end
    node.add_packet_field = function(self, ...) return record(...) end
    node.append_text = function(self, t) return record(t) end
    node.prepend_text = function(self, t) return record(t) end
    node.set_text = function(self, t) return record(t) end
    node.add_expert_info = function(self, ...) return node end
    node.set_generated = function(self) return node end
    node.set_hidden = function(self) return node end
    node.set_len = function(self) return node end
    return node
end

-- ----------------------------------------------------------------- pinfo
function M.pinfo(opts)
    opts = opts or {}
    local cols = {}
    setmetatable(cols, {
        __index = function(t, k) local c = mkcol(""); t[k] = c; return c end,
        -- Re-wrap raw string assignments so later :append() still works.
        __newindex = function(t, k, v)
            if type(v) == "string" then rawset(t, k, mkcol(v)) else rawset(t, k, v) end
        end,
    })
    return {
        cols = cols,
        src = mkcol(opts.src or "10.0.0.1"),
        dst = mkcol(opts.dst or "10.0.0.2"),
        number = opts.number or 1,
        src_port = opts.src_port or 0,
        dst_port = opts.dst_port or 0,
        curr_proto = "",
        visited = false,
        can_desegment = 0,
        desegment_len = 0,
        desegment_offset = 0,
        private = {},
        p2p_dir = 0,
        rel_ts = 0,
        abs_ts = 0,
        match_uint = 0,
        port_type = 0,
    }
end

-- --------------------------------------------- install globals & load file
-- Returns the Proto object the dissector registered (or nil).
function M.install(env)
    env = env or _G
    local captured = { proto = nil }

    env.base = setmetatable({}, { __index = function(_, k) return k end })
    env.ftypes = setmetatable({}, { __index = function(_, k) return k end })
    env.ENC_BIG_ENDIAN, env.ENC_LITTLE_ENDIAN = 0, 1
    env.ENC_UTF_8, env.ENC_ASCII, env.ENC_NA, env.ENC_STRING = 0, 0, 0, 0
    env.PI_PROTOCOL, env.PI_MALFORMED, env.PI_SECURITY = 0, 0, 0
    env.PI_WARN, env.PI_NOTE, env.PI_ERROR, env.PI_CHAT = 0, 0, 0, 0

    env.ProtoField = setmetatable({}, {
        __index = function() return function(abbr) return { abbr = abbr } end end,
    })
    env.ProtoExpert = setmetatable({}, {
        __index = function() return function() return {} end end,
    })

    env.Proto = function(name, desc)
        local p = { name = name, description = desc, fields = {}, experts = {}, prefs = {} }
        setmetatable(p.prefs, { __index = function() return 0 end, __newindex = function() end })
        -- Heuristic dissectors register via proto:register_heuristic(list, fn);
        -- keep the callback so tests can drive it like a normal dissector.
        p.heuristics = {}
        function p:register_heuristic(list, fn)
            self.heuristics[#self.heuristics + 1] = { list = list, fn = fn }
            if not self.dissector then self.dissector = fn end
        end
        captured.proto = p
        return p
    end

    local function faketable()
        return {
            add = function() end,
            set = function() end,
            remove = function() end,
            add_for_decode_as = function() end,
            get_dissector = function() return nil end,
            try = function() end,
        }
    end
    env.DissectorTable = {
        get = function() return faketable() end,
        new = function() return faketable() end,
        list = function() return {} end,
    }
    env.Dissector = setmetatable({
        get = function() return { call = function() end } end,
        list = function() return {} end,
    }, { __call = function() return { call = function() end } end })

    env.Field = setmetatable({
        new = function() return function() return nil end end,
        list = function() return {} end,
    }, { __call = function() return function() return nil end end })

    env.register_postdissector = function() end
    env.register_menu = function() end
    env.ByteArray = setmetatable({ new = function() return {} end }, {})
    env.Address = { ip = function(s) return s end }
    env.NSTime = function() return 0 end
    env.TvbRange = {}
    env.Int64 = setmetatable({ new = function(v) return v end }, {})
    env.UInt64 = setmetatable({ new = function(v) return v end }, {})
    env.gui_enabled = function() return false end
    env.get_version = function() return "4.2.0 (airtap-test-stub)" end

    return captured
end

return M
