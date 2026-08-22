-- TelcoSec.net - GSM COMP128-1/2/3 Weak RAND & SIM Ki Extraction Hunter
-- Target Standard: 3GPP TS 24.008 Section 9.2.2 / TS 43.020 (Security-related network functions)
-- Description: Dissects 128-bit (16-byte) RAND challenges in MM Authentication Request messages.
--              Computes Shannon entropy and Hamming distance between consecutive RAND challenges,
--              detecting COMP128-1 chosen-challenge attacks ($RAND_n = RAND_{n-1} + 1$), static RAND replays,
--              and linear sequence attacks deployed by IMSI Catchers to extract the 128-bit SIM root key (Ki).

local ok, gsm_comp128_proto = pcall(Proto, "gsm_comp128_sec", "TelcoSec GSM COMP128 Weak RAND & Ki Extraction Analyzer")
if not ok or not gsm_comp128_proto then return end

-- Protocol fields
local f_rand_bytes      = ProtoField.bytes("gsm_comp128_sec.rand", "RAND Challenge (128-bit / 16-byte)")
local f_rand_entropy    = ProtoField.float("gsm_comp128_sec.entropy", "RAND Shannon Entropy (bits/byte, max 8.0)")
local f_rand_delta      = ProtoField.int64("gsm_comp128_sec.delta", "Linear RAND Increment (Offset)")
local f_hamming_dist    = ProtoField.uint8("gsm_comp128_sec.hamming", "Hamming Distance to Previous RAND (bits)")
local f_attack_vector   = ProtoField.string("gsm_comp128_sec.attack", "Cryptographic Attack Classification")
local f_sec_alert       = ProtoField.string("gsm_comp128_sec.alert", "TelcoSec Cryptographic Alert")

gsm_comp128_proto.fields = {
    f_rand_bytes,
    f_rand_entropy,
    f_rand_delta,
    f_hamming_dist,
    f_attack_vector,
    f_sec_alert
}

-- Calculate Shannon Entropy over 16-byte RAND
local function calculate_entropy(tvb_rand)
    local len = tvb_rand:len()
    if len == 0 then return 0.0 end

    local counts = {}
    for i = 0, 255 do counts[i] = 0 end

    for i = 0, len - 1 do
        local b = tvb_rand(i, 1):uint()
        counts[b] = counts[b] + 1
    end

    local entropy = 0.0
    for i = 0, 255 do
        if counts[i] > 0 then
            local p = counts[i] / len
            entropy = entropy - (p * (math.log(p) / math.log(2)))
        end
    end
    return entropy
end

-- Calculate bitwise Hamming Distance between two 16-byte RANDs
local function calculate_hamming(tvb_cur, prev_bytes)
    if not prev_bytes or #prev_bytes < 16 or tvb_cur:len() < 16 then return 0 end
    local dist = 0
    for i = 0, 15 do
        local b1 = tvb_cur(i, 1):uint()
        local b2 = string.byte(prev_bytes, i + 1)
        local xor_val = bit.bxor(b1, b2)
        while xor_val > 0 do
            if bit.band(xor_val, 1) == 1 then dist = dist + 1 end
            xor_val = bit.rshift(xor_val, 1)
        end
    end
    return dist
end

-- State tracking for consecutive RAND challenges
local last_rand_state = {
    bytes = nil,
    count = 0,
    linear_streak = 0
}

function gsm_comp128_proto.dissector(tvb, pinfo, tree)
    -- Requires 16 bytes for 128-bit RAND
    if tvb:len() < 16 then return end

    local entropy = calculate_entropy(tvb(0, 16))
    local hex_rand = tostring(tvb(0, 16):bytes():tohex())

    local subtree = tree:add(gsm_comp128_proto, tvb(0, 16), string.format("COMP128 RAND Security Analysis (Entropy: %.2f bits)", entropy))
    subtree:add(f_rand_bytes, tvb(0, 16))
    subtree:add(f_rand_entropy, entropy)

    local is_attack = false

    -- 1. Static / Replayed RAND Attack
    if last_rand_state.bytes == hex_rand then
        last_rand_state.count = last_rand_state.count + 1
        subtree:add(f_attack_vector, "Static RAND Replay Attack")
        subtree:add(f_sec_alert, string.format("[CRITICAL] Identical RAND challenge repeated (%d times)! Rogue base station executing authentication replay.", last_rand_state.count))
        pinfo.cols.info:append(" [TELCOSEC: REPLAYED RAND ATTACK!]")
        is_attack = true
    else
        -- 2. Chosen-Challenge / Linear Incremental RAND Attack
        if last_rand_state.bytes ~= nil then
            local hamming = calculate_hamming(tvb(0, 16), last_rand_state.raw_bytes)
            subtree:add(f_hamming_dist, hamming)

            -- Check if Hamming distance is suspiciously low (< 8 bits diff across 128 bits)
            if hamming <= 4 and hamming > 0 then
                last_rand_state.linear_streak = last_rand_state.linear_streak + 1
                if last_rand_state.linear_streak >= 2 then
                    subtree:add(f_attack_vector, "COMP128-1 Chosen-Challenge Ki Extraction Attack")
                    subtree:add(f_sec_alert, "[CRITICAL] Highly correlated / sequential RAND challenges detected! IMSI Catcher actively exploiting COMP128-1 partition vulnerability to extract SIM root key (Ki).")
                    pinfo.cols.info:append(" [TELCOSEC: COMP128 Ki EXTRACTION ATTACK!]")
                    is_attack = true
                end
            else
                last_rand_state.linear_streak = 0
            end
        end

        -- 3. Low-Entropy / Predictable Pseudorandom Generator (PRNG) Fault
        if entropy < 2.5 then
            subtree:add(f_attack_vector, "Low-Entropy PRNG Challenge")
            subtree:add(f_sec_alert, string.format("[WARNING] Exceptionally low RAND entropy (%.2f bits/byte)! Predictable challenge PRNG in BTS.", entropy))
            is_attack = true
        end

        last_rand_state.bytes = hex_rand
        last_rand_state.raw_bytes = tvb(0, 16):raw()
        last_rand_state.count = 1
    end

    if not is_attack then
        subtree:add(f_attack_vector, "Normal Pseudorandom Challenge (Authentic GSM Network)")
    end
end
