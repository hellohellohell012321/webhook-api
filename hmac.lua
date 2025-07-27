-- BEGIN: HMAC-SHA256 in pure Lua (Roblox-compatible)
-- Source: Based on public domain implementations

local bit = bit32
local band, bor, bxor, bnot, rshift, lshift = bit.band, bit.bor, bit.bxor, bit.bnot, bit.rshift, bit.lshift

local function str2bytes(str)
	local bytes = {}
	for i = 1, #str do
		bytes[#bytes + 1] = string.byte(str, i)
	end
	return bytes
end

local function bytes2str(bytes)
	local str = ""
	for i = 1, #bytes do
		str = str .. string.char(bytes[i])
	end
	return str
end

local function tohex(bytes)
	local hex = ""
	for i = 1, #bytes do
		hex = hex .. string.format("%02x", bytes[i])
	end
	return hex
end

local function sha256(msg)
	local k = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
		0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
		0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
		0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
		0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
		0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
		0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
		0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
		0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	}

	local function ROTR(x,n)
		return rshift(x,n) + lshift(x,32-n)
	end

	local function sha256_compress(chunk, h)
		local w = {}
		for i = 1, 16 do
			local j = (i-1)*4+1
			w[i] = lshift(chunk[j],24) + lshift(chunk[j+1],16) + lshift(chunk[j+2],8) + chunk[j+3]
		end
		for i = 17, 64 do
			local s0 = bxor(ROTR(w[i-15],7), ROTR(w[i-15],18), rshift(w[i-15],3))
			local s1 = bxor(ROTR(w[i-2],17), ROTR(w[i-2],19), rshift(w[i-2],10))
			w[i] = (w[i-16] + s0 + w[i-7] + s1) % 2^32
		end

		local a,b,c,d,e,f,g,hh = table.unpack(h)

		for i = 1, 64 do
			local S1 = bxor(ROTR(e,6), ROTR(e,11), ROTR(e,25))
			local ch = bxor(band(e,f), band(bnot(e),g))
			local temp1 = (hh + S1 + ch + k[i] + w[i]) % 2^32
			local S0 = bxor(ROTR(a,2), ROTR(a,13), ROTR(a,22))
			local maj = bxor(band(a,b), band(a,c), band(b,c))
			local temp2 = (S0 + maj) % 2^32

			hh = g
			g = f
			f = e
			e = (d + temp1) % 2^32
			d = c
			c = b
			b = a
			a = (temp1 + temp2) % 2^32
		end

		h[1] = (h[1] + a) % 2^32
		h[2] = (h[2] + b) % 2^32
		h[3] = (h[3] + c) % 2^32
		h[4] = (h[4] + d) % 2^32
		h[5] = (h[5] + e) % 2^32
		h[6] = (h[6] + f) % 2^32
		h[7] = (h[7] + g) % 2^32
		h[8] = (h[8] + hh) % 2^32
	end

	local bytes = str2bytes(msg)
	local len = #bytes * 8

	bytes[#bytes+1] = 0x80
	while (#bytes % 64) ~= 56 do
		bytes[#bytes+1] = 0
	end

	for i = 56, 63 do
		bytes[#bytes+1] = 0
	end

	for i = 1, 8 do
		bytes[#bytes-8+i] = band(rshift(len, (8-i)*8), 0xFF)
	end

	local h = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	}

	for i = 1, #bytes, 64 do
		local chunk = {}
		for j = 0, 63 do
			chunk[#chunk+1] = bytes[i+j]
		end
		sha256_compress(chunk, h)
	end

	local digest = {}
	for i = 1, 8 do
		digest[#digest+1] = rshift(h[i],24) % 256
		digest[#digest+1] = rshift(h[i],16) % 256
		digest[#digest+1] = rshift(h[i],8) % 256
		digest[#digest+1] = h[i] % 256
	end

	return tohex(digest)
end

local function hmac_sha256(message, key)
	local blocksize = 64

	if #key > blocksize then
		key = sha256(key)
		key = bytes2str(str2bytes(key)) -- convert hex string back to raw string
	end

	while #key < blocksize do
		key = key .. string.char(0)
	end

	local o_key_pad = ""
	local i_key_pad = ""

	for i = 1, blocksize do
		local c = string.byte(key, i)
		o_key_pad = o_key_pad .. string.char(bxor(c, 0x5c))
		i_key_pad = i_key_pad .. string.char(bxor(c, 0x36))
	end

	local inner = sha256(i_key_pad .. message)
	inner = bytes2str(str2bytes(inner)) -- convert hex back to raw string for outer hash

	local outer = sha256(o_key_pad .. inner)
	return outer
end

return hmac_sha256
-- END MODULE
