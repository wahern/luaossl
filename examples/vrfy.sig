#!/usr/local/lua52/bin/lua
--
-- Example public-key signature verification.
--

local keytype, hash = ...

local openssl = require"openssl"
local pkey = require"openssl.pkey"
local digest = require"openssl.digest"

-- generate a public/private key pair
local function genkey(type)
	type = string.upper(type or (not openssl.NO_EC and "EC") or "RSA")

	if type == "RSA" then
		return pkey.new{ type = "RSA", bits = 1024 }
	elseif type == "DSA" then
		return pkey.new{ type = "DSA", bits = 1024 }
	else
		return pkey.new{ type = "EC", curve = "prime192v1" }
	end
end

local key = genkey(keytype)
if hash == nil then
	hash = key:getDefaultDigestName()
end

-- digest our message using an appropriate digest
local data = digest.new(hash)
data:update(... or "hello world")

-- generate a signature for our data
local sig = key:sign(data)

-- to prove verification works, instantiate a new object holding just
-- the public key
local pub = pkey.new(key:toPEM"public")

-- a utility routine to output our signature
local function tohex(b)
	local x = ""
	for i = 1, #b do
		x = x .. string.format("%.2x", string.byte(b, i))
	end
	return x
end

print("verified", pub:verify(sig, data))
print("key-type", pub:type())
print("hash-type", hash)
print("signature", tohex(sig))
