#!/usr/bin/env lua

local regress = require "regress"
local kdf = require "openssl.kdf"

local function hexstring(str)
	return (str:gsub("..", function(b) return string.char(tonumber(b, 16)) end))
end

-- Scrypt Example
regress.check(kdf.derive{
	type = "id-scrypt"; -- the nid short-name is id-scrypt
	pass = "";
	salt = "";
	N = 16;
	r = 1;
	p = 1;
	outlen = 64;
} == hexstring"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
	"scrypt output doesn't match test vector")

-- PBKDF2 Example
regress.check(kdf.derive{
	type = "PBKDF2";
	pass = "password";
	salt = "salt";
	iter = 1;
	md = "sha1";
	outlen = 20;
} == hexstring"0c60c80f961f0e71f3a9b524af6012062fe037a6",
	"PBKDF2 output doesn't match test vector")

-- TLS1-PRF Example
regress.check(kdf.derive{
	type = "TLS1-PRF";
	md = "md5-sha1";
	secret = hexstring"bded7fa5c1699c010be23dd06ada3a48349f21e5f86263d512c0c5cc379f0e780ec55d9844b2f1db02a96453513568d0";
	seed = "master secret"
		.. hexstring"e5acaf549cd25c22d964c0d930fa4b5261d2507fad84c33715b7b9a864020693"
		.. hexstring"135e4d557fdf3aa6406d82975d5c606a9734c9334b42136e96990fbd5358cdb2";
	outlen = 48;
} == hexstring"2f6962dfbc744c4b2138bb6b3d33054c5ecc14f24851d9896395a44ab3964efc2090c5bf51a0891209f46c1e1e998f62",
	"TLS1-PRF output doesn't match test vector")

regress.say "OK"
