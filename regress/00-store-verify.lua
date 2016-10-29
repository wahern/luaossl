#!/usr/bin/env lua

require"regress".export".*"

local st = store.new()

local ca_key, ca_crt = genkey()
st:add(ca_crt)

local key, crt = genkey("RSA", ca_key, ca_crt)

local ok, proof_or_reason = st:verify(crt)
check(ok, "%s", proof_or_reason)

--for _,crt in pairs(proof_or_reason) do
--	print(crt:text())
--end

say"OK"
