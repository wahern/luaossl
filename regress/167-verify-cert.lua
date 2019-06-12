#!/usr/bin/env lua

local regress = require "regress"

if (regress.openssl.OPENSSL_VERSION_NUMBER and regress.openssl.OPENSSL_VERSION_NUMBER < 0x10002000)
	or (regress.openssl.LIBRESSL_VERSION_NUMBER and regress.openssl.LIBRESSL_VERSION_NUMBER < 0x20705000)
then
	-- skipping test due to different behaviour in earlier OpenSSL versions
	return
end

local params = regress.verify_param.new()
params:setDepth(0)

local ca_key, ca_crt = regress.genkey()
do -- should fail as no trust anchor
	regress.check(not ca_crt:verify({params=params, chain=nil, store=nil}))
end

local store = regress.store.new()
store:add(ca_crt)
do -- should succeed as cert is in the store
	regress.check(ca_crt:verify({params=params, chain=nil, store=store}))
end

local intermediate_key, intermediate_crt = regress.genkey(nil, ca_key, ca_crt)
do -- should succeed as ca cert is in the store
	regress.check(intermediate_crt:verify({params=params, chain=nil, store=store}))
end

local _, crt = regress.genkey(nil, intermediate_key, intermediate_crt)
do -- should fail as intermediate cert is missing
	regress.check(not crt:verify({params=params, chain=nil, store=store}))
end

local chain = regress.chain.new()
chain:add(intermediate_crt)
do -- should fail as max depth is too low
	regress.check(not crt:verify({params=params, chain=chain, store=store}))
end

params:setDepth(1)
do -- should succeed
	regress.check(crt:verify({params=params, chain=chain, store=store}))
end

regress.say "OK"
