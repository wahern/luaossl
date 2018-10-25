#!/usr/bin/env lua

local regress = require "regress"
local cqueues = require "cqueues"
local cs = require "cqueues.socket"
local openssl_ctx = require "openssl.ssl.context"

local cli_ctx, srv_ctx
local call_check = 0

cli_ctx = regress.getsslctx("TLS", false, false)
regress.check(cli_ctx.addCustomExtension, "Custom extension support not available")
local function c_add_ext(ssl, ext_type, context) -- luacheck: ignore 212
	call_check = call_check + 1
	return "from the client"
end
local function c_parse_ext(ssl, ext_type, context, data) -- luacheck: ignore 212
	call_check = call_check + 2
	assert(data == "from the server")
	return true
end
cli_ctx:addCustomExtension(5000,
	openssl_ctx.EXT_CLIENT_HELLO +
	openssl_ctx.EXT_TLS1_2_SERVER_HELLO +
	openssl_ctx.EXT_TLS1_3_SERVER_HELLO
, c_add_ext, c_parse_ext)


srv_ctx = regress.getsslctx("TLS", true)
local function s_add_ext(ssl, ext_type, context) -- luacheck: ignore 212
	call_check = call_check + 4
	return "from the server"
end
local function s_parse_ext(ssl, ext_type, context, data) -- luacheck: ignore 212
	call_check = call_check + 8
	assert(data == "from the client")
	return true
end
srv_ctx:addCustomExtension(5000,
	openssl_ctx.EXT_CLIENT_HELLO +
	openssl_ctx.EXT_TLS1_2_SERVER_HELLO +
	openssl_ctx.EXT_TLS1_3_SERVER_HELLO
, s_add_ext, s_parse_ext)


local srv, cli = regress.check(cs.pair(cs.SOCK_STREAM))
local main = regress.check(cqueues.new())
main:wrap(function ()
	regress.check(cli:starttls(cli_ctx))
end)
main:wrap(function ()
	regress.check(srv:starttls(srv_ctx))
end)
regress.check(main:loop())

regress.check(call_check == 15, "callback count doesn't match")
regress.say "OK"
