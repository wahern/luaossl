#!/usr/bin/env lua

require"regress".export".*"

local ssl_context = require "openssl.ssl.context"

local value = {}
ssl_context.interpose("foo", value)
check(ssl_context.new().foo == value, "interpose failed")

require "openssl.ssl" -- Pick a module that doesn't get loaded by regress.lua
check(ssl_context.new().foo == value, "loading a module reset methods")
