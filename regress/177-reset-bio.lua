#!/usr/bin/env lua

local regress = require "regress"

local ok, err

local key = regress.pkey.new()

-- generate a minimal certificate and export to DER
local x509 = regress.x509.new()
x509:setPublicKey(key)
x509:sign(key)
local x509_der = x509:tostring("DER")

ok, err = pcall(regress.x509.new, x509_der)
regress.check(ok, "failed to load DER certificate: %s", err)

-- generate a minimal crl and export to DER
local crl = regress.crl.new()
crl:sign(key)
local crl_der = crl:tostring("DER")

ok, err = pcall(regress.crl.new, crl_der)
regress.check(ok, "failed to load DER CRL: %s", err)

-- generate a minimal csr and export to DER
local csr = regress.csr.new()
csr:setPublicKey(key)
csr:sign(key)
local csr_der = csr:tostring("DER")

ok, err = pcall(regress.csr.new, csr_der)
regress.check(ok, "failed to load DER CSR: %s", err)

regress.say "OK"
