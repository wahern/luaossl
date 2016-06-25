local auxlib = require"openssl.auxlib"
local pkey = require "openssl.pkey"
local x509_csr = require"_openssl.x509.csr"
local x509_altname = require"openssl.x509.altname"
local x509_name = require"openssl.x509.name"

local _basename = arg and arg[0] and arg[0]:match"([^/]+)$" or "UNKNOWN"

local function cluck(fmt, ...)
	io.stderr:write(_basename, ": ", string.format(fmt, ...), "\n")
end

local function croak(fmt, ...)
	io.stderr:write(_basename, ": ", string.format(fmt, ...), "\n")
	os.exit(1)
end

local function OK()
	cluck("OK")
	return true
end

local _testno = 0
local function testnames(altnames, expected)
	local matched = {}

	_testno = _testno + 1

	for type,data in auxlib.pairs(altnames) do
		local found

		for i,e in ipairs(expected) do
			if not matched[i] and e.type == type and e.data == data then
				cluck("expected match #%d.%d found (%s=%s)", _testno, i, type,data)

				matched[i] = true
				found = true
			end
		end

		if not found then
			return false, string.format("extra name in test #%d (%s=%s)", _testno, type, data)
		end
	end

	for i,e in ipairs(expected) do
		if not matched[i] then
			return false, string.format("expected match #%d.%d not found (%s=%s)", _testno, i, e.type, e.data)
		end
	end

	return true
end

local function checknames(altnames, expected)
	local ok, why = testnames(altnames, expected)

	if not ok then
		croak(why or "UNKNOWN")
	end

	return true
end

key = pkey.new({ bits = 4096 })

data = [[
-----BEGIN CERTIFICATE REQUEST-----
MIIFQjCCAyoCAQAwUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1OMRQwEgYDVQQH
DAtNaW5uZWFwb2xpczEhMB8GA1UECwwYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVk
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4sXzE3GQtpFKiuGe389k
MB0OaGXQxiI/yl6zm9PyYWe5aMpx1THDVhkWXemDVkduEqtLfa8GSNT0ps3BPdTx
qxNwZ3J9xiVfNZZYO5ZSxs1g32M1lw20wIezLpbQ1ggyt01o9VTQDY6kA+D0G87B
4FtIZxVaXM2z5HVaGYyivxAygDukDsO+RU0NC9mYOfAP4rt/u/xp8LsW0b4aIFqx
gPcBZj92B+Wi2B4sKSe1m5kMfmh+e8v981hbY7V8FUMebB63iRGF6GU4kjXiMMW6
gSoc+usq9li8VxjxPngql9pyLqFIa/2gW0c9sKKB2X9tB0nmudjAUrjZjHZEDlNr
yx15JHhEIT31yP9xGQpy5H+jBldp/shqaV4Alsou9Hn9W71ap7VHOWLrIcaZGKTn
CVSSYPygn4Rm8Cgwbv5mP6G+SqGHAFqirEysAARUFxsjBLlkNaVFOA38l2cufH8n
1NE/B4iOG/ETvQDR/aKrbyKKo2k/hO941h3J9pwJcCikE0NsRcH6WAm8ifJ0Zd/q
u8fqI8g9mYPbMWy11+njnfNOVFVhNOmM1/ZM66ac9zgGYncaHu4UzYnvWw75tDbF
vA+oIJlcxBUtWeTcYRf4xEcRL8IcHEwh1BZq7bgP42Wu+0aBuaa3eYXNBApCNP39
QmnHlo0iGH2rVeOfcq/wULcCAwEAAaCBqTCBpgYJKoZIhvcNAQkOMYGYMIGVMAkG
A1UdEwQCMAAwCwYDVR0PBAQDAgXgMHsGA1UdEQR0MHKCE3NlcnZlcjEuZXhhbXBs
ZS5jb22CEG1haWwuZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLmNvbYITd3d3LnN1
Yi5leGFtcGxlLmNvbYIObXguZXhhbXBsZS5jb22CE3N1cHBvcnQuZXhhbXBsZS5j
b20wDQYJKoZIhvcNAQEFBQADggIBAMiFPtDKVsy4HBhVkHSnbbIl41baaGGFjI/O
MG8fI7P9jplq5rNZcLxSW2zLzMVuYzCoC+q5roRE5zVVyJlB+5dY0A8e2xKaWVOT
AB9WvgepPvXDoGNViMBoX/idj3J2BU3e/cX08QWRPjKigwQWQWvUGsZYitGJv+Yv
/LbIDlxr8Jr+1Txcm1EdXcff6Owlh6Nu59bgCMRdZvABmWfU5ULmUDTJnmc3P9St
onz07v8ku8/XL7wwOfLJWVSVOk7RONySIJiPfVkgrU3YWiT64JaluDbFEIwnEgJS
04xL6Pl66bADXCaeG3pZ8ypCs41+4bqFvCnOYma0Sk8fv8hSCWvJfMQI+nQslPJu
UuGK4C4EEnYvoh/Qs/XEshfrVaNcG0zER3XtsRPAjhZjTPTcRgEjpOI0w3TJAvlN
LSQV4mXN6E2bcU+cRYvNSgqITwJ7c6wpsONwApIQwFryLsFSCHaIdSLpAZbEPNEW
UPa3uWXk5lWrBBPPkxyPbt8D3zpzahY4ycYEFKdz8MLdgA7pDalI2XpwgmoUybkw
AJnsFg7fnFc03R4FsqxCqvbRYj3Bccb8Uhg1zTeXU+7nxjP2yYdT+In16L9SYOsU
4ozEPqnGY9aI11i6C7hBwrUTvHYD6ZSDlylsUXKw/VZXQvS3+C0h6NuRmjBx8jNU
RG1EyxL4
-----END CERTIFICATE REQUEST-----
]]

-- baseline
do
	local expected = {
		{ type = "DNS", data = "server1.example.com" },
		{ type = "DNS", data = "mail.example.com" },
		{ type = "DNS", data = "www.example.com" },
		{ type = "DNS", data = "www.sub.example.com" },
		{ type = "DNS", data = "mx.example.com" },
		{ type = "DNS", data = "support.example.com" },
	}

	checknames((x509_csr.new(data)):getSubjectAlt(), expected)
end

-- modifying existing altnames
do
	local expected = {
		{ type = "DNS", data = "foo.com" },
		{ type = "DNS", data = "*.foo.com" },
	}

	local csr = x509_csr.new(data)
	local gn = x509_altname.new()
	gn:add("DNS", "foo.com")
	gn:add("DNS", "*.foo.com")
	csr:setSubjectAlt(gn)
	csr:setPublicKey(key)
	csr:sign(key)

	-- check modified object
	checknames(csr:getSubjectAlt(), expected)
	-- check after a round-trip through PEM
	checknames(x509_csr.new(tostring(csr)):getSubjectAlt(), expected)
end	

-- adding altnames where none existed 
do
	local expected = {
		name = {
			{ type = "CN", data = "example.com" },
		},
		altname = {
			{ type = "DNS", data = "foo.com" },
			{ type = "DNS", data = "*.foo.com" },
		},
	}

	local csr = x509_csr.new()
	local name = x509_name.new()
	name:add("CN", "example.com")
	csr:setSubject(name)
	local gn = x509_altname.new()
	gn:add("DNS", "foo.com")
	gn:add("DNS", "*.foo.com")
	csr:setSubjectAlt(gn)
	csr:setPublicKey(key)
	csr:sign(key)
  
	checknames(csr:getSubject(), expected.name)
	checknames(csr:getSubjectAlt(), expected.altname)

	local csr1 = x509_csr.new(tostring(csr))
	checknames(csr1:getSubject(), expected.name)
	checknames(csr1:getSubjectAlt(), expected.altname)
end

return OK()

