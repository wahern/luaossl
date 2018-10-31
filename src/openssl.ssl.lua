local ssl = require"_openssl.ssl"

local pack = table.pack or function(...) return { n = select("#", ...); ... } end

ssl.interpose("setStore", function(self, store)
	self:setChainStore(store)
	self:setVerifyStore(store)
	return true
end)

-- Allow passing a vararg of ciphers, or an array
local setCipherList; setCipherList = ssl.interpose("setCipherList", function (self, ciphers, ...)
	if (...) then
		local ciphers_t = pack(ciphers, ...)
		ciphers = table.concat(ciphers_t, ":", 1, ciphers_t.n)
	elseif type(ciphers) == "table" then
		ciphers = table.concat(ciphers, ":")
	end
	return setCipherList(self, ciphers)
end)

-- Allow passing a vararg of curves, or an array
local setCurvesList = ssl.interpose("setCurvesList", nil)
if setCurvesList then
	ssl.interpose("setCurvesList", function (self, curves, ...)
		if (...) then
			local curves_t = pack(curves, ...)
			curves = table.concat(curves_t, ":", 1, curves_t.n)
		elseif type(curves) == "table" then
			curves = table.concat(curves, ":")
		end
		return setCurvesList(self, curves)
	end)
end

-- Allow passing a vararg of ciphersuites, or an array
local setCipherSuites = ssl.interpose("setCipherSuites", nil)
if setCipherSuites then
	ssl.interpose("setCipherSuites", function (self, ciphers, ...)
		if (...) then
			local ciphers_t = pack(ciphers, ...)
			ciphers = table.concat(ciphers_t, ":", 1, ciphers_t.n)
		elseif type(ciphers) == "table" then
			ciphers = table.concat(ciphers, ":")
		end
		return setCipherSuites(self, ciphers)
	end)
end

return ssl
