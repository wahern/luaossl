local ssl = require"_openssl.ssl"

local pack = table.pack or function(...) return { n = select("#", ...); ... } end

ssl.interpose("setStore", function(self, store)
	self:setChainStore(store)
	self:setVerifyStore(store)
	return true
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

return ssl
