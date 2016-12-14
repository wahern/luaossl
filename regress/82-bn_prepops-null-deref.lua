#!/usr/bin/env lua
--
-- The following code could trigger a NULL dereference.
--
-- 	bn_prepops(lua_State *L, BIGNUM **r, BIGNUM **a, BIGNUM **b, _Bool commute) {
-- 		...
-- 		*b = checkbig(L, 2, &lvalue);
-- 		...
-- 	}
--
-- 	bn_sqr(lua_State *L) {
-- 		BIGNUM *r, *a;
--
-- 		bn_prepops(L, &r, &a, NULL, 1);
-- 		...
-- 	}
-- 
-- Caught by clang static analyzer. This was introduced with a patch adding
-- the :sqr method. This should have been caught sooner as the :sqr method
-- couldn't have possibly ever worked--a missing or non-numeric second
-- operand would have thrown a Lua error, and a numeric second operand
-- triggers the NULL dereference.
--
require"regress".export".*"

local function N(i) return bignum.new(i) end

-- passing a second numeric operand triggered a NULL dereference
local r = N(4):sqr(0)


-- check minimal functionality of all our operators
local tests = {
	{ op = "add", a = 1, b = 1, r = 2 },
	{ op = "sub", a = 2, b = 1, r = 1 },
	{ op = "mul", a = 2, b = 2, r = 4 },
	{ op = "idiv", a = 4, b = 2, r = 2 },
	{ op = "mod", a = 4, b = 2, r = 0 },
	{ op = "exp", a = 2, b = 2, r = 4 },
	{ op = "sqr", a = 4, b = nil, r = 16 },
	{ op = "gcd", a = 47, b = 3, r = 1 },
}

local function tdescr(t)
	return string.format("%s(%s, %s)", t.op, tostring(t.a), tostring(t.b))
end

for i,t in ipairs(tests) do
	local a = N(t.a)
	local op = a[t.op]
	local ok, r

	if t.b then
		ok, r = pcall(op, a, t.b)
	else
		ok, r = pcall(op, a)
	end

	check(ok, "failed test #%d (%s) (%s)", i, tdescr(t), r)
	check(N(r) == N(t.r), "failed test #%d (%s) (expected %s, got %s)", i, tdescr(t), tostring(t.r), tostring(r))
end

say"OK"
