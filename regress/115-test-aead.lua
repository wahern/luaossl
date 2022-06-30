local regress = require "regress";
local openssl = require "openssl";
local cipher = require "openssl.cipher"


-- Test AES-256-GCM
local key = "abcdefghijklmnopabcdefghijklmnop"
local iv = "123456123456"
local message = "My secret message"

function test_aead(params)
	local c = cipher.new(params.cipher):encrypt(key, iv)

	local encrypted = c:update(message)
	regress.check(encrypted)
	regress.check(c:final(), "fail final encrypt")

	local tag = assert(c:getTag(params.tag_length))
	regress.check(tag and #tag == params.tag_length)


	-- Now for the decryption
	local d = cipher.new(params.cipher):decrypt(key, iv)
	d:setTag(tag);

	local decrypted = d:update(encrypted)
	regress.check(decrypted == message, "decrypted message doesn't match")
	regress.check(d:final(), "fail final decrypt")
end

test_aead {
	cipher = "aes-256-gcm";
	tag_length = 16;
}

test_aead {
	cipher = "aes-256-ccm";
	tag_length = 12;
}
