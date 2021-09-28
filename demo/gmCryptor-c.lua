local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string

local libName = 'gmCryptor-c'
local libType = 'dylib'
if jit.os == 'OSX' then
  libType = 'dylib'
  if jit.arch == 'arm64' then
    libName = libName .. '-darwin-arm64'
  else
    libName = libName .. '-darwin-x64'  
  end
end
if jit.os == 'Linux' then
  libType = 'so'
  libName = libName .. '-linux-x64'
end


local C = ffi.load("../release/gmCryptor-c-libs/"..libName.."."..libType)

ffi.cdef [[  
    char *sm3Hash(const unsigned char *message, size_t *out_len);
    char *sm4EcbEncrypt(const unsigned char *plain_text, const unsigned char *key_hex, size_t *out_len);
    char *sm4EcbDecrypt(const unsigned char *cipher_hex, const unsigned char *key_hex, size_t *out_len);
    char *sm4CbcEncrypt(const unsigned char *plain_text, const unsigned char *key_hex, const unsigned char *iv_hex, size_t *out_len);
    char *sm4CbcDecrypt(const unsigned char *cipher_hex, const unsigned char *key_hex, const unsigned char *iv_hex, size_t *out_len);
    char *sm2Encrypt(const unsigned char *plain_text, const unsigned char *pub_hex, const int mode, size_t *out_len);
    char *sm2Decrypt(const unsigned char *cipher_hex, const unsigned char *pri_hex, const int mode, size_t *out_len);
    char *sm2EncryptAsn1(const unsigned char *plain_text, const unsigned char *pub_hex, size_t *out_len);
    char *sm2DecryptAsn1(const unsigned char *cipher_hex, const unsigned char *pri_hex, size_t *out_len);
    char *sm2Signature(const unsigned char *message, const unsigned char *pri_hex, size_t *out_len);
    bool sm2VerifySign(const unsigned char *message, const unsigned char *sign_hex, const unsigned char *pub_hex);
]]

local _M = {_VERSION = '0.0.1'}

function _M.sm3Hash(s)
    if not s then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm3Hash(s,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm4EcbEncrypt(s, k)
    if not s then return nil end
    if not k then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm4EcbEncrypt(s,k,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm4EcbDecrypt(s, k)
    if not s then return nil end
    if not k then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm4EcbDecrypt(s,k,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm4CbcEncrypt(s, k, i)
    if not s then return nil end
    if not k then return nil end
    if not i then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm4CbcEncrypt(s, k, i,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm4CbcDecrypt(s, k, i)
    if not s then return nil end
    if not k then return nil end
    if not i then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm4CbcDecrypt(s, k, i,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm2Encrypt(s, k, m)
    if not s then return nil end
    if not k then return nil end
    if not m then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm2Encrypt(s,k,m,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm2Decrypt(s, k, m)
    if not s then return nil end
    if not k then return nil end
    if not m then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm2Decrypt(s, k, m,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm2EncryptAsn1(s, k)
    if not s then return nil end
    if not k then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm2EncryptAsn1(s,k,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm2DecryptAsn1(s, k)
    if not s then return nil end
    if not k then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm2DecryptAsn1(s,k,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm2Signature(s, k)
    if not s then return nil end
    if not k then return nil end
    local out_len = ffi.new("uint64_t[1]", 4)
    local out = C.sm2Signature(s,k,out_len)
    return ffi_str(out,out_len[0])
end

function _M.sm2VerifySign(s, k, d)
    if not s then return nil end
    if not k then return nil end
    if not d then return nil end
    local out = C.sm2VerifySign(s,k, d)
    return out
end

return _M
