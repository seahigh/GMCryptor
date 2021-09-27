local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string

local libName = 'gmCryptor-go'
local libType = 'dylib'
if jit.os == 'OSX' then
  libType = 'dylib'
  if jit.arch == 'arm64' then
    libName = libName .. '-darwin-arm64'
  else
    libName = libName .. '-darwin-x64'  
  end
end

local C = ffi.load("../release/gmCryptor-go-libs/"..libName.."."..libType)

ffi.cdef [[  
    extern char* sm3Hash(char* data);
    extern char* sm2Encrypt(char* data, char* publicKey, int mode);
    extern char* sm2Decrypt(char* encData, char* privateKey, int mode);
    extern char* sm2EncryptAsn1(char* data, char* publicKey);
    extern char* sm2DecryptAsn1(char* encData, char* privateKey);
    extern char* sm4EcbEncrypt(char* data, char* sm4Key);
    extern char* sm4EcbDecrypt(char* encData, char* sm4Key);
    extern char* sm4CbcEncrypt(char* data, char* sm4Key, char* sm4Iv);
    extern char* sm4CbcDecrypt(char* encData, char* sm4Key, char* sm4Iv);
    extern char* sm2Signature(char* data, char* privateKey);
    extern _Bool sm2VerifySign(char* data, char* signData, char* publicKey);
    extern char* cipherUnmarshal(char* data, int mode);
]]

local _M = {_VERSION = '0.0.1'}

function _M.sm3Hash(s)
    if not s then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local out = C.sm3Hash(data)
    return ffi_str(out)
end

function _M.sm4EcbEncrypt(s, k)
    if not s then return nil end
    if not k then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local key = ffi.new("char[?]", #k + 1)
    ffi.copy(key, k)
    local out = C.sm4EcbEncrypt(data,key)
    return ffi_str(out)
end

function _M.sm4EcbDecrypt(s, k)
    if not s then return nil end
    if not k then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local key = ffi.new("char[?]", #k + 1)
    ffi.copy(key, k)
    local out = C.sm4EcbDecrypt(data,key)
    return ffi_str(out)
end

function _M.sm4CbcEncrypt(s, k, i)
    if not s then return nil end
    if not k then return nil end
    if not i then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local key = ffi.new("char[?]", #k + 1)
    ffi.copy(key, k)
    local iv = ffi.new("char[?]", #i + 1)
    ffi.copy(iv, i)
    local out = C.sm4CbcEncrypt(data,key,iv)
    return ffi_str(out)
end

function _M.sm4CbcDecrypt(s, k, i)
    if not s then return nil end
    if not k then return nil end
    if not i then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local key = ffi.new("char[?]", #k + 1)
    ffi.copy(key, k)
    local iv = ffi.new("char[?]", #i + 1)
    ffi.copy(iv, i)
    local out = C.sm4CbcDecrypt(data,key,iv)
    return ffi_str(out)
end

function _M.sm2Encrypt(s, k, m)
    if not s then return nil end
    if not k then return nil end
    if not m then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local key = ffi.new("char[?]", #k + 1)
    ffi.copy(key, k)
    local out = C.sm2Encrypt(data,key,m)
    return ffi_str(out)
end

function _M.sm2Decrypt(s, k, m)
    if not s then return nil end
    if not k then return nil end
    if not m then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local key = ffi.new("char[?]", #k + 1)
    ffi.copy(key, k)
    local out = C.sm2Decrypt(data,key,m)
    return ffi_str(out)
end

function _M.sm2EncryptAsn1(s, k)
    if not s then return nil end
    if not k then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local key = ffi.new("char[?]", #k + 1)
    ffi.copy(key, k)
    local out = C.sm2EncryptAsn1(data,key)
    return ffi_str(out)
end

function _M.sm2DecryptAsn1(s, k)
    if not s then return nil end
    if not k then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local key = ffi.new("char[?]", #k + 1)
    ffi.copy(key, k)
    local out = C.sm2DecryptAsn1(data,key)
    return ffi_str(out)
end

function _M.sm2Signature(s, k)
    if not s then return nil end
    if not k then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s) 
    local pri = ffi.new("char[?]", #k + 1)
    ffi.copy(pri, k)
    local out = C.sm2Signature(data,pri)
    return ffi_str(out)
end

function _M.sm2VerifySign(s, k, d)
    if not s then return nil end
    if not k then return nil end
    if not d then return nil end
    local data = ffi.new("char[?]", #s + 1)
    ffi.copy(data, s)
    local sign = ffi.new("char[?]", #k + 1)
    ffi.copy(sign, k)
    local pub = ffi.new("char[?]", #d + 1)
    ffi.copy(pub, d)
    local out = C.sm2VerifySign(data,sign,pub)
    return out
end

return _M
