package.path = package.path .. ';../lua/?.lua'

local lua2go = require('lua2go')
local ffi = require('ffi')

local libName = 'GMCryptor'
local libType = 'dylib'
if jit.os == 'OSX' then
  libType = 'dylib'
  if jit.arch == 'arm64' then
    libName = libName .. '-darwin-arm64'
  else
    libName = libName .. '-darwin-x64'  
  end
end

local gmCryptor = lua2go.Load('./'..libName..'.'..libType)
 
lua2go.Externs[[
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

local testStr = "{name: \"Seahigh DX\", nick: \"Seahigh DX\"}"

local pubStr = "04efb77dc4e6545b0379901e3a8c656d0ef2623fd00ccab5afa8631f676715d679d89aa792f3b3a2bad5cfa0d30f30f1fb6e5e8ca11a0a3dcd714330a30f16e017"
local priStr = "ac615b172f8bbc223de2f631d9c803e9a9b6dea9df81b1330d02fd9a874b44cf"

local sm4KeyStr = "996ce17f6abc9fe126b57aa5f1d8c92c"
local sm4IvStr = "504f1a1f80d40c760c74bd5257124dc9"

local N = 1

local data = ffi.new("char[?]", #testStr + 1)
ffi.copy(data, testStr)

local pub = ffi.new("char[?]", #pubStr + 1)
ffi.copy(pub, pubStr)

local pri = ffi.new("char[?]", #priStr + 1)
ffi.copy(pri, priStr)

local sm4key = ffi.new("char[?]", #sm4KeyStr + 1)
ffi.copy(sm4key, sm4KeyStr)

local sm4iv = ffi.new("char[?]", #sm4IvStr + 1)
ffi.copy(sm4iv, sm4IvStr)

local sm3Data = lua2go.ToLua(gmCryptor.sm3Hash(data)) 
local starttime = os.clock(); 
for i = 1, N do
    lua2go.ToLua(gmCryptor.sm3Hash(data)) 
end
print(string.format("SM3摘要 : %.4f", os.clock() - starttime) .. "  "..sm3Data);

local enData = lua2go.ToLua(gmCryptor.sm2Encrypt(data,pub,0)) 
local starttime = os.clock();
for i = 1, N do
   lua2go.ToLua(gmCryptor.sm2Encrypt(data,pub,0)) 
end
print(string.format("SM2[C1C3C2]加密 : %.4f", os.clock() - starttime).. "  "..enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmCryptor.sm2Decrypt(en,pri,0)) 
 
local starttime = os.clock(); 
for i = 1, N do
    lua2go.ToLua(gmCryptor.sm2Decrypt(en,pri,0)) 
end
print(string.format("SM2[C1C3C2]解密 : %.4f", os.clock() - starttime).. "  "..deData);

local enData = lua2go.ToLua(gmCryptor.sm2Encrypt(data,pub,1)) 
local starttime = os.clock();
for i = 1, N do
   lua2go.ToLua(gmCryptor.sm2Encrypt(data,pub,1)) 
end
print(string.format("SM2[C1C2C3]加密 : %.4f", os.clock() - starttime).. "  "..enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmCryptor.sm2Decrypt(en,pri,1)) 
 
local starttime = os.clock(); 
for i = 1, N do
    lua2go.ToLua(gmCryptor.sm2Decrypt(en,pri,1)) 
end
print(string.format("SM2[C1C2C3]解密 : %.4f", os.clock() - starttime).. "  "..deData);


local enData = lua2go.ToLua(gmCryptor.sm2EncryptAsn1(data,pub)) 
local starttime = os.clock(); 
for i = 1, N do
   lua2go.ToLua(gmCryptor.sm2EncryptAsn1(data,pub)) 
end
print(string.format("SM2[Asn1]加密 : %.4f", os.clock() - starttime).. "  "..enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmCryptor.sm2DecryptAsn1(en,pri)) 
 
local starttime = os.clock(); 
for i = 1, N do
    lua2go.ToLua(gmCryptor.sm2DecryptAsn1(en,pri)) 
end
print(string.format("SM2[Asn1]解密 : %.4f", os.clock() - starttime).. "  "..deData);

local sm2Sign = lua2go.ToLua(gmCryptor.sm2Signature(data,pri)) 
local starttime = os.clock(); 
for i = 1, N do
   lua2go.ToLua(gmCryptor.sm2Signature(data,pri)) 
end
print(string.format("SM2加签 : %.4f", os.clock() - starttime).. "  ".. sm2Sign);

local sign = ffi.new("char[?]", #sm2Sign + 1)
ffi.copy(sign, sm2Sign)

local veri = lua2go.ToLua(gmCryptor.sm2VerifySign(data,sign,pub));

local starttime = os.clock(); 

for i = 1, N do
  lua2go.ToLua(gmCryptor.sm2VerifySign(data,sign,pub));
end
print(string.format("SM2验签 : %.4f", os.clock() - starttime).. "  ".. tostring(veri));

local enData = lua2go.ToLua(gmCryptor.sm4EcbEncrypt(data,sm4key))

local starttime = os.clock(); 
for i = 1, N do
   lua2go.ToLua(gmCryptor.sm4EcbEncrypt(data,sm4key)) 
end
print(string.format("SM4[ECB]加密 : %.4f", os.clock() - starttime).. "  ".. enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmCryptor.sm4EcbDecrypt(en,sm4key))

local starttime = os.clock(); 
for i = 1, N do
  lua2go.ToLua(gmCryptor.sm4EcbDecrypt(en,sm4key)) 
end

print(string.format("SM4[ECB]解密 : %.4f", os.clock() - starttime).. "  ".. deData);


local enData = lua2go.ToLua(gmCryptor.sm4CbcEncrypt(data,sm4key,sm4iv))

local starttime = os.clock(); 
for i = 1, N do
   lua2go.ToLua(gmCryptor.sm4CbcEncrypt(data,sm4key,sm4iv)) 
end
print(string.format("SM4[CBC]加密 : %.4f", os.clock() - starttime).. "  ".. enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmCryptor.sm4CbcDecrypt(en,sm4key,sm4iv))

local starttime = os.clock(); 
for i = 1, N do
  lua2go.ToLua(gmCryptor.sm4CbcDecrypt(en,sm4key,sm4iv)) 
end

print(string.format("SM4[CBC]解密 : %.4f", os.clock() - starttime).. "  ".. deData);