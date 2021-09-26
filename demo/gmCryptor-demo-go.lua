package.path = package.path .. ';../lua/?.lua'

function string.count(str)
    local tmpStr = str
    local _, sum = string.gsub(str, "[^\128-\193]", "")
    local _, countEn = string.gsub(tmpStr, "[%z\1-\127]", "")
    return sum, countEn, sum - countEn
end
function string.width(str)
    local _, en, cn = string.count(str)
    return cn * 2 + en
end
function string.toleft(str, len, filledChar)
    local function toleft(str, len, filledChar)
        str = tostring(str);
        filledChar = filledChar or " ";
        local nRestLen = len - string.width(str);
        local nNeedCharNum = math.floor(nRestLen / string.width(filledChar));
        str = str .. string.rep(filledChar, nNeedCharNum);
        return str;
    end
    if type(str) == "number" or type(str) == "string" then
        if not string.find(tostring(str), "\n") then
            return toleft(str, len, filledChar)
        else
            str = string.split(str, "\n")
        end
    end
    if type(str) == "table" then
        local tmpStr = toleft(str[1], len, filledChar)
        for i = 2, #str do
            tmpStr = tmpStr .. "\n" .. toleft(str[i], len, filledChar)
        end
        return tmpStr
    end
end

local lua2go = require('lua2go')
local ffi = require('ffi')

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

local gmGo = lua2go.Load('../release/GMCryptor-go-libs/'..libName..'.'..libType)
 
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

local N = 10000

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

print(string.format("C GO测试"..N.."次================================================="));

local sm3Data = lua2go.ToLua(gmGo.sm3Hash(data)) 
local starttime = os.clock(); 
for i = 1, N do
    lua2go.ToLua(gmGo.sm3Hash(data)) 
end

print(string.format(string.toleft("SM3摘要["..#sm3Data.."位]",30)..": %.4f", os.clock() - starttime) .. "  "..sm3Data);

local enData = lua2go.ToLua(gmGo.sm2Encrypt(data,pub,0)) 
local starttime = os.clock();
for i = 1, N do
   lua2go.ToLua(gmGo.sm2Encrypt(data,pub,0)) 
end
print(string.format(string.toleft("SM2[C1C3C2]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime).. "  "..enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmGo.sm2Decrypt(en,pri,0)) 
 
local starttime = os.clock(); 
for i = 1, N do
    lua2go.ToLua(gmGo.sm2Decrypt(en,pri,0)) 
end
print(string.format(string.toleft("SM2[C1C3C2]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  "..deData);

local enData = lua2go.ToLua(gmGo.sm2Encrypt(data,pub,1)) 
local starttime = os.clock();
for i = 1, N do
   lua2go.ToLua(gmGo.sm2Encrypt(data,pub,1)) 
end
print(string.format(string.toleft("SM2[C1C2C3]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime).. "  "..enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmGo.sm2Decrypt(en,pri,1)) 
 
local starttime = os.clock(); 
for i = 1, N do
    lua2go.ToLua(gmGo.sm2Decrypt(en,pri,1)) 
end
print(string.format(string.toleft("SM2[C1C2C3]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  "..deData);


local enData = lua2go.ToLua(gmGo.sm2EncryptAsn1(data,pub)) 
local starttime = os.clock(); 
for i = 1, N do
   lua2go.ToLua(gmGo.sm2EncryptAsn1(data,pub)) 
end
print(string.format(string.toleft("SM2[Asn1]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime).. "  "..enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmGo.sm2DecryptAsn1(en,pri)) 
 
local starttime = os.clock(); 
for i = 1, N do
    lua2go.ToLua(gmGo.sm2DecryptAsn1(en,pri)) 
end
print(string.format(string.toleft("SM2[Asn1]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  "..deData);

local enData = lua2go.ToLua(gmGo.sm4EcbEncrypt(data,sm4key))

local starttime = os.clock(); 
for i = 1, N do
   lua2go.ToLua(gmGo.sm4EcbEncrypt(data,sm4key)) 
end
print(string.format(string.toleft("SM4[ECB]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime).. "  ".. enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmGo.sm4EcbDecrypt(en,sm4key))

local starttime = os.clock(); 
for i = 1, N do
  lua2go.ToLua(gmGo.sm4EcbDecrypt(en,sm4key)) 
end

print(string.format(string.toleft("SM4[ECB]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  ".. deData);

local enData = lua2go.ToLua(gmGo.sm4CbcEncrypt(data,sm4key,sm4iv))

local starttime = os.clock(); 
for i = 1, N do
   lua2go.ToLua(gmGo.sm4CbcEncrypt(data,sm4key,sm4iv)) 
end
print(string.format(string.toleft("SM4[CBC]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime).. "  ".. enData);

local en = ffi.new("char[?]", #enData + 1)
ffi.copy(en, enData)

local deData = lua2go.ToLua(gmGo.sm4CbcDecrypt(en,sm4key,sm4iv))

local starttime = os.clock(); 
for i = 1, N do
  lua2go.ToLua(gmGo.sm4CbcDecrypt(en,sm4key,sm4iv)) 
end

print(string.format(string.toleft("SM4[CBC]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  ".. deData);

local sm2Sign = lua2go.ToLua(gmGo.sm2Signature(data,pri)) 
local starttime = os.clock(); 
for i = 1, N do
   lua2go.ToLua(gmGo.sm2Signature(data,pri)) 
end
print(string.format(string.toleft("SM2加签["..#sm2Sign.."位]",30)..": %.4f", os.clock() - starttime).. "  ".. sm2Sign);

local sign = ffi.new("char[?]", #sm2Sign + 1)
ffi.copy(sign, sm2Sign)

local veri = lua2go.ToLua(gmGo.sm2VerifySign(data,sign,pub));

local starttime = os.clock(); 

for i = 1, N do
  lua2go.ToLua(gmGo.sm2VerifySign(data,sign,pub));
end
print(string.format(string.toleft("SM2验签[0位]",30)..": %.4f", os.clock() - starttime).. "  ".. tostring(veri));