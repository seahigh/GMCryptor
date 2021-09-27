package.path = package.path .. ';../lua/?.lua'

--格式化补齐文字打印显示，没什么实质用途
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

--开始测试
local testStr = "{name: \"Seahigh DX\", nick: \"Seahigh DX\"}"
local pubStr = "04efb77dc4e6545b0379901e3a8c656d0ef2623fd00ccab5afa8631f676715d679d89aa792f3b3a2bad5cfa0d30f30f1fb6e5e8ca11a0a3dcd714330a30f16e017"
local priStr = "ac615b172f8bbc223de2f631d9c803e9a9b6dea9df81b1330d02fd9a874b44cf"
local sm4KeyStr = "996ce17f6abc9fe126b57aa5f1d8c92c"
local sm4IvStr = "504f1a1f80d40c760c74bd5257124dc9"

local N = 10000

--2选1，API一致，不可同时用
print(string.format("C OPENSSL测试"..N.."次================================================="));
local gmLib = require "gmCryptor-c"

-- print(string.format("C GO测试"..N.."次================================================="));
-- local gmLib = require "gmCryptor-go"

local sm3Data = gmLib.sm3Hash(testStr)
local starttime = os.clock();
for i = 1, N do 
    gmLib.sm3Hash(testStr);
end
print(string.format(string.toleft("SM3摘要["..#sm3Data.."位]",30)..": %.4f", os.clock() - starttime) .. "  " ..  sm3Data);

local enData = gmLib.sm4EcbEncrypt(testStr, sm4KeyStr)

local starttime = os.clock();
for i = 1, N do 
    gmLib.sm4EcbEncrypt(testStr, sm4KeyStr) 
end
print(string.format(string.toleft("SM4[ECB]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime) .. "  " ..  enData);

local deData = gmLib.sm4EcbDecrypt(enData,sm4KeyStr)

local starttime = os.clock(); 
for i = 1, N do
    gmLib.sm4EcbDecrypt(enData,sm4KeyStr) 
end

print(string.format(string.toleft("SM4[ECB]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  ".. deData);

local enData = gmLib.sm4CbcEncrypt(testStr, sm4KeyStr, sm4IvStr)

local starttime = os.clock();
for i = 1, N do 
    gmLib.sm4CbcEncrypt(testStr, sm4KeyStr, sm4IvStr) 
end
print(string.format(string.toleft("SM4[CBC]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime) .. "  " ..  enData);

local deData =  gmLib.sm4CbcDecrypt(enData,sm4KeyStr,sm4IvStr)

local starttime = os.clock(); 
for i = 1, N do
    gmLib.sm4CbcDecrypt(enData,sm4KeyStr,sm4IvStr) 
end

print(string.format(string.toleft("SM4[CBC]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  ".. deData);

local enData = gmLib.sm2Encrypt(testStr, pubStr, 0) 

local starttime = os.clock();
for i = 1, N do 
    gmLib.sm2Encrypt(testStr, pubStr, 0) 
end
print(string.format(string.toleft("SM2[C1C3C2]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime) .. "  " ..  enData);

local deData = gmLib.sm2Decrypt(enData,priStr,0)
 
local starttime = os.clock(); 
for i = 1, N do
    gmLib.sm2Decrypt(enData,priStr,0)
end
print(string.format(string.toleft("SM2[C1C3C2]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  "..deData);

local enData = gmLib.sm2Encrypt(testStr, pubStr, 1) 

local starttime = os.clock();
for i = 1, N do 
    gmLib.sm2Encrypt(testStr, pubStr, 1) 
end
print(string.format(string.toleft("SM2[C1C2C3]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime) .. "  " ..  enData);

local deData = gmLib.sm2Decrypt(enData,priStr,1)
 
local starttime = os.clock(); 
for i = 1, N do
    gmLib.sm2Decrypt(enData,priStr,1)
end
print(string.format(string.toleft("SM2[C1C2C3]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  "..deData);

local enData = gmLib.sm2EncryptAsn1(testStr, pubStr) 

local starttime = os.clock();
for i = 1, N do 
    gmLib.sm2EncryptAsn1(testStr, pubStr) 
end
print(string.format(string.toleft("SM2[Asn1]加密["..#enData.."位]",30)..": %.4f", os.clock() - starttime) .. "  " ..  enData);

local deData = gmLib.sm2DecryptAsn1(enData,priStr)
 
local starttime = os.clock(); 
for i = 1, N do
    gmLib.sm2DecryptAsn1(enData,priStr)
end
print(string.format(string.toleft("SM2[Asn1]解密["..#deData.."位]",30)..": %.4f", os.clock() - starttime).. "  "..deData);

local sig = gmLib.sm2Signature(testStr,priStr)
 
local starttime = os.clock(); 
for i = 1, N do
    gmLib.sm2Signature(testStr,priStr)
end
print(string.format(string.toleft("SM2加签["..#sig.."位]",30)..": %.4f", os.clock() - starttime).. "  "..sig);

local veri =  gmLib.sm2VerifySign(testStr,sig,pubStr);

local starttime = os.clock(); 
for i = 1, N do
    gmLib.sm2VerifySign(testStr,sig,pubStr);
end
print(string.format(string.toleft("SM2验签[0位]",30)..": %.4f", os.clock() - starttime).. "  ".. tostring(veri));