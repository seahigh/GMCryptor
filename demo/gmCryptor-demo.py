from ctypes import *
import ctypes
import platform

libName = "darwin-x64.dylib"
if platform.platform().find('macOS')>=0 and platform.platform().find('arm64')>=0:
    libName = "darwin-arm64.dylib"
if platform.platform().find('macOS')>=0 and platform.platform().find('x64')>=0:
    libName = "darwin-x64.dylib"
 
print("=================================================C GO测试=================================================")
gmGo = cdll.LoadLibrary('../release/gmCryptor-go-libs/gmCryptor-go-'+libName)
testString = "{name: \"Seahigh DX\", nick: \"Seahigh DX\"}"
pubStr = "04efb77dc4e6545b0379901e3a8c656d0ef2623fd00ccab5afa8631f676715d679d89aa792f3b3a2bad5cfa0d30f30f1fb6e5e8ca11a0a3dcd714330a30f16e017"
priStr = "ac615b172f8bbc223de2f631d9c803e9a9b6dea9df81b1330d02fd9a874b44cf"

sm4KeyStr = "996ce17f6abc9fe126b57aa5f1d8c92c"
sm4IvStr = "504f1a1f80d40c760c74bd5257124dc9"

gmGo.sm3Hash.restype = c_char_p
print("SM3摘要",gmGo.sm3Hash(c_char_p(testString.encode("utf-8"))).decode("utf-8"))

gmGo.sm4EcbEncrypt.restype = c_char_p
ecbCipherHex = gmGo.sm4EcbEncrypt(c_char_p(testString.encode("utf-8")),c_char_p(sm4KeyStr.encode("utf-8"))).decode("utf-8")
print("SM4[ECB]加密",ecbCipherHex)

gmGo.sm4EcbDecrypt.restype = c_char_p
ecbPlainText = gmGo.sm4EcbDecrypt(c_char_p(ecbCipherHex.encode("utf-8")),c_char_p(sm4KeyStr.encode("utf-8"))).decode("utf-8")
print("SM4[ECB]解密",ecbPlainText)

gmGo.sm4CbcEncrypt.restype = c_char_p
cbcCipherHex = gmGo.sm4CbcEncrypt(c_char_p(testString.encode("utf-8")),c_char_p(sm4KeyStr.encode("utf-8")),c_char_p(sm4IvStr.encode("utf-8"))).decode("utf-8")
print("SM4[CBC]加密",cbcCipherHex)

gmGo.sm4CbcDecrypt.restype = c_char_p
cbcPlainText = gmGo.sm4CbcDecrypt(c_char_p(cbcCipherHex.encode("utf-8")),c_char_p(sm4KeyStr.encode("utf-8")),c_char_p(sm4IvStr.encode("utf-8"))).decode("utf-8")
print("SM4[CBC]解密",cbcPlainText)

gmGo.sm2Encrypt.restype = c_char_p
sm2CipherHex1 = gmGo.sm2Encrypt(c_char_p(testString.encode("utf-8")),c_char_p(pubStr.encode("utf-8")),0).decode("utf-8")
print("SM2[C1C3C2]加密",sm2CipherHex1)

gmGo.sm2Decrypt.restype = c_char_p
sm2PlainText1 = gmGo.sm2Decrypt(c_char_p(sm2CipherHex1.encode("utf-8")),c_char_p(priStr.encode("utf-8")),0).decode("utf-8")
print("SM2[C1C3C2]解密",sm2PlainText1)

sm2CipherHex2 = gmGo.sm2Encrypt(c_char_p(testString.encode("utf-8")),c_char_p(pubStr.encode("utf-8")),1).decode("utf-8")
print("SM2[C1C2C3]加密",sm2CipherHex2)

sm2PlainText2 = gmGo.sm2Decrypt(c_char_p(sm2CipherHex2.encode("utf-8")),c_char_p(priStr.encode("utf-8")),1).decode("utf-8")
print("SM2[C1C2C3]解密",sm2PlainText2)

gmGo.sm2EncryptAsn1.restype = c_char_p
sm2Asn1CipherHex = gmGo.sm2EncryptAsn1(c_char_p(testString.encode("utf-8")),c_char_p(pubStr.encode("utf-8"))).decode("utf-8")
print("SM2[Asn1]加密",sm2Asn1CipherHex)

gmGo.sm2DecryptAsn1.restype = c_char_p
sm2Asn1PlainText = gmGo.sm2DecryptAsn1(c_char_p(sm2Asn1CipherHex.encode("utf-8")),c_char_p(priStr.encode("utf-8"))).decode("utf-8")
print("SM2[Asn1]解密",sm2Asn1PlainText)

gmGo.sm2Signature.restype = c_char_p
sm2Sign = gmGo.sm2Signature(c_char_p(testString.encode("utf-8")),c_char_p(priStr.encode("utf-8"))).decode("utf-8")
print("SM2加签",sm2Sign)

gmGo.sm2VerifySign.restype = c_bool
sm2Verify= gmGo.sm2VerifySign(c_char_p(testString.encode("utf-8")),c_char_p(sm2Sign.encode("utf-8")),c_char_p(pubStr.encode("utf-8")))
print("SM2加签",sm2Verify)

print("=================================================C OENSSL测试=================================================")
gmOpenssl = cdll.LoadLibrary('../release/gmCryptor-c-libs/gmCryptor-c-'+libName)

gmOpenssl.sm3Hash.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm3Hash(c_char_p(testString.encode("utf-8")),outbuflen)
print("SM3摘要",outbuf[:outbuflen.contents.value].decode("utf-8"))

gmOpenssl.sm4EcbEncrypt.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm4EcbEncrypt(c_char_p(testString.encode("utf-8")),c_char_p(sm4KeyStr.encode("utf-8")),outbuflen)
ecbCipherHex = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM4[ECB]加密",ecbCipherHex)

gmOpenssl.sm4EcbDecrypt.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm4EcbDecrypt(c_char_p(ecbCipherHex.encode("utf-8")),c_char_p(sm4KeyStr.encode("utf-8")),outbuflen)
ecbPlainText = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM4[ECB]解密",ecbPlainText)

gmOpenssl.sm4CbcEncrypt.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm4CbcEncrypt(c_char_p(testString.encode("utf-8")),c_char_p(sm4KeyStr.encode("utf-8")),c_char_p(sm4IvStr.encode("utf-8")),outbuflen)
cbcCipherHex = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM4[CBC]加密",cbcCipherHex)

gmOpenssl.sm4CbcDecrypt.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm4CbcDecrypt(c_char_p(cbcCipherHex.encode("utf-8")),c_char_p(sm4KeyStr.encode("utf-8")),c_char_p(sm4IvStr.encode("utf-8")),outbuflen)
cbcPlainText = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM4[CBC]解密",cbcPlainText)

gmOpenssl.sm2Encrypt.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm2Encrypt(c_char_p(testString.encode("utf-8")),c_char_p(pubStr.encode("utf-8")),0,outbuflen)
sm2CipherHex1 = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM2[C1C3C2]加密",sm2CipherHex1)

gmOpenssl.sm2Decrypt.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm2Decrypt(c_char_p(sm2CipherHex1.encode("utf-8")),c_char_p(priStr.encode("utf-8")),0,outbuflen)
sm2PlainText1 = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM2[C1C3C2]解密",sm2PlainText1)

outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm2Encrypt(c_char_p(testString.encode("utf-8")),c_char_p(pubStr.encode("utf-8")),1,outbuflen)
sm2CipherHex2 = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM2[C1C2C3]加密",sm2CipherHex2)

outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm2Decrypt(c_char_p(sm2CipherHex2.encode("utf-8")),c_char_p(priStr.encode("utf-8")),1,outbuflen)
sm2PlainText2 = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM2[C1C2C3]解密",sm2PlainText2)

gmOpenssl.sm2EncryptAsn1.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm2EncryptAsn1(c_char_p(testString.encode("utf-8")),c_char_p(pubStr.encode("utf-8")),outbuflen)
sm2Asn1CipherHex = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM2[Asn1]加密",sm2Asn1CipherHex)

gmOpenssl.sm2DecryptAsn1.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm2DecryptAsn1(c_char_p(sm2Asn1CipherHex.encode("utf-8")),c_char_p(priStr.encode("utf-8")),outbuflen)
sm2Asn1PlainText = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM2[Asn1]解密",sm2Asn1PlainText)

gmOpenssl.sm2Signature.restype = c_char_p
outbuflen = pointer(c_size_t(0))
outbuf = gmOpenssl.sm2Signature(c_char_p(testString.encode("utf-8")),c_char_p(priStr.encode("utf-8")),outbuflen)
sm2Sign = outbuf[:outbuflen.contents.value].decode("utf-8")
print("SM2加签",sm2Sign)

gmOpenssl.sm2VerifySign.restype = c_bool
sm2Verify = gmOpenssl.sm2VerifySign(c_char_p(testString.encode("utf-8")),c_char_p(sm2Sign.encode("utf-8")),c_char_p(pubStr.encode("utf-8")))
print("SM2加签",sm2Verify)