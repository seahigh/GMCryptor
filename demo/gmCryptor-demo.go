package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"gmCryptor/cryptor"
	"time"
)

func main() {
	sm2PublicKey := "047184D28EF2A558F13A730F75F380C3744ED9A8433DFA1F0AFE1BAADA0E18588223D7A249173DDE03FD25FF65C9EE0BD3F17E861171664504CD6B21BA80E32505"
	sm2PrivateKey := "0CD190D5FFBC3F9D808AAF6145D010F06D7726F6B65C6127AB121C9D379A2941"

	testString := "{name: \"Seahigh DX\", nick: \"Seahigh DX\"}"

	h := md5.New()
	h.Write([]byte("1234567890abcdef"))
	sm4_md5_key := hex.EncodeToString(h.Sum(nil))

	h = md5.New()
	h.Write([]byte("abcdef1234567890"))
	sm4_md5_iv := hex.EncodeToString(h.Sum(nil))

	fmt.Println("SM2公钥：" + sm2PublicKey)
	fmt.Println("SM2私钥：" + sm2PrivateKey)

	fmt.Println("SM4密钥：" + sm4_md5_key)
	fmt.Println("SM4IV：" + sm4_md5_iv)

	count := 1000
	fmt.Println("===========测试", count, "次===========")

	endata := cryptor.SM3Hash(testString)
	t1 := time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM3Hash(testString)
	}
	fmt.Println("SM3摘要", time.Since(t1), endata)

	endata = cryptor.SM4EcbEncrypt(testString, sm4_md5_key)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM4EcbEncrypt(testString, sm4_md5_key)
	}
	fmt.Println("SM4[ECB]加密", time.Since(t1), endata)

	dedata := cryptor.SM4EcbDecrypt(endata, sm4_md5_key)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM4EcbDecrypt(endata, sm4_md5_key)
	}
	fmt.Println("SM4[ECB]解密", time.Since(t1), dedata)

	endata = cryptor.SM4CbcEncrypt(testString, sm4_md5_key, sm4_md5_iv)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM4CbcEncrypt(testString, sm2PublicKey, sm4_md5_iv)
	}
	fmt.Println("SM4[CBC]加密", time.Since(t1), endata)

	dedata = cryptor.SM4CbcDecrypt(endata, sm4_md5_key, sm4_md5_iv)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM4CbcDecrypt(endata, sm4_md5_key, sm4_md5_iv)
	}
	fmt.Println("SM4[CBC]解密", time.Since(t1), dedata)

	endata = cryptor.SM2Encrypt(testString, sm2PublicKey, 0)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM2Encrypt(testString, sm2PublicKey, 0)
	}
	fmt.Println("SM2[C1C3C2]加密", time.Since(t1), endata)

	dedata = cryptor.SM2Decrypt(endata, sm2PrivateKey, 0)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM2Decrypt(endata, sm2PrivateKey, 0)
	}
	fmt.Println("SM2[C1C3C2]解密", time.Since(t1), dedata)

	endata = cryptor.SM2Encrypt(testString, sm2PublicKey, 1)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM2Encrypt(testString, sm2PublicKey, 1)
	}
	fmt.Println("SM2[C1C2C3]加密", time.Since(t1), endata)

	dedata = cryptor.SM2Decrypt(endata, sm2PrivateKey, 1)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM2Decrypt(endata, sm2PrivateKey, 1)
	}
	fmt.Println("SM2[C1C2C3]解密", time.Since(t1), dedata)

	endata = cryptor.SM2EncryptAsn1(testString, sm2PublicKey)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM2EncryptAsn1(testString, sm2PublicKey)
	}
	fmt.Println("SM2[Asn1]加密", time.Since(t1), endata)

	c1c2c3Hex := cryptor.CipherUnmarshal(endata, 1)
	rs := cryptor.SM2Decrypt(c1c2c3Hex, sm2PrivateKey, 1)

	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.CipherUnmarshal(endata, 1)
	}
	fmt.Println("Asn1转化C1C2C3后解密[解密不记时]", time.Since(t1), rs)

	c1c3c2Hex := cryptor.CipherUnmarshal(endata, 0)
	rs = cryptor.SM2Decrypt(c1c3c2Hex, sm2PrivateKey, 0)

	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.CipherUnmarshal(endata, 0)
	}
	fmt.Println("Asn1转化C1C3C2后解密[解密不记时]", time.Since(t1), rs)

	dedata = cryptor.SM2DecryptAsn1(endata, sm2PrivateKey)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM2DecryptAsn1(endata, sm2PrivateKey)
	}
	fmt.Println("SM2[Asn1]解密", time.Since(t1), dedata)

	endata = cryptor.SM2Signature(testString, sm2PrivateKey)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM2Signature(testString, sm2PrivateKey)
	}
	fmt.Println("SM2签名", time.Since(t1), endata)

	v := cryptor.SM2VerifySign(testString, endata, sm2PublicKey)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		cryptor.SM2VerifySign(testString, endata, sm2PublicKey)
	}
	fmt.Println("SM2验签", time.Since(t1), v)
}
