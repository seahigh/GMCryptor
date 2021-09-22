package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"
)

func regMain() {
	sm2PublicKey := "047184D28EF2A558F13A730F75F380C3744ED9A8433DFA1F0AFE1BAADA0E18588223D7A249173DDE03FD25FF65C9EE0BD3F17E861171664504CD6B21BA80E32505"
	sm2PrivateKey := "0CD190D5FFBC3F9D808AAF6145D010F06D7726F6B65C6127AB121C9D379A2941"

	testString := "{name: \"Seahigh DX\", password: \"Seahigh DX\"}"

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

	endata := SM3Hash(testString)
	t1 := time.Now()
	for i := 0; i <= count; i++ {
		SM3Hash(testString)
	}
	fmt.Println("SM3摘要", time.Since(t1), endata)

	endata = SM4EcbEncrypt(testString, sm4_md5_key)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM4EcbEncrypt(testString, sm4_md5_key)
	}
	fmt.Println("SM4[ECB]加密", time.Since(t1), endata)

	dedata := SM4EcbDecrypt(endata, sm4_md5_key)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM4EcbDecrypt(endata, sm4_md5_key)
	}
	fmt.Println("SM4[ECB]解密", time.Since(t1), dedata)

	endata = SM4CbcEncrypt(testString, sm4_md5_key, sm4_md5_iv)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM4CbcEncrypt(testString, sm2PublicKey, sm4_md5_iv)
	}
	fmt.Println("SM4[CBC]加密", time.Since(t1), endata)

	dedata = SM4CbcDecrypt(endata, sm4_md5_key, sm4_md5_iv)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM4CbcDecrypt(endata, sm4_md5_key, sm4_md5_iv)
	}
	fmt.Println("SM4[CBC]解密", time.Since(t1), dedata)

	endata = SM2Encrypt(testString, sm2PublicKey, 0)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM2Encrypt(testString, sm2PublicKey, 0)
	}
	fmt.Println("SM2[C1C3C2]加密", time.Since(t1), endata)

	dedata = SM2Decrypt(endata, sm2PrivateKey, 0)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM2Decrypt(endata, sm2PrivateKey, 0)
	}
	fmt.Println("SM2[C1C3C2]解密", time.Since(t1), dedata)

	endata = SM2Encrypt(testString, sm2PublicKey, 1)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM2Encrypt(testString, sm2PublicKey, 1)
	}
	fmt.Println("SM2[C1C2C3]加密", time.Since(t1), endata)

	dedata = SM2Decrypt(endata, sm2PrivateKey, 1)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM2Decrypt(endata, sm2PrivateKey, 1)
	}
	fmt.Println("SM2[C1C2C3]解密", time.Since(t1), dedata)

	endata = SM2EncryptAsn1(testString, sm2PublicKey)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM2EncryptAsn1(testString, sm2PublicKey)
	}
	fmt.Println("SM2[Asn1]加密", time.Since(t1), endata)

	c1c2c3Hex := CipherUnmarshal(endata, 1)
	rs := SM2Decrypt(c1c2c3Hex, sm2PrivateKey, 1)

	t1 = time.Now()
	for i := 0; i <= count; i++ {
		CipherUnmarshal(endata, 1)
	}
	fmt.Println("Asn1转化C1C2C3后解密[解密不记时]", time.Since(t1), rs)

	c1c3c2Hex := CipherUnmarshal(endata, 0)
	rs = SM2Decrypt(c1c3c2Hex, sm2PrivateKey, 0)

	t1 = time.Now()
	for i := 0; i <= count; i++ {
		CipherUnmarshal(endata, 0)
	}
	fmt.Println("Asn1转化C1C3C2后解密[解密不记时]", time.Since(t1), rs)

	dedata = SM2DecryptAsn1(endata, sm2PrivateKey)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM2DecryptAsn1(endata, sm2PrivateKey)
	}
	fmt.Println("SM2[Asn1]解密", time.Since(t1), dedata)

	endata = SM2Signature(testString, sm2PrivateKey)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM2Signature(testString, sm2PrivateKey)
	}
	fmt.Println("SM2签名", time.Since(t1), endata)

	v := SM2VerifySign(testString, endata, sm2PublicKey)
	t1 = time.Now()
	for i := 0; i <= count; i++ {
		SM2VerifySign(testString, endata, sm2PublicKey)
	}
	fmt.Println("SM2验签", time.Since(t1), v)
}
