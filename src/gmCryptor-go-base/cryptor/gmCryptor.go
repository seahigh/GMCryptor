package cryptor

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
)

// brew install mingw-w64
// brew tap messense/macos-cross-toolchains
// brew install x86_64-unknown-linux-gnu
// brew install aarch64-unknown-linux-gnu
// brew install zstd

func SM2Encrypt(plainText string, publicKey string, mode int) string {
	cipherHex := ""
	plainTextBytes := []byte(plainText)
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return ""
	}
	curve := sm2.P256Sm2()
	x, y := elliptic.Unmarshal(curve, pubKeyBytes)
	pubKey := &sm2.PublicKey{Curve: curve, X: x, Y: y}

	cipherTextBytes, err := sm2.Encrypt(pubKey, plainTextBytes, rand.Reader, mode)
	if err != nil {
		return ""
	}
	cipherHex = hex.EncodeToString(cipherTextBytes)
	return cipherHex
}

func SM2EncryptAsn1(plainText string, publicKey string) string {
	cipherHex := ""
	plainTextBytes := []byte(plainText)
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return ""
	}
	curve := sm2.P256Sm2()
	x, y := elliptic.Unmarshal(curve, pubKeyBytes)
	pubKey := &sm2.PublicKey{Curve: curve, X: x, Y: y}

	cipherTextBytes, err := pubKey.EncryptAsn1(plainTextBytes, rand.Reader) //sm2加密
	if err != nil {
		return ""
	}
	cipherHex = hex.EncodeToString(cipherTextBytes)
	return cipherHex
}

func SM2Decrypt(cipherHex string, privateKey string, mode int) string {
	if privateKey == "" || cipherHex == "" {
		return ""
	}
	c := sm2.P256Sm2()
	bytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return ""
	}
	k := new(big.Int).SetBytes(bytes)
	privKey := new(sm2.PrivateKey)
	privKey.PublicKey.Curve = c
	privKey.D = k
	privKey.PublicKey.X, privKey.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	cipherTextBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		return ""
	}
	plainText, err := sm2.Decrypt(privKey, cipherTextBytes, mode)
	if err != nil {
		return ""
	}
	return string(plainText)
}

func SM2DecryptAsn1(cipherHex string, privateKey string) string {
	c := sm2.P256Sm2()
	bytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return ""
	}
	k := new(big.Int).SetBytes(bytes)
	privKey := new(sm2.PrivateKey)
	privKey.PublicKey.Curve = c
	privKey.D = k
	privKey.PublicKey.X, privKey.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	cipherTextBytes, err := hex.DecodeString(cipherHex)
	plainText, err := privKey.DecryptAsn1(cipherTextBytes) //sm2解密
	if err != nil {
		return ""
	}
	return string(plainText)
}

func CipherUnmarshal(ans1 string, mode int) string {
	asn1Bytes, err := hex.DecodeString(ans1)
	if err != nil {
		return ""
	}
	c1c3c2Bytes, err := sm2.CipherUnmarshal(asn1Bytes)
	if err != nil {
		return ""
	}
	if mode == 1 {
		c := c1c3c2Bytes[1:]
		c1 := make([]byte, 64)
		c2 := make([]byte, len(c)-96)
		c3 := make([]byte, 32)
		copy(c1, c[:64])   //x1,y1
		copy(c3, c[64:96]) //hash
		copy(c2, c[96:])   //密文
		ciphertext := []byte{}
		ciphertext = append(ciphertext, c1...)
		ciphertext = append(ciphertext, c2...)
		ciphertext = append(ciphertext, c3...)
		c1c2c3Bytes := append([]byte{0x04}, ciphertext...)
		return hex.EncodeToString(c1c2c3Bytes)

	} else if mode == 0 {
		return hex.EncodeToString(c1c3c2Bytes)
	}
	return ""
}

func SM2Signature(message string, privateKey string) string {
	msgBytes := []byte(message)
	c := sm2.P256Sm2()
	bytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return ""
	}
	k := new(big.Int).SetBytes(bytes)
	privKey := new(sm2.PrivateKey)
	privKey.PublicKey.Curve = c
	privKey.D = k
	privKey.PublicKey.X, privKey.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	signBytes, err := privKey.Sign(rand.Reader, msgBytes, nil)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(signBytes)
}

func SM2VerifySign(message string, signHex string, publicKey string) bool {
	msgBytes := []byte(message)
	signBytes, err := hex.DecodeString(signHex)
	if err != nil {
		return false
	}
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false
	}
	curve := sm2.P256Sm2()
	x, y := elliptic.Unmarshal(curve, pubKeyBytes)
	pubKey := &sm2.PublicKey{Curve: curve, X: x, Y: y}
	return pubKey.Verify(msgBytes, signBytes)
}

func SM3Hash(message string) string {
	sum := sm3.Sm3Sum([]byte(message))
	return hex.EncodeToString(sum)
}

func SM4EcbEncrypt(plainText string, secretKey string) string {
	key, err := hex.DecodeString(secretKey)
	if err != nil {
		return ""
	}
	plainBytes := []byte(plainText)
	cipherText, err := sm4.Sm4Ecb(key, plainBytes, true)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(cipherText)
}

func SM4EcbDecrypt(cipherHex string, secretKey string) string {
	key, err := hex.DecodeString(secretKey)
	if err != nil {
		return ""
	}
	cipherBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		return ""
	}
	plainTxt, err := sm4.Sm4Ecb(key, cipherBytes, false)
	if err != nil {
		return ""
	}
	return string(plainTxt[:])
}

func SM4CbcEncrypt(plainText string, secretKey string, ivHex string) string {
	key, err := hex.DecodeString(secretKey)
	if err != nil {
		return ""
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return ""
	}
	plainBytes := []byte(plainText)
	err = sm4.SetIV(iv)
	cipherText, err := sm4.Sm4Cbc(key, plainBytes, true)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(cipherText)
}

func SM4CbcDecrypt(cipherHex string, secretKey string, ivHex string) string {
	key, err := hex.DecodeString(secretKey)
	if err != nil {
		return ""
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return ""
	}
	cipherBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		return ""
	}
	err = sm4.SetIV(iv)
	plainText, err := sm4.Sm4Cbc(key, cipherBytes, false)
	if err != nil {
		return ""
	}
	return string(plainText[:])
}
