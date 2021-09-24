package gmCryptorMobile

import (
	"gmCryptor/cryptor"
)

func SM2Encrypt(plainText string, publicKey string, mode int) string {
	return cryptor.SM2Encrypt(plainText, publicKey, mode)
}

func SM2EncryptAsn1(plainText string, publicKey string) string {

	return cryptor.SM2EncryptAsn1(plainText, publicKey)
}

func SM2Decrypt(cipherHex string, privateKey string, mode int) string {
	return cryptor.SM2Decrypt(cipherHex, privateKey, mode)
}

func SM2DecryptAsn1(cipherHex string, privateKey string) string {
	return cryptor.SM2DecryptAsn1(cipherHex, privateKey)
}

func CipherUnmarshal(ans1 string, mode int) string {

	return cryptor.CipherUnmarshal(ans1, mode)
}

func SM2Signature(message string, privateKey string) string {
	return cryptor.SM2Signature(message, privateKey)
}

func SM2VerifySign(message string, signHex string, publicKey string) bool {
	return cryptor.SM2VerifySign(message, signHex, publicKey)
}

func SM3Hash(message string) string {
	return cryptor.SM3Hash(message)
}

func SM4EcbEncrypt(plainText string, secretKey string) string {
	return cryptor.SM4EcbEncrypt(plainText, secretKey)
}

func SM4EcbDecrypt(cipherHex string, secretKey string) string {
	return cryptor.SM4EcbDecrypt(cipherHex, secretKey)
}

func SM4CbcEncrypt(plainText string, secretKey string, ivHex string) string {
	return cryptor.SM4CbcEncrypt(plainText, secretKey, ivHex)
}

func SM4CbcDecrypt(cipherHex string, secretKey string, ivHex string) string {
	return cryptor.SM4CbcDecrypt(cipherHex, secretKey, ivHex)
}
