package main

/*
  #include <stdlib.h>
  #include <stdbool.h>
*/
import "C"
import "gmCryptor/cryptor"

func main() {

}

//export sm3Hash
func sm3Hash(message *C.char) *C.char {
	return C.CString(cryptor.SM3Hash(C.GoString(message)))
}

//export sm2Encrypt
func sm2Encrypt(plainText *C.char, publicKey *C.char, mode C.int) *C.char {
	return C.CString(cryptor.SM2Encrypt(C.GoString(plainText), C.GoString(publicKey), int(mode)))
}

//export sm2Decrypt
func sm2Decrypt(cipherHex *C.char, privateKey *C.char, mode C.int) *C.char {
	return C.CString(cryptor.SM2Decrypt(C.GoString(cipherHex), C.GoString(privateKey), int(mode)))
}

//export sm2EncryptAsn1
func sm2EncryptAsn1(plainText *C.char, publicKey *C.char) *C.char {
	return C.CString(cryptor.SM2EncryptAsn1(C.GoString(plainText), C.GoString(publicKey)))
}

//export sm2DecryptAsn1
func sm2DecryptAsn1(cipherHex *C.char, privateKey *C.char) *C.char {
	return C.CString(cryptor.SM2DecryptAsn1(C.GoString(cipherHex), C.GoString(privateKey)))
}

//export sm4EcbEncrypt
func sm4EcbEncrypt(plainText *C.char, sm4Key *C.char) *C.char {
	return C.CString(cryptor.SM4EcbEncrypt(C.GoString(plainText), C.GoString(sm4Key)))
}

//export sm4EcbDecrypt
func sm4EcbDecrypt(cipherHex *C.char, secretKey *C.char) *C.char {
	return C.CString(cryptor.SM4EcbDecrypt(C.GoString(cipherHex), C.GoString(secretKey)))
}

//export sm4CbcEncrypt
func sm4CbcEncrypt(plainText *C.char, secretKey *C.char, ivHex *C.char) *C.char {
	return C.CString(cryptor.SM4CbcEncrypt(C.GoString(plainText), C.GoString(secretKey), C.GoString(ivHex)))
}

//export sm4CbcDecrypt
func sm4CbcDecrypt(cipherHex *C.char, secretKey *C.char, ivHex *C.char) *C.char {
	return C.CString(cryptor.SM4CbcDecrypt(C.GoString(cipherHex), C.GoString(secretKey), C.GoString(ivHex)))
}

//export sm2Signature
func sm2Signature(message *C.char, privateKey *C.char) *C.char {
	return C.CString(cryptor.SM2Signature(C.GoString(message), C.GoString(privateKey)))
}

//export sm2VerifySign
func sm2VerifySign(message *C.char, signHex *C.char, publicKey *C.char) C.bool {
	return C.bool(cryptor.SM2VerifySign(C.GoString(message), C.GoString(signHex), C.GoString(publicKey)))
}

//export cipherUnmarshal
func cipherUnmarshal(data *C.char, mode C.int) *C.char {
	return C.CString(cryptor.CipherUnmarshal(C.GoString(data), int(mode)))
}
