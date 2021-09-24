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
func sm3Hash(data *C.char) *C.char {
	return C.CString(cryptor.SM3Hash(C.GoString(data)))
}

//export sm2Encrypt
func sm2Encrypt(data *C.char, publicKey *C.char, mode C.int) *C.char {
	return C.CString(cryptor.SM2Encrypt(C.GoString(data), C.GoString(publicKey), int(mode)))
}

//export sm2Decrypt
func sm2Decrypt(encData *C.char, privateKey *C.char, mode C.int) *C.char {
	return C.CString(cryptor.SM2Decrypt(C.GoString(encData), C.GoString(privateKey), int(mode)))
}

//export sm2EncryptAsn1
func sm2EncryptAsn1(data *C.char, publicKey *C.char) *C.char {
	return C.CString(cryptor.SM2EncryptAsn1(C.GoString(data), C.GoString(publicKey)))
}

//export sm2DecryptAsn1
func sm2DecryptAsn1(encData *C.char, privateKey *C.char) *C.char {
	return C.CString(cryptor.SM2DecryptAsn1(C.GoString(encData), C.GoString(privateKey)))
}

//export sm4EcbEncrypt
func sm4EcbEncrypt(data *C.char, sm4Key *C.char) *C.char {
	return C.CString(cryptor.SM4EcbEncrypt(C.GoString(data), C.GoString(sm4Key)))
}

//export sm4EcbDecrypt
func sm4EcbDecrypt(encData *C.char, sm4Key *C.char) *C.char {
	return C.CString(cryptor.SM4EcbDecrypt(C.GoString(encData), C.GoString(sm4Key)))
}

//export sm4CbcEncrypt
func sm4CbcEncrypt(data *C.char, sm4Key *C.char, sm4Iv *C.char) *C.char {
	return C.CString(cryptor.SM4CbcEncrypt(C.GoString(data), C.GoString(sm4Key), C.GoString(sm4Iv)))
}

//export sm4CbcDecrypt
func sm4CbcDecrypt(encData *C.char, sm4Key *C.char, sm4Iv *C.char) *C.char {
	return C.CString(cryptor.SM4CbcDecrypt(C.GoString(encData), C.GoString(sm4Key), C.GoString(sm4Iv)))
}

//export sm2Signature
func sm2Signature(data *C.char, privateKey *C.char) *C.char {
	return C.CString(cryptor.SM2Signature(C.GoString(data), C.GoString(privateKey)))
}

//export sm2VerifySign
func sm2VerifySign(data *C.char, signData *C.char, publicKey *C.char) C.bool {
	return C.bool(cryptor.SM2VerifySign(C.GoString(data), C.GoString(signData), C.GoString(publicKey)))
}

//export cipherUnmarshal
func cipherUnmarshal(data *C.char, mode C.int) *C.char {
	return C.CString(cryptor.CipherUnmarshal(C.GoString(data), int(mode)))
}
