package main

import (
	"gmCryptor/cryptor"
	"syscall/js"
)

func main() {
	done := make(chan struct{}, 0)
	js.Global().Set("goCryptorWasm", js.ValueOf(map[string]interface{}{
		"sm3Hash":         js.FuncOf(jsSM3Hash),
		"sm4EcbEncrypt":   js.FuncOf(jsSM4EcbEncrypt),
		"sm4EcbDecrypt":   js.FuncOf(jsSM4EcbDecrypt),
		"sm4CbcEncrypt":   js.FuncOf(jsSM4CbcEncrypt),
		"sm4CbcDecrypt":   js.FuncOf(jsSM4CbcDecrypt),
		"sm2Signature":    js.FuncOf(jsSM2Signature),
		"sm2VerifySign":   js.FuncOf(jsSM2VerifySign),
		"sm2Encrypt":      js.FuncOf(jsSM2Encrypt),
		"sm2Decrypt":      js.FuncOf(jsSM2Decrypt),
		"sm2EncryptAsn1":  js.FuncOf(jsSM2EncryptAsn1),
		"sm2DecryptAsn1":  js.FuncOf(jsSM2DecryptAsn1),
		"cipherUnmarshal": js.FuncOf(jsCipherUnmarshal),
	}))
	<-done
}

func jsSM3Hash(this js.Value, args []js.Value) interface{} {
	data := args[0].String()
	return cryptor.SM3Hash(data)
}

func jsSM4EcbEncrypt(this js.Value, args []js.Value) interface{} {
	rt := cryptor.SM4EcbEncrypt(args[0].String(), args[1].String())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}

func jsSM4EcbDecrypt(this js.Value, args []js.Value) interface{} {
	rt := cryptor.SM4EcbDecrypt(args[0].String(), args[1].String())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}

func jsSM4CbcEncrypt(this js.Value, args []js.Value) interface{} {
	rt := cryptor.SM4CbcEncrypt(args[0].String(), args[1].String(), args[2].String())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}

func jsSM4CbcDecrypt(this js.Value, args []js.Value) interface{} {
	rt := cryptor.SM4CbcDecrypt(args[0].String(), args[1].String(), args[2].String())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}

func jsSM2DecryptAsn1(this js.Value, args []js.Value) interface{} {
	rt := cryptor.SM2DecryptAsn1(args[0].String(), args[1].String())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}

func jsSM2EncryptAsn1(this js.Value, args []js.Value) interface{} {
	rt := cryptor.SM2EncryptAsn1(args[0].String(), args[1].String())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}

func jsSM2Decrypt(this js.Value, args []js.Value) interface{} {
	rt := cryptor.SM2Decrypt(args[0].String(), args[1].String(), args[2].Int())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}

func jsSM2Encrypt(this js.Value, args []js.Value) interface{} {
	rt := cryptor.SM2Encrypt(args[0].String(), args[1].String(), args[2].Int())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}

func jsSM2Signature(this js.Value, args []js.Value) interface{} {
	rt := cryptor.SM2Signature(args[0].String(), args[1].String())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}

func jsSM2VerifySign(this js.Value, args []js.Value) interface{} {
	return cryptor.SM2VerifySign(args[0].String(), args[1].String(), args[2].String())
}

func jsCipherUnmarshal(this js.Value, args []js.Value) interface{} {
	rt := cryptor.CipherUnmarshal(args[0].String(), args[1].Int())
	if rt == "" {
		return nil
	} else {
		return rt
	}
}
