#include <node.h>
#include <nan.h>
#include <stdbool.h>
#include "../../libs/gmCryptor-go-libs/gmCryptor-go.h"

using v8::Boolean;
using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::NewStringType;
using v8::Object;
using v8::String;
using v8::Value;


void SM3HashMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 1)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String msgString(args[0]);
  char *message = (char *)malloc(msgString.length() + 1);
  strcpy(message, *msgString);
  char *result = sm3Hash(message);
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
  delete message;
  delete result;
}

void SM2EncryptMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 3)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *data = (char *)malloc(dataString.length() + 1);
  strcpy(data, *dataString);

  Nan::Utf8String pubString(args[1]);
  char *pub = (char *)malloc(pubString.length() + 1);
  strcpy(pub, *pubString);

  char *result = sm2Encrypt(data, pub, Nan::To<int>(args[2]).FromJust());
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
  delete result;
  delete data;
  delete pub;
}

void SM2DecryptMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 3)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *data = (char *)malloc(dataString.length() + 1);
  strcpy(data, *dataString);

  Nan::Utf8String priString(args[1]);
  char *pri = (char *)malloc(priString.length() + 1);
  strcpy(pri, *priString);

  char *result = sm2Decrypt(data, pri, Nan::To<int>(args[2]).FromJust());
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
  delete result;
  delete data;
  delete pri;
}

void SM2EncryptAsn1Method(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 2)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *data = (char *)malloc(dataString.length() + 1);
  strcpy(data, *dataString);

  Nan::Utf8String pubString(args[1]);
  char *pub = (char *)malloc(pubString.length() + 1);
  strcpy(pub, *pubString);

  char *result = sm2EncryptAsn1(data, pub);
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
  delete result;
  delete data;
  delete pub;
}

void SM2DecryptAsn1Method(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 2)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *enData = (char *)malloc(dataString.length() + 1);
  strcpy(enData, *dataString);

  Nan::Utf8String priString(args[1]);
  char *pri = (char *)malloc(priString.length() + 1);
  strcpy(pri, *priString);

  char *result = sm2DecryptAsn1(enData, pri);
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
  delete result;
  delete enData;
  delete pri;
}

void SM4EcbEncryptMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 2)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *data = (char *)malloc(dataString.length() + 1);
  strcpy(data, *dataString);

  Nan::Utf8String keyString(args[1]);
  char *key = (char *)malloc(keyString.length() + 1);
  strcpy(key, *keyString);

  char *result = sm4EcbEncrypt(data, key);
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
  delete result;
  delete data;
  delete key;
}

void SM4EcbDecryptMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 2)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *data = (char *)malloc(dataString.length() + 1);
  strcpy(data, *dataString);

  Nan::Utf8String keyString(args[1]);
  char *key = (char *)malloc(keyString.length() + 1);
  strcpy(key, *keyString);

  char *result = sm4EcbDecrypt(data, key);
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
  delete result;
  delete data;
  delete key;
}

void SM4CbcEncryptMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 3)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *data = (char *)malloc(dataString.length() + 1);
  strcpy(data, *dataString);

  Nan::Utf8String keyString(args[1]);
  char *key = (char *)malloc(keyString.length() + 1);
  strcpy(key, *keyString);

  Nan::Utf8String ivString(args[2]);
  char *iv = (char *)malloc(ivString.length() + 1);
  strcpy(iv, *ivString);

  char *result = sm4CbcEncrypt(data, key, iv);
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());

  delete result;
  delete data;
  delete key;
  delete iv;
}

void SM4CbcDecryptMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 3)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String string(args[0]);
  char *data = (char *)malloc(string.length() + 1);
  strcpy(data, *string);

  Nan::Utf8String keyString(args[1]);
  char *key = (char *)malloc(keyString.length() + 1);
  strcpy(key, *keyString);

  Nan::Utf8String ivString(args[2]);
  char *iv = (char *)malloc(ivString.length() + 1);
  strcpy(iv, *ivString);

  char *result = sm4CbcDecrypt(data, key, iv);
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
  delete result;
  delete data;
  delete key;
  delete iv;
}

void SM2SignatureMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 2)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *data = (char *)malloc(dataString.length() + 1);
  strcpy(data, *dataString);

  Nan::Utf8String priString(args[1]);
  char *pri = (char *)malloc(priString.length() + 1);
  strcpy(pri, *priString);

  char *result = sm2Signature(data, pri);
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());

  delete result;
  delete data;
  delete pri;
}

void SM2VerifySignMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 3)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *data = (char *)malloc(dataString.length() + 1);
  strcpy(data, *dataString);

  Nan::Utf8String signString(args[1]);
  char *sign = (char *)malloc(signString.length() + 1);
  strcpy(sign, *signString);

  Nan::Utf8String pubString(args[2]);
  char *pub = (char *)malloc(pubString.length() + 1);
  strcpy(pub, *pubString);

  bool result = sm2VerifySign(data, sign, pub);
  args.GetReturnValue().Set(result);

  delete data;
  delete sign;
  delete pub;
}

void CipherUnmarshalMethod(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() != 2)
  {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }
  Nan::Utf8String dataString(args[0]);
  char *data = (char *)malloc(dataString.length() + 1);
  strcpy(data, *dataString);
  char *result = cipherUnmarshal(data, Nan::To<int>(args[1]).FromJust());
  args.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
  delete result;
  delete data;
}

void Init(Local<Object> exports)
{
  NODE_SET_METHOD(exports, "sm3Hash", SM3HashMethod);
  NODE_SET_METHOD(exports, "sm2Encrypt", SM2EncryptMethod);
  NODE_SET_METHOD(exports, "sm2Decrypt", SM2DecryptMethod);
  NODE_SET_METHOD(exports, "sm2EncryptAsn1", SM2EncryptAsn1Method);
  NODE_SET_METHOD(exports, "sm2DecryptAsn1", SM2DecryptAsn1Method);
  NODE_SET_METHOD(exports, "sm4EcbEncrypt", SM4EcbEncryptMethod);
  NODE_SET_METHOD(exports, "sm4EcbDecrypt", SM4EcbDecryptMethod);
  NODE_SET_METHOD(exports, "sm4CbcEncrypt", SM4CbcEncryptMethod);
  NODE_SET_METHOD(exports, "sm4CbcDecrypt", SM4CbcDecryptMethod);
  NODE_SET_METHOD(exports, "sm2Signature", SM2SignatureMethod);
  NODE_SET_METHOD(exports, "sm2VerifySign", SM2VerifySignMethod);
  NODE_SET_METHOD(exports, "cipherUnmarshal", CipherUnmarshalMethod);
}

NODE_MODULE(GMCryptorGoAddon, Init)
