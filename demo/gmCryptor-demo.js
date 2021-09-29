var sm2 = require('sm-crypto').sm2;
var sm3 = require('sm-crypto').sm3;
var sm4 = require('sm-crypto').sm4;
var crypto = require('crypto');
var ffi = require('ffi-napi');
var os = require('os');

var rustCryptorWasm = require('../release/gmCryptor-rust-wasm/.')
var rustCryptorAddon = require('../release/gmCryptor-rust-addon/.')
var goCryptorAddon = require('../release/gmCryptor-go-addon/.')
var cCryptorAddon = require('../release/gmCryptor-c-addon/.')
var wasm = require('./wasm_exec.js')

var count = 100000;

var keypair = sm2.generateKeyPairHex();
var sm2PublicKey = keypair.publicKey;
var sm2PrivateKey = keypair.privateKey;

var sm4_md5_key = crypto.createHash('md5').update('1234567890abcdef').digest('hex');
var sm4_md5_iv = crypto.createHash('md5').update('abcdef1234567890').digest('hex');

console.log("SM2公钥：" + sm2PublicKey);
console.log("SM2私钥：" + sm2PrivateKey);
console.log("SM4密钥：" + sm4_md5_key);
console.log("SM4IV：" + sm4_md5_iv);

var testString = "{name: \"Seahigh DX\", nick: \"Seahigh DX\"}";

function doFn(fnName, fn) {
  var enc = '';
  var myArgs = [].slice.call(arguments);
  if (arguments.length >= 3) {
    enc = fn.apply(this, myArgs.slice(2, myArgs.length));
  }
  var dtNow = new Date().getTime()
  for (let index = 0; index < count; index++) {
    if (arguments.length >= 3) {
      fn.apply(this, myArgs.slice(2, myArgs.length));
    }
  }
  var endStr = "[0位]";
  if (String(enc.length) != "undefined") {
    endStr = "[" + enc.length + "位]"
  }
  console.log((fnName + endStr).padEnd(25), new Date().getTime() - dtNow, enc)
  return enc;
}

console.log("C(OPENSSL)-ADDON 测试" + count + "次=================================================");
doFn('SM3摘要', cCryptorAddon.sm3Hash, testString)
var sm4Enc = doFn('SM4[ECB]加密', cCryptorAddon.sm4EcbEncrypt, testString, sm4_md5_key)
doFn('SM4[ECB]解密', cCryptorAddon.sm4EcbDecrypt, sm4Enc, sm4_md5_key)
var sm4Enc = doFn('SM4[CBC]加密', cCryptorAddon.sm4CbcEncrypt, testString, sm4_md5_key, sm4_md5_iv)
doFn('SM4[CBC]解密', cCryptorAddon.sm4CbcDecrypt, sm4Enc, sm4_md5_key, sm4_md5_iv)
var sm2Enc = doFn('SM2[C1C3C2]加密', cCryptorAddon.sm2Encrypt, testString, sm2PublicKey, cCryptorAddon.C1C3C2)
doFn('SM2[C1C3C2]解密', cCryptorAddon.sm2Decrypt, sm2Enc, sm2PrivateKey, cCryptorAddon.C1C3C2)
var sm2Enc = doFn('SM2[C1C2C3]加密', cCryptorAddon.sm2Encrypt, testString, sm2PublicKey, cCryptorAddon.C1C2C3)
doFn('SM2[C1C2C3]解密', cCryptorAddon.sm2Decrypt, sm2Enc, sm2PrivateKey, cCryptorAddon.C1C2C3)
var sm2EncAsn1 = doFn('SM2[Asn1]加密', cCryptorAddon.sm2EncryptAsn1, testString, sm2PublicKey)
doFn('SM2[Asn1]解密', cCryptorAddon.sm2DecryptAsn1, sm2EncAsn1, sm2PrivateKey)
var sm2Sign = doFn('SM2加签', cCryptorAddon.sm2Signature, testString, sm2PrivateKey)
doFn('SM2验签', cCryptorAddon.sm2VerifySign, testString, sm2Sign, sm2PublicKey)

console.log("RUST(OPENSSL)-ADDON 测试" + count + "次=================================================");
//rm index.node & npm install
doFn('SM3摘要', rustCryptorAddon.sm3Hash, testString)
var sm4Enc = doFn('SM4[ECB]加密', rustCryptorAddon.sm4EcbEncrypt, testString, sm4_md5_key)
doFn('SM4[ECB]解密', rustCryptorAddon.sm4EcbDecrypt, sm4Enc, sm4_md5_key)
var sm4Enc = doFn('SM4[CBC]加密', rustCryptorAddon.sm4CbcEncrypt, testString, sm4_md5_key, sm4_md5_iv)
doFn('SM4[CBC]解密', rustCryptorAddon.sm4CbcDecrypt, sm4Enc, sm4_md5_key, sm4_md5_iv)
var sm2EncAsn1 = doFn('SM2[Asn1]加密', rustCryptorAddon.sm2EncryptAsn1, testString, sm2PublicKey)
doFn('SM2[Asn1]解密', rustCryptorAddon.sm2DecryptAsn1, sm2EncAsn1, sm2PrivateKey);
var sm2Sign = doFn('SM2加签', rustCryptorAddon.sm2Signature, testString, sm2PrivateKey);
doFn('SM2验签', rustCryptorAddon.sm2VerifySign, testString, sm2Sign, sm2PublicKey);

console.log("RUST-WASM 测试" + count + "次=================================================(纯Rust实现，SM2性能还不行)");
//wasm-pack build --target nodejs
doFn('SM3摘要', rustCryptorWasm.sm3Hash, testString)
var sm4Enc = doFn('SM4[ECB]加密', rustCryptorWasm.sm4EcbEncrypt, testString, sm4_md5_key)
doFn('SM4[ECB]解密', rustCryptorWasm.sm4EcbDecrypt, sm4Enc, sm4_md5_key)
var sm4Enc = doFn('SM4[CBC]加密', rustCryptorWasm.sm4CbcEncrypt, testString, sm4_md5_key, sm4_md5_iv)
doFn('SM4[CBC]解密', rustCryptorWasm.sm4CbcDecrypt, sm4Enc, sm4_md5_key, sm4_md5_iv)
var sm2Enc = doFn('SM2[C1C3C2]加密', rustCryptorWasm.sm2Encrypt, testString, sm2PublicKey, rustCryptorWasm.C1C3C2)
doFn('SM2[C1C3C2]解密', rustCryptorWasm.sm2Decrypt, sm2Enc, sm2PrivateKey, rustCryptorWasm.C1C3C2)
var sm2Enc = doFn('SM2[C1C2C3]加密', rustCryptorWasm.sm2Encrypt, testString, sm2PublicKey, rustCryptorWasm.C1C2C3)
doFn('SM2[C1C2C3]解密', rustCryptorWasm.sm2Decrypt, sm2Enc, sm2PrivateKey, rustCryptorWasm.C1C2C3)
var sm2Sign = doFn('SM2加签', rustCryptorWasm.sm2Signature, testString, sm2PrivateKey)
doFn('SM2验签', rustCryptorWasm.sm2VerifySign, testString, sm2Sign, sm2PublicKey)

console.log("GO-ADDON 测试" + count + "次=================================================(性能不错，初步测试GC很好，无内存泄露)");

doFn('SM3摘要', goCryptorAddon.sm3Hash, testString)
var sm4Enc = doFn('SM4[ECB]加密', goCryptorAddon.sm4EcbEncrypt, testString, sm4_md5_key)
doFn('SM4[ECB]解密', goCryptorAddon.sm4EcbDecrypt, sm4Enc, sm4_md5_key)
var sm4Enc = doFn('SM4[CBC]加密', goCryptorAddon.sm4CbcEncrypt, testString, sm4_md5_key, sm4_md5_iv)
doFn('SM4[CBC]解密', goCryptorAddon.sm4CbcDecrypt, sm4Enc, sm4_md5_key, sm4_md5_iv)
var sm2Enc = doFn('SM2[C1C3C2]加密', goCryptorAddon.sm2Encrypt, testString, sm2PublicKey, 0)
doFn('SM2[C1C3C2]解密', goCryptorAddon.sm2Decrypt, sm2Enc, sm2PrivateKey, 0)
var sm2Enc = doFn('SM2[C1C2C3]加密', goCryptorAddon.sm2Encrypt, testString, sm2PublicKey, 1)
doFn('SM2[C1C2C3]解密', goCryptorAddon.sm2Decrypt, sm2Enc, sm2PrivateKey, 1)
var sm2EncAsn1 = doFn('SM2[Asn1]加密', goCryptorAddon.sm2EncryptAsn1, testString, sm2PublicKey)
doFn('SM2[Asn1]解密', goCryptorAddon.sm2DecryptAsn1, sm2EncAsn1, sm2PrivateKey)
var sm2Sign = doFn('SM2加签', goCryptorAddon.sm2Signature, testString, sm2PrivateKey)
doFn('SM2验签', goCryptorAddon.sm2VerifySign, testString, sm2Sign, sm2PublicKey)


var libGMCryptor = ffi.Library('../release/gmCryptor-go-libs/gmCryptor-go-' + os.platform() + "-" + os.arch(), {
  'sm3Hash': ['string', ['string']],
  'sm2Encrypt': ['string', ['string', 'string', 'int']],
  'sm2Decrypt': ['string', ['string', 'string', 'int']],
  'sm2EncryptAsn1': ['string', ['string', 'string']],
  'sm2DecryptAsn1': ['string', ['string', 'string']],
  'sm4EcbEncrypt': ['string', ['string', 'string']],
  'sm4EcbDecrypt': ['string', ['string', 'string']],
  'sm4CbcEncrypt': ['string', ['string', 'string', 'string']],
  'sm4CbcDecrypt': ['string', ['string', 'string', 'string']],
  'sm2Signature': ['string', ['string', 'string']],
  'sm2VerifySign': ['bool', ['string', 'string', 'string']],
})

console.log("FFI 测试" + count + "次=================================================(不建议使用，都有严重内存泄露，而且除了Node v12外调用都很慢，貌似ffi-napi问题暂没法修复)");

doFn('SM3摘要', libGMCryptor.sm3Hash, testString)
var sm4Enc = doFn('SM4[ECB]加密', libGMCryptor.sm4EcbEncrypt, testString, sm4_md5_key)
doFn('SM4[ECB]解密', libGMCryptor.sm4EcbDecrypt, sm4Enc, sm4_md5_key)
var sm4Enc = doFn('SM4[CBC]加密', libGMCryptor.sm4CbcEncrypt, testString, sm4_md5_key, sm4_md5_iv)
doFn('SM4[CBC]解密', libGMCryptor.sm4CbcDecrypt, sm4Enc, sm4_md5_key, sm4_md5_iv)
var sm2Enc = doFn('SM2[C1C3C2]加密', libGMCryptor.sm2Encrypt, testString, sm2PublicKey, 0)
doFn('SM2[C1C3C2]解密', libGMCryptor.sm2Decrypt, sm2Enc, sm2PrivateKey, 0)
var sm2Enc = doFn('SM2[C1C2C3]加密', libGMCryptor.sm2Encrypt, testString, sm2PublicKey, 1)
doFn('SM2[C1C2C3]解密', libGMCryptor.sm2Decrypt, sm2Enc, sm2PrivateKey, 1)
var sm2EncAsn1 = doFn('SM2[Asn1]加密', libGMCryptor.sm2EncryptAsn1, testString, sm2PublicKey)
doFn('SM2[Asn1]解密', libGMCryptor.sm2DecryptAsn1, sm2EncAsn1, sm2PrivateKey)
var sm2Sign = doFn('SM2加签', libGMCryptor.sm2Signature, testString, sm2PrivateKey)
doFn('SM2验签', libGMCryptor.sm2VerifySign, testString, sm2Sign, sm2PublicKey)

console.log("NODE(纯JS) 测试" + count + "次=================================================(慢就一个字，SM4还行可以用用，C1CxCx模式0和1和其他相反，加密结果比其他前两位少04，对齐需注意)");

doFn('SM3摘要', sm3, testString)
var sm4Enc = doFn('SM4[ECB]加密', sm4.encrypt, testString, sm4_md5_key)
doFn('SM4[ECB]解密', sm4.decrypt, sm4Enc, sm4_md5_key)
var sm4Enc = doFn('SM4[CBC]加密', sm4.encrypt, testString, sm4_md5_key, { mode: 'cbc', iv: sm4_md5_iv });
doFn('SM4[CBC]解密', sm4.decrypt, sm4Enc, sm4_md5_key, { mode: 'cbc', iv: sm4_md5_iv });
var sm2Enc = doFn('SM2[C1C3C2]加密', sm2.doEncrypt, testString, sm2PublicKey, 1);
doFn('SM2[C1C3C2]解密', sm2.doDecrypt, sm2Enc, sm2PrivateKey, 1);
var sm2Enc = doFn('SM2[C1C2C3]加密', sm2.doEncrypt, testString, sm2PublicKey, 0)
doFn('SM2[C1C2C3]解密', sm2.doDecrypt, sm2Enc, sm2PrivateKey, 0);
var sm2Sign = doFn('SM2加签', sm2.doSignature, testString, sm2PrivateKey, {
  der: true,
  hash: true
});
doFn('SM2验签', sm2.doVerifySignature, testString, sm2Sign, sm2PublicKey, {
  der: true,
  hash: true
});

console.log("NODE(原生) 测试" + count + "次=================================================(快，需Node版本基于OPENSSL1.1构建)");

function cryptoSM3(testString) {
  return crypto.createHash('sm3').update(testString).digest('hex')
}

function cryptoSM4EcbEncrypt(message, key) {
  const cipher = crypto.createCipheriv("sm4-ecb", Buffer.from(key, 'hex'), null);
  let crypted = cipher.update(message, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
};

function cryptoSM4EcbDecrypt(text, key) {
  const cipher = crypto.createDecipheriv("sm4-ecb", Buffer.from(key, 'hex'), null);
  let decrypted = cipher.update(text, "hex", "utf8");
  decrypted += cipher.final("utf8");
  return decrypted;
};

function cryptoSM4CbcEncrypt(message, key, iv) {
  const cipher = crypto.createCipheriv("sm4-cbc", Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  let crypted = cipher.update(message, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
};

function cryptoSM4CbcDecrypt(text, key, iv) {
  const cipher = crypto.createDecipheriv("sm4-cbc", Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  let decrypted = cipher.update(text, "hex", "utf8");
  decrypted += cipher.final("utf8");
  return decrypted;
};

doFn('SM3摘要', cryptoSM3, testString);
var sm4Enc = doFn('SM4[ECB]加密', cryptoSM4EcbEncrypt, testString, sm4_md5_key);
doFn('SM4[ECB]解密', cryptoSM4EcbDecrypt, sm4Enc, sm4_md5_key);

var sm4Enc = doFn('SM4[CBC]加密', cryptoSM4CbcEncrypt, testString, sm4_md5_key, sm4_md5_iv);
doFn('SM4[CBC]解密', cryptoSM4CbcDecrypt, sm4Enc, sm4_md5_key, sm4_md5_iv);

(async function () {
  const go = new Go();
  const {
    instance
  } = await WebAssembly.instantiate(fs.readFileSync('../release/gmCryptor-go-libs/gmCryptor-go-wasm.wasm'), go.importObject)
  var run = go.run(instance)
  console.log("GO-WASM 测试" + count + "次=================================================(性能一般，syscall/js损耗大，无内存泄露)");
  doFn('SM3摘要', goCryptorWasm.sm3Hash, testString)
  var sm4Enc = doFn('SM4[ECB]加密', goCryptorWasm.sm4EcbEncrypt, testString, sm4_md5_key)
  doFn('SM4[ECB]解密', goCryptorWasm.sm4EcbDecrypt, sm4Enc, sm4_md5_key)
  var sm4Enc = doFn('SM4[CBC]加密', goCryptorWasm.sm4CbcEncrypt, testString, sm4_md5_key, sm4_md5_iv)
  doFn('SM4[CBC]解密', goCryptorWasm.sm4CbcDecrypt, sm4Enc, sm4_md5_key, sm4_md5_iv)
  var sm2EncAsn1 = doFn('SM2[Asn1]加密', goCryptorWasm.sm2EncryptAsn1, testString, sm2PublicKey)
  doFn('SM2[Asn1]解密', goCryptorWasm.sm2DecryptAsn1, sm2EncAsn1, sm2PrivateKey)
  var sm2Enc = doFn('SM2[C1C3C2]加密', goCryptorWasm.sm2Encrypt, testString, sm2PublicKey, 0)
  doFn('SM2[C1C3C2]解密', goCryptorWasm.sm2Decrypt, sm2Enc, sm2PrivateKey, 0)
  var sm2Enc = doFn('SM2[C1C2C3]加密', goCryptorWasm.sm2Encrypt, testString, sm2PublicKey, 1)
  doFn('SM2[C1C2C3]解密', goCryptorWasm.sm2Decrypt, sm2Enc, sm2PrivateKey, 1)
  var sm2Sign = doFn('SM2加签', goCryptorWasm.sm2Signature, testString, sm2PrivateKey)
  doFn('SM2验签', goCryptorWasm.sm2VerifySign, testString, sm2Sign, sm2PublicKey)
})();

var cCryptorWasm = require('../release/gmCryptor-c-wasm/.')
cCryptorWasm.onRuntimeInitialized = () => {
  console.log("C-WASM 测试" + count + "次=================================================");
  cCryptorWasm.sm3Hash = cCryptorWasm.cwrap('_sm3Hash', 'string', ['string']);
  cCryptorWasm.sm4EcbEncrypt = cCryptorWasm.cwrap('_sm4EcbEncrypt', 'string', ['string', 'string']);
  cCryptorWasm.sm4CbcEncrypt = cCryptorWasm.cwrap('_sm4CbcEncrypt', 'string', ['string', 'string', 'string']);
  cCryptorWasm.sm4EcbDecrypt = cCryptorWasm.cwrap('_sm4EcbDecrypt', 'string', ['string', 'string']);
  cCryptorWasm.sm4CbcDecrypt = cCryptorWasm.cwrap('_sm4CbcDecrypt', 'string', ['string', 'string', 'string']);
  cCryptorWasm.sm2Encrypt = cCryptorWasm.cwrap('_sm2Encrypt', 'string', ['string', 'string', 'int']);
  cCryptorWasm.sm2Decrypt = cCryptorWasm.cwrap('_sm2Decrypt', 'string', ['string', 'string', 'int']);
  cCryptorWasm.sm2Signature = cCryptorWasm.cwrap('_sm2Signature', 'string', ['string', 'string', 'string']);
  cCryptorWasm.sm2VerifySign = cCryptorWasm.cwrap('_sm2VerifySign', 'boolean', ['string', 'string', 'string']);
  cCryptorWasm.sm2EncryptAsn1 = cCryptorWasm.cwrap('_sm2EncryptAsn1', 'string', ['string', 'string']);
  cCryptorWasm.sm2DecryptAsn1 = cCryptorWasm.cwrap('_sm2DecryptAsn1', 'string', ['string', 'string']);
  doFn('SM3摘要', cCryptorWasm.sm3Hash, testString)
  var sm4Enc = doFn('SM4[ECB]加密', cCryptorWasm.sm4EcbEncrypt, testString, sm4_md5_key)
  doFn('SM4[ECB]解密', cCryptorWasm.sm4EcbDecrypt, sm4Enc, sm4_md5_key)
  var sm4Enc = doFn('SM4[CBC]加密', cCryptorWasm.sm4CbcEncrypt, testString, sm4_md5_key, sm4_md5_iv)
  doFn('SM4[CBC]解密', cCryptorWasm.sm4CbcDecrypt, sm4Enc, sm4_md5_key, sm4_md5_iv)
  var sm2EncAsn1 = doFn('SM2[Asn1]加密', cCryptorWasm.sm2EncryptAsn1, testString, sm2PublicKey)
  doFn('SM2[Asn1]解密', cCryptorWasm.sm2DecryptAsn1, sm2EncAsn1, sm2PrivateKey)
  var sm2Enc = doFn('SM2[C1C3C2]加密', cCryptorWasm.sm2Encrypt, testString, sm2PublicKey, 0)
  doFn('SM2[C1C3C2]解密', cCryptorWasm.sm2Decrypt, sm2Enc, sm2PrivateKey, 0)
  var sm2Enc = doFn('SM2[C1C2C3]加密', cCryptorWasm.sm2Encrypt, testString, sm2PublicKey, 1)
  doFn('SM2[C1C2C3]解密', cCryptorWasm.sm2Decrypt, sm2Enc, sm2PrivateKey, 1)
  var sm2Sign = doFn('SM2加签', cCryptorWasm.sm2Signature, testString, sm2PrivateKey)
  doFn('SM2验签', cCryptorWasm.sm2VerifySign, testString, sm2Sign, sm2PublicKey)
}

function doMemoryTest(type) {
  if (type == 0) {
    return
  }
  var myFN = null;
  var name = '';
  if (type == 1) {
    myFN = goCryptorAddon;
    name = 'GO-ADDON 测试'
  }
  if (type == 2) {
    myFN = goCryptorWasm;
    name = 'GO-WASM 测试'
  }
  if (type == 3) {
    myFN = libGMCryptor;
    name = 'FFI 测试'
  }
  if (type == 4) {
    myFN = rustCryptorAddon;
    name = 'RUST-ADDON 测试'
  }
  if (type == 5) {
    myFN = cCryptorAddon;
    name = 'C-ADDON 测试'
  }
  if (type == 6) {
    myFN = cCryptorWasm;
    name = 'C-WASM 测试'
  }
  for (let index = 0; index <= 100000; index++) {
    myFN.sm3Hash(testString)
    var sm2Enc = myFN.sm2Encrypt(testString, sm2PublicKey, 1)
    myFN.sm2Decrypt(sm2Enc, sm2PrivateKey, 1)
    var sm2Enc = myFN.sm2Encrypt(testString, sm2PublicKey, 0)
    myFN.sm2Decrypt(sm2Enc, sm2PrivateKey, 0);
    var sm2Enc = myFN.sm2EncryptAsn1(testString, sm2PublicKey)
    myFN.sm2DecryptAsn1(sm2Enc, sm2PrivateKey)
    var sm4Enc = myFN.sm4EcbEncrypt(testString, sm4_md5_key)
    myFN.sm4EcbDecrypt(sm4Enc, sm4_md5_key)
    var sm4Enc = myFN.sm4CbcEncrypt(testString, sm4_md5_key, sm4_md5_iv)
    myFN.sm4CbcDecrypt(sm4Enc, sm4_md5_key, sm4_md5_iv)
    var sm2Sig = myFN.sm2Signature(testString, sm2PrivateKey)
    myFN.sm2VerifySign(testString, sm2Sig, sm2PublicKey)

    if (index % 1000 == 0) {
      console.log(name, ` #${index}次 内存使用: ${process.memoryUsage().rss / 1024 / 1024}`);
    }
  }
}
