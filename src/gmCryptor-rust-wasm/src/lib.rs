pub mod sm2;
pub mod sm3;
pub mod sm4;

use gmsm::sm3::sm3_hex;
use gmsm::sm4::*;
use gmsm::sm2::*;
use wasm_bindgen::prelude::*;

use sm2::signature::{Signature, SigCtx};
use sm4::{Mode, Cipher};

 

#[macro_use]
extern crate lazy_static;

#[wasm_bindgen]
pub fn sm3Hash(msg: &str) -> String {
    return sm3_hex(msg).to_lowercase();
}

#[wasm_bindgen]
pub fn sm4CbcDecrypt(cipher_str: &str,key_str: &str,iv_str: &str) -> String {
    let plain = sm4_cbc_decrypt_hex(cipher_str, key_str,iv_str);
    return plain 
    // let key = hex::decode(key_str).unwrap();
    // let iv = hex::decode(iv_str).unwrap();
    // let cipher = Cipher::new(&key, Mode::Cbc);
    // let plain_text: Vec<u8> = cipher.decrypt(&hex::decode(msg).unwrap(), &iv);
    // return  String::from(std::str::from_utf8(&plain_text).unwrap())
}

#[wasm_bindgen]
pub fn sm4CbcEncrypt(msg: &str,key_str: &str,iv_str: &str) -> String {
    let key = hex::decode(key_str).unwrap();
    let iv = hex::decode(iv_str).unwrap();
    let cipher = Cipher::new(&key, Mode::Cbc);
    let cipher_text: Vec<u8> = cipher.encrypt(msg.as_bytes(), &iv);
    let res = hex::encode(&cipher_text);
    return res
    // let ecb_cipher = sm4_cbc_encrypt_hex(plain_str, key_str,iv_str);
    // return ecb_cipher.to_lowercase()
}

#[wasm_bindgen]
pub fn sm4EcbEncrypt(plain_str: &str,key_str: &str) -> String {
    let ecb_cipher = sm4_ecb_encrypt_hex(plain_str, key_str);
    return ecb_cipher.to_lowercase()
}

#[wasm_bindgen]
pub fn sm4EcbDecrypt(cipher_str: &str,key_str: &str) -> String {
    return sm4_ecb_decrypt_hex(cipher_str, key_str);
}

#[wasm_bindgen]
pub fn sm2Encrypt(plain_str: &str,pub_hex: &str,mode:i32) -> String {
    if mode == 0 
    {
        return sm2_encrypt_c1c3c2(plain_str, pub_hex).to_lowercase();
    } 
    else if mode == 1
    {
        return sm2_encrypt(plain_str, pub_hex).to_lowercase();
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn sm2Decrypt(cipher_str: &str,pri_hex: &str,mode:i32) -> String { 
    if mode == 0 
    {
        return sm2_decrypt_c1c3c2(cipher_str, pri_hex);
    } 
    else if mode == 1 {
        return sm2_decrypt(cipher_str, pri_hex);
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn sm2Signature(msg: &str,pri_hex: &str) -> String {
    let ctx = SigCtx::new(); 
    let sk_bz = hex::decode(pri_hex).unwrap();
    let sk = ctx.load_seckey(&sk_bz).unwrap();   
    let pk = ctx.pk_from_sk(&sk); 
    let signature = ctx.sign(msg.as_bytes(), &sk, &pk);     
    let der = signature.der_encode();
    return hex::encode(&der);
}

#[wasm_bindgen]
pub fn sm2VerifySign(msg: &str,sign_hex: &str, pub_hex: &str) -> bool {
    let ctx = SigCtx::new();   
    let pk_bz = hex::decode(pub_hex).unwrap();
    let pk = ctx.load_pubkey(&pk_bz).unwrap();
    let sig_bz  = hex::decode(sign_hex).unwrap();
    let sig = Signature::der_decode(&sig_bz).unwrap();
    let result: bool = ctx.verify(msg.as_bytes(), &pk, &sig);
    return result;
}