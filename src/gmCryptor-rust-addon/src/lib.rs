use neon::prelude::*;
use openssl_sys::*;
use libc::*;
use std::ptr;
 
fn sm3Hash(mut cx: FunctionContext) -> JsResult<JsString> {
    if cx.len() != 1 {
        return cx.throw_error("Wrong arguments")
    }
    let message = cx.argument::<JsString>(0)?.value(&mut cx);
    let hash =  SM3::hash(&message.into_bytes());
    let content = hex::encode(&hash);
    Ok(cx.string(content))
}

fn sm4CbcDecrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    if cx.len() != 3 {
        return cx.throw_error("Wrong arguments")
    }
    let cipher_str = cx.argument::<JsString>(0)?.value(&mut cx);
    let key_str = cx.argument::<JsString>(1)?.value(&mut cx);
    let iv_str = cx.argument::<JsString>(2)?.value(&mut cx);
    let key = hex::decode(&key_str).unwrap();
    let iv = hex::decode(&iv_str).unwrap();
    let cipher = hex::decode(&cipher_str).unwrap();  
    let plain = SM4::cbc_decrypt(&cipher,&key,&iv);
    Ok(cx.string(std::str::from_utf8(&plain).unwrap()))
}
 
fn sm4CbcEncrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let msg = cx.argument::<JsString>(0)?.value(&mut cx);
    let key_str = cx.argument::<JsString>(1)?.value(&mut cx);
    let iv_str = cx.argument::<JsString>(2)?.value(&mut cx);
    let key = hex::decode(&key_str).unwrap();
    let iv = hex::decode(&iv_str).unwrap();   
    let cipher_text = SM4::cbc_encrypt(&msg.into_bytes(),&key,&iv);
    let res = hex::encode(&cipher_text);
    Ok(cx.string(res))
}
  
fn sm4EcbEncrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let msg = cx.argument::<JsString>(0)?.value(&mut cx);
    let key_str = cx.argument::<JsString>(1)?.value(&mut cx);
    let key = hex::decode(&key_str).unwrap();
    let cipher_text = SM4::ecb_encrypt(&msg.into_bytes(),&key);

    let res = hex::encode(&cipher_text);
    Ok(cx.string(res))
}

fn sm4EcbDecrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let cipher_str = cx.argument::<JsString>(0)?.value(&mut cx);
    let key_str = cx.argument::<JsString>(1)?.value(&mut cx);
    let key = hex::decode(&key_str).unwrap();
    let cipher = hex::decode(&cipher_str).unwrap();  
    let plain = SM4::ecb_decrypt(&cipher,&key);
    Ok(cx.string(std::str::from_utf8(&plain).unwrap()))
}

fn sm2VerifySign(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let msg = cx.argument::<JsString>(0)?.value(&mut cx);
    let sign_str = cx.argument::<JsString>(1)?.value(&mut cx);
    let sign = hex::decode(&sign_str).unwrap();
    let pubkey = cx.argument::<JsString>(2)?.value(&mut cx); 
    let sign_bool = match SM2::verify(&sign,&msg.into_bytes(),&pubkey.into_bytes()) {
        Ok(sign_bool) => sign_bool,
        Err(e) => return cx.throw_error(e)
    };
    Ok(cx.boolean(sign_bool))
}

fn sm2Signature(mut cx: FunctionContext) -> JsResult<JsString> {
    let msg = cx.argument::<JsString>(0)?.value(&mut cx);
    let prikey = cx.argument::<JsString>(1)?.value(&mut cx);
    
    let sign_text = match SM2::sign(&msg.into_bytes(),&prikey.into_bytes()) {
        Ok(sign_text) => sign_text,
        Err(e) => return cx.throw_error(e)
    };
    let res = hex::encode(&sign_text);
    Ok(cx.string(res))
}

fn sm2EncryptAsn1(mut cx: FunctionContext) -> JsResult<JsString> {
    let msg = cx.argument::<JsString>(0)?.value(&mut cx);
    let pubkey = cx.argument::<JsString>(1)?.value(&mut cx); 
    let encode_text = match SM2::encrypt(&msg.into_bytes(),&pubkey.into_bytes()) {
        Ok(encode_text) => encode_text,
        Err(e) => return cx.throw_error(e)
    };
    let res = hex::encode(&encode_text);
    Ok(cx.string(res))
}

fn sm2DecryptAsn1(mut cx: FunctionContext) -> JsResult<JsString> {
    let cipher_str = cx.argument::<JsString>(0)?.value(&mut cx);
    let cipher = hex::decode(&cipher_str).unwrap();  
    let prikey = cx.argument::<JsString>(1)?.value(&mut cx);
    let plain = match SM2::decrypt(&cipher,&prikey.into_bytes()) {
        Ok(plain) => plain,
        Err(e) => return cx.throw_error(e)
    };
    Ok(cx.string(std::str::from_utf8(&plain).unwrap()))
}

pub const EVP_PKEY_SM2: c_int = NID_sm2;

pub const NID_sm2: c_int = 1172;

pub const EVP_PKEY_ALG_CTRL: c_int = 0x1000;
pub const EVP_PKEY_CTRL_SET1_ID: c_int = EVP_PKEY_ALG_CTRL + 11;

pub const CERTVRIFY_SM2_ID_LEN: c_int = 16;

 

extern "C" {
    pub fn EVP_sm4_ecb() -> *const EVP_CIPHER;
    pub fn EVP_sm4_cbc() -> *const EVP_CIPHER;
    pub fn EVP_sm4_ofb() -> *const EVP_CIPHER;
    pub fn EVP_sm4_ctr() -> *const EVP_CIPHER;

    pub fn EVP_PKEY_set1_EC_KEY(pkey: *mut EVP_PKEY, key: *mut EC_KEY) -> c_int;
    pub fn EVP_PKEY_set_alias_type(pkey: *mut EVP_PKEY, ttype: c_int) -> c_int;
    pub fn EC_POINT_hex2point(group: *const EC_GROUP, hex: *const libc::c_char, p: *mut EC_POINT, ctx: *mut BN_CTX) -> *mut EC_POINT;
    pub fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut EVP_MD_CTX, sctx: *mut EVP_PKEY_CTX) -> c_int;
}

pub struct SM3 {}

impl SM3 {
    pub fn hash(data: &Vec<u8>) -> Vec<u8> {
        let mut res = vec![0; 32].into_boxed_slice();
        let res_len: *mut u32 = Box::into_raw(Box::new(0));
        unsafe {
            let md = EVP_sm3();
            let md_ctx = EVP_MD_CTX_new();
            let engin: *mut ENGINE = ptr::null_mut();
            EVP_DigestInit_ex(md_ctx, md, engin);
            EVP_DigestUpdate(md_ctx, data.as_ptr() as *const c_void, data.len());
            EVP_DigestFinal_ex(md_ctx, res.as_mut_ptr(), res_len);
            EVP_MD_CTX_free(md_ctx);
            drop(Box::from_raw(res_len));
        }
        res.to_vec()
    }
}

pub struct SM4 {}

impl SM4 {
    pub fn ecb_encrypt(data: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
        let cipher_length: *mut c_int = Box::into_raw(Box::new(data.len() as i32 + 32));
        let mut cipher_text = vec![0 as u8; data.len() + 32].into_boxed_slice();
        let final_length: *mut c_int = Box::into_raw(Box::new(0));
        let mut len = 0;
        unsafe {
            let evp_cipher = EVP_sm4_ecb();
            let ctx = EVP_CIPHER_CTX_new();
            let engin: *mut ENGINE = ptr::null_mut();
            EVP_EncryptInit_ex(
                ctx,
                evp_cipher,
                engin,
                key.as_ptr() as *const c_uchar,
                ptr::null_mut()
            );
            EVP_EncryptUpdate(
                ctx,
                cipher_text.as_mut_ptr() as *mut c_uchar,
                cipher_length,
                data.as_ptr(),
                data.len() as i32,
            );
            EVP_EncryptFinal_ex(
                ctx,
                cipher_text.as_mut_ptr().offset(*cipher_length as isize) as *mut c_uchar,
                final_length,
            );
            EVP_CIPHER_CTX_free(ctx);
            len = *cipher_length + *final_length;

            drop(Box::from_raw(cipher_length));
            drop(Box::from_raw(final_length));
        }
        let mut r = cipher_text.to_vec();
        r.truncate(len as usize);
        r
    }

    pub fn cbc_encrypt(data: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
        let cipher_length: *mut c_int = Box::into_raw(Box::new(data.len() as i32 + 32));
        let mut cipher_text = vec![0 as u8; data.len() + 32].into_boxed_slice();
        let final_length: *mut c_int = Box::into_raw(Box::new(0));
        let mut len = 0;
        unsafe {
            let evp_cipher = EVP_sm4_cbc();
            let ctx = EVP_CIPHER_CTX_new();
            let engin: *mut ENGINE = ptr::null_mut();
            EVP_EncryptInit_ex(
                ctx,
                evp_cipher,
                engin,
                key.as_ptr() as *const c_uchar,
                iv.as_ptr() as *const c_uchar,
            );
            EVP_EncryptUpdate(
                ctx,
                cipher_text.as_mut_ptr() as *mut c_uchar,
                cipher_length,
                data.as_ptr(),
                data.len() as i32,
            );
            EVP_EncryptFinal_ex(
                ctx,
                cipher_text.as_mut_ptr().offset(*cipher_length as isize) as *mut c_uchar,
                final_length,
            );
            EVP_CIPHER_CTX_free(ctx);
            len = *cipher_length + *final_length;

            drop(Box::from_raw(cipher_length));
            drop(Box::from_raw(final_length));
        }
        let mut r = cipher_text.to_vec();
        r.truncate(len as usize);
        r
    }

    pub fn ecb_decrypt(data: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
        let cipher_length: *mut c_int = Box::into_raw(Box::new(data.len() as i32 + 32));
        let mut cipher_text = vec![0; data.len() + 32].into_boxed_slice();

        let final_length: *mut c_int = Box::into_raw(Box::new(0));
        let mut len = 0;
        unsafe {
            let evp_cipher = EVP_sm4_ecb();
            let ctx = EVP_CIPHER_CTX_new();
            let engin: *mut ENGINE = ptr::null_mut();
            EVP_DecryptInit_ex(
                ctx,
                evp_cipher,
                engin,
                key.as_ptr() as *const c_uchar,
                ptr::null_mut()
            );
            EVP_DecryptUpdate(
                ctx,
                cipher_text.as_mut_ptr() as *mut c_uchar,
                cipher_length,
                data.as_ptr(),
                data.len() as i32,
            );
            EVP_DecryptFinal_ex(
                ctx,
                cipher_text.as_mut_ptr().offset(*cipher_length as isize) as *mut c_uchar,
                final_length,
            );
            EVP_CIPHER_CTX_free(ctx);
            len = *cipher_length + *final_length;
            drop(Box::from_raw(cipher_length));
            drop(Box::from_raw(final_length));
        }
        let mut r = cipher_text.to_vec();
        r.truncate(len as usize);
        r
    }

    pub fn cbc_decrypt(data: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
        let cipher_length: *mut c_int = Box::into_raw(Box::new(data.len() as i32 + 32));
        let mut cipher_text = vec![0; data.len() + 32].into_boxed_slice();
        let final_length: *mut c_int = Box::into_raw(Box::new(0));
        let mut len = 0;
        unsafe {
            let evp_cipher = EVP_sm4_cbc();
            let ctx = EVP_CIPHER_CTX_new();
            let engin: *mut ENGINE = ptr::null_mut();
            EVP_DecryptInit_ex(
                ctx,
                evp_cipher,
                engin,
                key.as_ptr() as *const c_uchar,
                iv.as_ptr() as *const c_uchar,
            );
            EVP_DecryptUpdate(
                ctx,
                cipher_text.as_mut_ptr() as *mut c_uchar,
                cipher_length,
                data.as_ptr(),
                data.len() as i32,
            );
            EVP_DecryptFinal_ex(
                ctx,
                cipher_text.as_mut_ptr().offset(*cipher_length as isize) as *mut c_uchar,
                final_length,
            );
            EVP_CIPHER_CTX_free(ctx);
            len = *cipher_length + *final_length;
            drop(Box::from_raw(cipher_length));
            drop(Box::from_raw(final_length));
        }
        let mut r = cipher_text.to_vec();
        r.truncate(len as usize);
        r
    }
}

pub struct SM2 {}

impl SM2 {
    fn create_evp_pkey(key: &Vec<u8>, is_pub: i32) -> Result<*mut EVP_PKEY, String> {
        let is_pem_key: Option<usize> = std::str::from_utf8(&key).unwrap()[4..].find("BEGIN").map(|i| i + 4);
        if is_pem_key.is_some() {
            unsafe {
                let evp_key = EVP_PKEY_new();
                let mut ec_key = ptr::null_mut();
                let userdata = ptr::null_mut();
    
                let keybio = BIO_new_mem_buf(key.as_ptr() as *const c_void, key.len() as i32);
                if keybio == ptr::null_mut() {
                    return Err("BIO_new_mem_buf failed.".to_string());
                }
                let pem_passwd_cb = Option::None;
                if is_pub==1 {  
                    let ec_key = PEM_read_bio_EC_PUBKEY(keybio, &mut ec_key, pem_passwd_cb, userdata);
                    if ec_key == ptr::null_mut() {
                        BIO_free_all(keybio);
                        return Err("PEM_read_bio_EC_PUBKEY failed".to_string());
                    }          
                    if EVP_PKEY_set1_EC_KEY(evp_key, ec_key) != 1 {
                        EC_KEY_free(ec_key);
                        BIO_free_all(keybio);
                        return Err("EVP_KEY_set1_EC_KEY failed".to_string());
                    }      
                    EC_KEY_free(ec_key);
                } else {
                    let ec_key =
                        PEM_read_bio_ECPrivateKey(keybio, &mut ec_key, pem_passwd_cb, userdata);
                    if ec_key == ptr::null_mut() {
                        BIO_free_all(keybio);
                        return Err("PEM_read_bio_ECPrivateKey failed".to_string());
                    }
                    if EVP_PKEY_set1_EC_KEY(evp_key, ec_key) != 1 {
                        EC_KEY_free(ec_key);
                        BIO_free_all(keybio);
                        return Err("EVP_KEY_set1_EC_KEY failed".to_string());
                    }
                    EC_KEY_free(ec_key);
                }
                BIO_free_all(keybio);
                Ok(evp_key)
            }
        }
        else{
            unsafe {
                let evp_key = EVP_PKEY_new(); 
                let mut ec_key = ptr::null_mut();          
                if is_pub==1 {  
                    ec_key  = EC_KEY_new_by_curve_name(NID_sm2);
                    let group = EC_KEY_get0_group(ec_key);
                    let pub_key = EC_POINT_hex2point(group, key.as_ptr() as *const _, ptr::null_mut(), ptr::null_mut());
                    EC_KEY_set_public_key(ec_key, pub_key);
                    EC_POINT_free(pub_key);
                    if EVP_PKEY_set1_EC_KEY(evp_key, ec_key) != 1 {
                        EC_KEY_free(ec_key);
                        return Err("EVP_KEY_set1_EC_KEY failed".to_string());
                    }      
                    EC_KEY_free(ec_key);
                } else {
                    let mut pri_key = ptr::null_mut();
                    BN_hex2bn(&mut pri_key, key.as_ptr() as *const _);
                    if is_pub==0 {
                        ec_key = EC_KEY_new();
                        let group = EC_GROUP_new_by_curve_name(NID_sm2);
                        EC_KEY_set_group(ec_key, group);
                        let r = EC_POINT_new(group);

                        let ctx = BN_CTX_new();         
                        EC_POINT_mul(group, r, pri_key, ptr::null_mut(), ptr::null_mut(), ctx);
                        EC_KEY_set_public_key(ec_key, r);
                        BN_CTX_free(ctx); 
                        EC_KEY_set_private_key(ec_key, pri_key);
                        EC_POINT_free(r);
                        EC_GROUP_free(group);
                    }
                    else  {
                        ec_key  = EC_KEY_new_by_curve_name(NID_sm2);
                        EC_KEY_set_private_key(ec_key, pri_key);
                    }

                    BN_free(pri_key);
                    if EVP_PKEY_set1_EC_KEY(evp_key, ec_key) != 1 {
                        EC_KEY_free(ec_key); 
                        return Err("EVP_KEY_set1_EC_KEY failed".to_string());                   
                    } 
                    EC_KEY_free(ec_key);    
                }
                Ok(evp_key)
            }   
        }    
    }
 
    pub fn encrypt(data: &Vec<u8>, pub_key: &Vec<u8>) -> Result<Vec<u8>, String>  {
        let mut r = vec![];
        unsafe {
            let ciphertext_len: *mut size_t = Box::into_raw(Box::new(0));
            let evp_key = match SM2::create_evp_pkey(pub_key, 1) {
                Ok(evp_key) => evp_key,
                Err(e) => return Err(e),
            };
            EVP_PKEY_set_alias_type(evp_key, EVP_PKEY_SM2);
            let ectx = EVP_PKEY_CTX_new(evp_key, ptr::null_mut());
            EVP_PKEY_encrypt_init(ectx);
            EVP_PKEY_encrypt(
                ectx,
                ptr::null_mut(),
                ciphertext_len,
                data.as_ptr(),
                data.len(),
            );
            let mut cipher_text = vec![0; *ciphertext_len].into_boxed_slice();
            EVP_PKEY_encrypt(
                ectx,
                cipher_text.as_mut_ptr(),
                ciphertext_len,
                data.as_ptr(),
                data.len(),
            );
            drop(Box::from_raw(ciphertext_len));
            EVP_PKEY_free(evp_key);
            EVP_PKEY_CTX_free(ectx);
            r = cipher_text.to_vec();
        }
        Ok(r)
    }

    pub fn decrypt(data: &Vec<u8>, pri_key: &Vec<u8>) -> Result<Vec<u8>, String> {
        let mut r = vec![];
        unsafe {
            let ciphertext_len: *mut size_t = Box::into_raw(Box::new(0));
            let pkey = match SM2::create_evp_pkey(pri_key, -1) {
                Ok(evp_key) => evp_key,
                Err(e) => return Err(e),
            };
            EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
            let ectx = EVP_PKEY_CTX_new(pkey, ptr::null_mut());
            EVP_PKEY_decrypt_init(ectx);
            EVP_PKEY_decrypt(
                ectx,
                ptr::null_mut(),
                ciphertext_len,
                data.as_ptr(),
                data.len(),
            );
            let mut cipher_text = vec![0; *ciphertext_len].into_boxed_slice();
            EVP_PKEY_decrypt(
                ectx,
                cipher_text.as_mut_ptr(),
                ciphertext_len,
                data.as_ptr(),
                data.len(),
            );
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ectx);

            let mut result_vec = cipher_text.to_vec();
            result_vec.truncate(*ciphertext_len);
            r = result_vec;
        }
        Ok(r)
    }

    pub fn sign(data: &Vec<u8>, pri_key: &Vec<u8>) -> Result<Vec<u8>, String> {
        let mut r = vec![];
        let certvrify_sm2_id: Vec<u8> = "1234567812345678".as_bytes().to_vec();
        unsafe {
            let sig_len: *mut size_t = Box::into_raw(Box::new(0));
            let pkey = match SM2::create_evp_pkey(pri_key, 0) {
                Ok(evp_key) => evp_key,
                Err(e) => return Err(e),
            };
            let evp_md_ctx: *mut EVP_MD_CTX = EVP_MD_CTX_new();
            EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
            let sctx = EVP_PKEY_CTX_new(pkey, ptr::null_mut());
            EVP_PKEY_CTX_ctrl(sctx, -1, -1,  EVP_PKEY_CTRL_SET1_ID, CERTVRIFY_SM2_ID_LEN, certvrify_sm2_id.as_ptr() as *mut c_void);
            EVP_MD_CTX_set_pkey_ctx(evp_md_ctx, sctx);
            EVP_DigestSignInit(evp_md_ctx, ptr::null_mut(), EVP_sm3(), ptr::null_mut(), pkey);
            EVP_DigestSign(
                evp_md_ctx,
                ptr::null_mut(),
                sig_len,
                data.as_ptr(),
                data.len(),
            );
            let mut sig = vec![0; *sig_len].into_boxed_slice();
            EVP_DigestSign(
                evp_md_ctx,
                sig.as_mut_ptr(),
                sig_len,
                data.as_ptr(),
                data.len(),
            );
            EVP_MD_CTX_free(evp_md_ctx);
            EVP_PKEY_CTX_free(sctx);
            EVP_PKEY_free(pkey);

            let mut result_vec = sig.to_vec();
            result_vec.truncate(*sig_len);
            r = result_vec;
        }
        Ok(r)
    }

    pub fn verify(sign_hex: &Vec<u8>, message: &Vec<u8>, pub_key: &Vec<u8>) -> Result<bool, String> {
        let mut verify_result = false;
        let certvrify_sm2_id: Vec<u8> = "1234567812345678".as_bytes().to_vec();
        unsafe {
            let evp_key = match SM2::create_evp_pkey(pub_key, 1) {
                Ok(evp_key) => evp_key,
                Err(e) => return Err(e),
            };
            let evp_md_ctx: *mut EVP_MD_CTX = EVP_MD_CTX_new();
            EVP_PKEY_set_alias_type(evp_key, EVP_PKEY_SM2);
            let sctx = EVP_PKEY_CTX_new(evp_key, ptr::null_mut());
            EVP_PKEY_CTX_ctrl(sctx, -1, -1,  EVP_PKEY_CTRL_SET1_ID, CERTVRIFY_SM2_ID_LEN, certvrify_sm2_id.as_ptr() as *mut c_void);
            EVP_MD_CTX_set_pkey_ctx(evp_md_ctx, sctx);
            EVP_DigestVerifyInit(
                evp_md_ctx,
                ptr::null_mut(),
                EVP_sm3(),
                ptr::null_mut(),
                evp_key,
            );
            if EVP_DigestVerify(
                evp_md_ctx,
                sign_hex.as_ptr(),
                sign_hex.len(),
                message.as_ptr(),
                message.len(),
            ) != 1
            {
                verify_result = false;
            } else {
                verify_result = true;
            }
            EVP_PKEY_CTX_free(sctx);
            EVP_PKEY_free(evp_key);
            EVP_MD_CTX_free(evp_md_ctx);
        }
        Ok(verify_result)
    }
}


#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("sm3Hash", sm3Hash)?;
    cx.export_function("sm4CbcDecrypt", sm4CbcDecrypt)?;
    cx.export_function("sm4CbcEncrypt", sm4CbcEncrypt)?;
    cx.export_function("sm4EcbEncrypt", sm4EcbEncrypt)?;
    cx.export_function("sm4EcbDecrypt", sm4EcbDecrypt)?;
    cx.export_function("sm2EncryptAsn1", sm2EncryptAsn1)?;   
    cx.export_function("sm2DecryptAsn1", sm2DecryptAsn1)?;  
    cx.export_function("sm2Signature", sm2Signature)?;
    cx.export_function("sm2VerifySign", sm2VerifySign)?;
    Ok(())
}