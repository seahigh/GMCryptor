package;

import com.sun.jna.Library;
import com.sun.jna.Native;

public class GMCryptorTest {
    static GMCryptor GO_GMCRYPTOR;
    static {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        String libExtension;
        String libPlatform = "";
        String libArch = "x64";
        if (os.contains("mac os")) {
            libExtension = "dylib";
            libPlatform = "darwin";
            if(arch.contains("x86_64")){
                libArch = "x64";
            }
            else{
                libArch = "arm64";
            }
        } else if (os.contains("windows")) {
            libExtension = "dll";
        } else {
            libExtension = "so";
        }
        String pwd = System.getProperty("user.dir");
        String lib = pwd + "/gmCryptor-go-"+libPlatform+"-"+libArch+"." + libExtension;
        GO_GMCRYPTOR = (GMCryptor) Native.loadLibrary(lib, GMCryptor.class);
    }

    public interface GMCryptor extends Library {
        String sm3Hash(String data);
        String sm4EcbEncrypt(String data,String key);
        String sm4EcbDecrypt(String data,String key);
        String sm4CbcEncrypt(String data,String key,String iv);
        String sm4CbcDecrypt(String data,String key,String iv);
        String sm2Encrypt(String data,String sm2PublicKey,int mode);
        String sm2Decrypt(String enData,String sm2PrivateKey,int mode);
        String sm2EncryptAsn1(String data,String sm2PublicKey);
        String sm2DecryptAsn1(String enData,String sm2PrivateKey);
        String sm2Signature(String data,String sm2PrivateKey);
        Boolean sm2VerifySign(String data,String sm2Sign,String sm2PublicKey);
    }

    public static void main(String[] args) {

        String str = "{name: \"Seahigh DX\", nick: \"Seahigh DX\"}";
        String pub = "04c450f108400a4078a677286308b944000ecae6c4328d8deb2c2ccc6e3ac248b7ac19c402ff66b0332fbff685041a5ca3b24861b993733da883e3794219121002";
        String pri = "6d4cfbe05c097d75334c7a631259e7179a9d97e66435f72f332fbb098588c97d";
        String sm4Key = "996ce17f6abc9fe126b57aa5f1d8c92c";
        String sm4Iv = "504f1a1f80d40c760c74bd5257124dc9";

        long start = 0;
        int count = 1000;

        String sm3Data = GO_GMCRYPTOR.sm3Hash(str);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm3Hash(str);
        }
        System.out.println("SM3摘要: "+ (System.currentTimeMillis() - start)+"  " +sm3Data);

        String sm4EnData = GO_GMCRYPTOR.sm4EcbEncrypt(str,sm4Key);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm4EcbEncrypt(str,sm4Key);
        }
        System.out.println("SM4[ECB]加密: " + (System.currentTimeMillis() - start)+"  " +sm4EnData);

        String sm4DeData = GO_GMCRYPTOR.sm4EcbDecrypt(sm4EnData,sm4Key);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm4EcbDecrypt(sm4EnData,sm4Key);
        }
        System.out.println("SM4[ECB]解密: " + (System.currentTimeMillis() - start)+"  " +sm4DeData);

        sm4EnData = GO_GMCRYPTOR.sm4CbcEncrypt(str,sm4Key,sm4Iv);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm4CbcEncrypt(str,sm4Key,sm4Iv);
        }
        System.out.println("SM4[CBC]加密: " + (System.currentTimeMillis() - start)+"  " +sm4EnData);

        sm4DeData = GO_GMCRYPTOR.sm4CbcDecrypt(sm4EnData,sm4Key,sm4Iv);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm4CbcDecrypt(sm4EnData,sm4Key,sm4Iv);
        }
        System.out.println("SM4[CBC]解密: " + (System.currentTimeMillis() - start)+"  " +sm4DeData);

        String sm2EnDataAsn1 = GO_GMCRYPTOR.sm2EncryptAsn1(str,pub);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm2EncryptAsn1(str,pub);
        }
        System.out.println("SM2[Asn1]加密: " + (System.currentTimeMillis() - start)+"  " +sm2EnDataAsn1);

        String sm2DeDataAsn1 = GO_GMCRYPTOR.sm2DecryptAsn1(sm2EnDataAsn1,pri);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm2DecryptAsn1(sm2EnDataAsn1,pri);
        }
        System.out.println("SM2[Asn1]解密: " + (System.currentTimeMillis() - start)+"  " +sm2DeDataAsn1);

        String sm2EnData = GO_GMCRYPTOR.sm2Encrypt(str,pub,0);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm2Encrypt(str,pub,0);
        }
        System.out.println("SM2[C1C3C2]加密: " + (System.currentTimeMillis() - start)+"  " +sm2EnData);

        String sm2DeData = GO_GMCRYPTOR.sm2Decrypt(sm2EnData,pri,0);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm2Decrypt(sm2EnData,pri,0);
        }
        System.out.println("SM2[C1C3C2]解密: " + (System.currentTimeMillis() - start)+"  " +sm2DeData);


        sm2EnData = GO_GMCRYPTOR.sm2Encrypt(str,pub,1);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm2Encrypt(str,pub,1);
        }
        System.out.println("SM2[C1C2C3]加密: " + (System.currentTimeMillis() - start)+"  " +sm2EnData);

         sm2DeData = GO_GMCRYPTOR.sm2Decrypt(sm2EnData,pri,1);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm2Decrypt(sm2EnData,pri,1);
        }
        System.out.println("SM2[C1C2C3]解密: " + (System.currentTimeMillis() - start)+"  " +sm2DeData);

        String sm2Sign = GO_GMCRYPTOR.sm2Signature(str,pri);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm2Signature(str,pri);
        }
        System.out.println("SM2签名: " + (System.currentTimeMillis() - start)+"  " +sm2Sign);

        Boolean sm2Verify = GO_GMCRYPTOR.sm2VerifySign(str,sm2Sign,pub);
        start = System.currentTimeMillis();
        for (int j = 0; j < count; j++) {
            GO_GMCRYPTOR.sm2VerifySign(str,sm2Sign,pub);
        }
        System.out.println("SM2验签: " + (System.currentTimeMillis() - start)+"  " +sm2Verify);
    }
}