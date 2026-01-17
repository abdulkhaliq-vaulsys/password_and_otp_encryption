import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;

class Main {
    public static void main(String[] args) {
        try {
            getEncryptionDecryption(
                    "123000",
                    "3aae908b20ce459ac85a45e48bf7d9c85d8ee80f718e1e2f6a38ef6014f25dbe",
                    "OTP"
                );

            getEncryptionDecryption(
                    "1234",
                    "7c7af5793727b8820ebf9b2a1914b4340381315bb408837169cdbacba4ad3e31",
                    "App password"
                );

            getEncryptionDecryption(
                    "122333",
                    "7c7af5793727b8820ebf9b2a1914b4340381315bb408837169cdbacba4ad3e31",
                    "App password"
                );

            getEncryptionDecryption(
                    "123456",
                    "7c7af5793727b8820ebf9b2a1914b4340381315bb408837169cdbacba4ad3e31",
                    "App password"
                );
                
            getEncryptionDecryption(
                    "122333",
                    "7c7af5793727b8820ebf9b2a1914b4340381315bb408837169cdbacba4ad3e31",
                    "App password"
                );

            getEncryptionDecryption(
                    "cust9999999997602046B11C9FBAACF1B7E0631616780A585600000007333644",
                    "d7a1c345c46a77644fba6e438a98c2369871bda07f409039e5c11ed2b49d489c",
                    "QR ID Encryption"
                );

            // FOR PRODUCTION USE ONLY
            System.out.println("*************************************");
            System.out.println("Production Environment Encryption/Decryption");
            System.out.println("*************************************");

            getEncryptionDecryption
            (
                    "123000",
                    "1d2fdced2bfa51df79b364e519b9eb55e13baaf58bd84e32ccfb1d0c1bedf3f3",
                    "Production OTP Encryption"
            );

            getEncryptionDecryption
            (
                    "123456",
                    "b3d9cfac9ca744c6aa4515068a06ea6a71dc0c59245ae7e4c442422afc752d30",
                    "Production App password Encryption"
            );

            getEncryptionDecryption
            (
                    "3d0f6cf6652715987cd9f5678c18c4c3c8164e9588123304c0b86f2fd158b89f",
                    "d7a1c345c46a77644fba6e438a98c2369871bda07f409039e5c11ed2b49d489c",
                    "Production QR ID Encryption"
            );

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void getEncryptionDecryption(String password, String encryptkey, String passName) {
        try {
            System.out.println("*************************************");
            System.out.println("Starting [" + passName + "] encryption/decryption process");

            String encrypted = Base64.getEncoder()
                    .encodeToString(PassFromApp_DESEncryptCBCPKCS5Padding(password, encryptkey));
            System.out.println("Encrypted Password --> [" + encrypted + "]");

            String decrypted = PassFromApp_DESDecryptCBCPKCS5Padding(Base64.getDecoder().decode(encrypted), encryptkey);
            System.out.println("Decrypted Password --> [" + decrypted + "]");
            System.out.println("*************************************");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] PassFromApp_DESEncryptCBCPKCS5Padding(String message, String skey) throws Exception {
        byte[] keyBytes = null;
        SecretKey key = null;
        IvParameterSpec iv = null;
        Cipher cipher = null;
        byte[] plainTextBytes = null;
        byte[] cipherText = null;
        try {
            keyBytes = Arrays.copyOf(skey
                    .getBytes("utf-8"), 24);

            key = new SecretKeySpec(keyBytes, "DESede");
            iv = new IvParameterSpec(new byte[8]);
            cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            plainTextBytes = message.getBytes("utf-8");
            cipherText = cipher.doFinal(plainTextBytes);
            return cipherText;
        } finally {
            keyBytes = null;
            key = null;
            iv = null;
            cipher = null;
            plainTextBytes = null;
            cipherText = null;
        }
    }

    public static String PassFromApp_DESDecryptCBCPKCS5Padding(byte[] message, String skey) throws Exception {
        byte[] keyBytes = null;
        SecretKey key = null;
        IvParameterSpec iv = null;
        Cipher decipher = null;
        byte[] plainText = null;

        try {
            keyBytes = Arrays.copyOf(skey
                    .getBytes("utf-8"), 24);

            key = new SecretKeySpec(keyBytes, "DESede");
            iv = new IvParameterSpec(new byte[8]);
            decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, key, iv);

            plainText = decipher.doFinal(message);

            return new String(plainText, "UTF-8");
        } finally {
            keyBytes = null;
            key = null;
            iv = null;
            decipher = null;
            plainText = null;
        }

    }
}