import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class sadad_biller_encrypt {
    public static void main(String[] args) {

        System.out.println("Encrypt sadad biller password");

        try {
            String publicKey = 
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCW8uUAIe/yuRur8cZDIWHphDFJ2X5FyUuxH80wuUECVOOimyfTFf1vdIo2E2B4k7mkCFqKWftJ5xqkoNaigK6SltlemNZdAq/RK4IjkIwPB6eHJqi3up8GLsol+NOt1w/YUbkCt5hCPE+OJ1i+zyEtvfW+hnlUH0IFq4h6nf/LHxp+z3XDlgmx2k02FJ4HuZljHTKWvEsq7BbQ5/zcejpzZUwIMBI/A805Ly0ajf4OwTq6lWbWxbdcMSP0leh6HmbSl/v766E3euy8k/QPLHpk84ZPNUKmBB0mAA2ARtXmlrjwT8FatGB9K2W9PNa/KxzoyOb6bWLF+wWJgS5+GF4jAgMBAAECggEAL4qmx2jo6tiUN455dDEyZlrFL0457/7bQRkUBjGCoRpda5xUaa42WQEqeqeVrcRRJrGe2o5Gj9si0BD8KMhAs1ihc6LNeRPcjhOW9F6VTjKJ+A4b+2nipg7ciiMZgFoI2oe6rnlmkg3uvIX19HrGJ2L54Bz4X59Mqv6AiKX0p2NTn3oCNPZeecoHNQu8lvXCOjfE28OG92uODmt1nSe20M3CHzHbquW4FtrBn0uz+1VG+MF8/WUARJiJswuKe5N08OUzDlN9fhEQeNV5el+HscUwPdWAzvEMpA7Fiax8Fi7Te6QZJtt3LepM7HJgfzZbWOb5RVUtxn4xr3QZ29ZhgQKBgQDF8MMOwqZ4QILsn3DzD9oQV0KIa8AlH/jIRzaeoKI62rYeAUDZ22PoiRuJgLbQTe4CIZ8kxjCAVWmtGlPCa5inHt597+LOcdXpyWWBS3iSlp94cV9R+V1kBaTKdHMZaju3mYgZyNDEjRZ+cTNvNPa92GJ+oyx/0WdeTNxsKRJn4wKBgQDDOY4GWfEAWziuYEFLtVqwmSGOdEEPa9g9Fn31lhSMO/5IqxHDUAYaPBP6/QHD9Z6LPCX5QEufaTIF28sXLBppQ8DJIA7HXgPI5SR5CsGvD5Ei5qHapF4/hL/mmtcM+2uRFAKRqujhNqVbf8nkVsLFGKGdbqBoxSAMH4meWm2EwQKBgDNJl/D6JJIh/Qp8oZKJN/Jl+bpJWQcFiruyIAfoDUD8rJWHs5r/SprU88qkDDpbBuGMfqTTqXuHJhORL8S/hlU/HV06S+U7/7ZM1b0zpfEtj/JwRceCul0RTUqb87rRGNoQsQAlVVqoR/zJLg+RhKFaMOMpOn1/762ycqaf2cILAoGALCTAg5kk0KLP30YunZLlbddCajbJW1ZUcAO8+aI1BTyvk/jyrEpVBuuczP0WwBuy/OLd501tjB86S27WrmevlSvX1OKl1NjiXDPMGn6fKxmHBPBHmuvdz9kRl3Bdvja/rO9sYUnXHM3BeD4eBb7EjdKzAKk6Jlakl3kuIhtqdkECgYBh76IsVl16do9aOX1QqxJ8Fi5f05zco2QpyMO6PDiFki9TtlFeWpFSjC50wXTERkMxs0yPamL7gpM3rH0XWjuKPLl/+PBG7SUTbEIQqho0n0u3jJjtfXDq1ZXnT3YpW9JLVJAQFLkRF6MeJXsKDZofZk1ywG8RIZocjUQVeTgEiA==";

            String originalText = "N$TU@1234";

            // String encryptedText = RSAEncryptByPKCS8Key(publicKey, originalText);
            String encryptedText = encryptMessage(originalText,publicKey);

            System.out.println("Original Text: " + originalText);
            System.out.println("Encrypted Text: " + encryptedText);

            System.out.println("Encrypted sadad biller password");

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static String RSAEncryptByPKCS8Key(String publicKeyStr, String originalText)
            throws Exception {

        PKCS8EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFactory.generatePrivate(pubKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, priv);

        // Encrypt the string using the public key
        return Base64.getEncoder().encodeToString((cipher.doFinal(originalText.getBytes())));
    }

    public static String encryptMessage(String plainText, String privateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey priv = fact.generatePrivate(keySpec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, priv);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
