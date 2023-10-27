package org.seginf.exercício7;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class MainA {

    public static void main(String[] args) throws Exception {
        String textToEncrypt = "Hello, World!";
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey encryptionKey = keyGenerator.generateKey();


        String encryptedTextBase64 = enc(textToEncrypt, encryptionKey);
        System.out.println("Texto Cifrado: " + encryptedTextBase64);

        String decryptedText = dec(encryptedTextBase64, encryptionKey);
        System.out.println("Texto Descriptografado: " + decryptedText);
    }

    public static String enc(String textToEncrypt, SecretKey encryptionKey) throws Exception {
        byte[] keyBytes = encryptionKey.getEncoded();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] encryptedText = cipher.doFinal(textToEncrypt.getBytes());

        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        String encryptedTextBase64 = Base64.getEncoder().encodeToString(encryptedText);

        String Header = "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}";

        return Header + "." + ivBase64 + "." + encryptedTextBase64;
    }

    public static String dec(String encryptedTextBase64, SecretKey encryptionKey) throws Exception {
        String[] parts = encryptedTextBase64.split("\\.");
        String ivBase64 = parts[1];
        String encryptedTextPart = parts[2];

        byte[] iv = Base64.getDecoder().decode(ivBase64);
        byte[] encryptedText = Base64.getDecoder().decode(encryptedTextPart);

        byte[] keyBytes = encryptionKey.getEncoded();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);

        return new String(decryptedText);
    }
}

