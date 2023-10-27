package org.seginf.exercício7;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;


public class MainB {

    public static String encSymmetricKey(SecretKey symmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKeyBytes = cipher.doFinal(symmetricKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKeyBytes);
    }

    public static SecretKey decSymmetricKey(String encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKeyBytes);
        return new SecretKeySpec(decryptedKeyBytes, 0, decryptedKeyBytes.length, "AES");
    }

    public static void main(String[] args) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey symmetricKey = keyGenerator.generateKey();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String encryptedKey = encSymmetricKey(symmetricKey, publicKey);
        System.out.println("Chave simétrica cifrada: " + encryptedKey);

        SecretKey decryptedKey = decSymmetricKey(encryptedKey, privateKey);
        System.out.println("Chave simétrica decifrada: " + Base64.getEncoder().encodeToString(decryptedKey.getEncoded()));
    }
}
