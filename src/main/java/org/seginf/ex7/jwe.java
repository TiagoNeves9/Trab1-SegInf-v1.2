package org.seginf.ex7;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;


public class jwe {

    public static PublicKey getPublicKeyFromCertificate(String certificateFilePath) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream certFile = new FileInputStream(certificateFilePath);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFile);
        return certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeystore(String keystoreFilePath, String keystorePassword, String alias)
            throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        FileInputStream keystoreFile = new FileInputStream(keystoreFilePath);
        keystore.load(keystoreFile, keystorePassword.toCharArray());

        Key key = keystore.getKey(alias, keystorePassword.toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        } else {
            throw new Exception("A chave não é uma chave privada ou a senha está incorreta.");
        }
    }

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
        String encryptedTextBase64 = Base64.getEncoder().withoutPadding().encodeToString(encryptedText);
        String header = Base64.getEncoder().encodeToString("{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}".getBytes());

        return header + "." + ivBase64 + "." + encryptedTextBase64;
    }

    public static String dec(String encryptedTextBase64, SecretKey encryptionKey) throws Exception {
        String[] parts = encryptedTextBase64.split("\\.");
        String ivBase64 = parts[1];
        String encryptedTextPart = parts[2];

        System.out.println(encryptedTextBase64);
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

    public static void main(String[] args) throws Exception {

        String certificate = args[2];
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey encryptionKey = keyGenerator.generateKey();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        String certificateFilePath = "C:\\Users\\missf\\Documents\\ISEL\\3ANO\\SegInf\\TP1\\code\\src\\main\\java\\org\\seginf\\ex7\\end-entities\\" + certificate + ".cer";
        PublicKey publicKey = getPublicKeyFromCertificate(certificateFilePath);
        String encryptedSymmetricKey = encSymmetricKey(encryptionKey, publicKey);

       if (args[0].equals("enc")) {

            //encryptedSymmetricKey = encSymmetricKey(encryptionKey, publicKey);

            String textToEncrypt = args[1];
            String encryptedTextBase64 = enc(textToEncrypt, encryptionKey);

            //String s = encryptedTextBase64 + "." + encryptedSymmetricKey;
            System.out.println("JWE token: " + encryptedTextBase64 + "." + encryptedSymmetricKey);

       } else {

            String keystoreFilePath = "C:\\Users\\missf\\Documents\\ISEL\\3ANO\\SegInf\\TP1\\code\\src\\main\\java\\org\\seginf\\ex7\\pfx\\" + certificate + ".pfx";

            String keystorePassword = "changeit";
            String alias = "1";

            PrivateKey privateKey = getPrivateKeyFromKeystore(keystoreFilePath, keystorePassword, alias);

            SecretKey decryptedSymmetricKey = decSymmetricKey(encryptedSymmetricKey, privateKey);


            String textToDecrypt = args[1];
            System.out.println(textToDecrypt);
            String decryptedTextBase64 = dec(textToDecrypt, encryptionKey);

            System.out.println("WE token: " + decryptedTextBase64);// + "." + decryptedSymmetricKey);
        }


    }
}
